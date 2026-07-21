from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .block import parse_block
from .io_utils import read_json, write_byte_csv, write_json
from .network import DEFAULT_API, EsploraClient
from .transaction import build_and_sign_p2wpkh, parse_transaction, verify_p2wpkh_draft
from .wallet import create_wallet, load_wallet, public_wallet


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SECRET_PATH = PROJECT_ROOT / ".secrets" / "testnet4_wallet.json"
PUBLIC_WALLET_PATH = PROJECT_ROOT / "data" / "wallet_public.json"
DRAFT_PATH = PROJECT_ROOT / "data" / "transaction_draft.json"
BROADCAST_PATH = PROJECT_ROOT / "data" / "broadcast.json"
CONFIRMATION_PATH = PROJECT_ROOT / "data" / "confirmation.json"
RAW_DIR = PROJECT_ROOT / "data" / "raw"
OUTPUT_DATA_DIR = PROJECT_ROOT / "output" / "data"


def print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=False))


def client_from_args(args: argparse.Namespace) -> EsploraClient:
    return EsploraClient(args.api)


def save_transaction_analysis(raw: bytes, stem: str) -> dict[str, Any]:
    parsed, records = parse_transaction(raw)
    write_json(OUTPUT_DATA_DIR / f"{stem}.json", parsed)
    write_byte_csv(OUTPUT_DATA_DIR / f"{stem}_bytes.csv", records)
    return parsed


def save_block_analysis(raw: bytes, stem: str) -> dict[str, Any]:
    parsed, records = parse_block(raw)
    write_json(OUTPUT_DATA_DIR / f"{stem}.json", parsed)
    write_byte_csv(OUTPUT_DATA_DIR / f"{stem}_bytes.csv", records)
    return parsed


def command_wallet_init(_: argparse.Namespace) -> None:
    wallet = create_wallet(SECRET_PATH, PUBLIC_WALLET_PATH)
    public = public_wallet(wallet)
    print_json(
        {
            "created_or_loaded": True,
            "secret_path": str(SECRET_PATH),
            "secret_file_mode": oct(SECRET_PATH.stat().st_mode & 0o777),
            "public_wallet": public,
            "next_step": "fund sender.address with at least 5000 Testnet4 sats, then run funding-status",
        }
    )


def command_funding_status(args: argparse.Namespace) -> None:
    wallet = public_wallet(load_wallet(SECRET_PATH))
    utxos = client_from_args(args).address_utxos(wallet["sender"]["address"])
    confirmed = [utxo for utxo in utxos if utxo.get("status", {}).get("confirmed")]
    print_json(
        {
            "address": wallet["sender"]["address"],
            "utxos": utxos,
            "confirmed_balance_sats": sum(int(utxo["value"]) for utxo in confirmed),
            "ready": any(int(utxo["value"]) >= 5000 for utxo in confirmed),
        }
    )


def command_build(args: argparse.Namespace) -> None:
    wallet = load_wallet(SECRET_PATH)
    public = public_wallet(wallet)
    replaced_txid: str | None = None
    if args.replace_draft:
        if not DRAFT_PATH.exists():
            raise RuntimeError("cannot replace: no existing transaction draft")
        previous_draft = read_json(DRAFT_PATH)
        utxo = previous_draft["selected_utxo"]
        replaced_txid = previous_draft["txid"]
    else:
        utxos = client_from_args(args).address_utxos(public["sender"]["address"])
        confirmed = [utxo for utxo in utxos if utxo.get("status", {}).get("confirmed")]
        if not confirmed:
            raise RuntimeError(
                f"no confirmed UTXO at {public['sender']['address']}; fund it from a Testnet4 faucet first"
            )
        utxo = max(confirmed, key=lambda item: int(item["value"]))
    draft = build_and_sign_p2wpkh(
        private_key=bytes.fromhex(wallet["sender"]["private_key_hex"]),
        public_key=bytes.fromhex(public["sender"]["public_key_hex"]),
        utxo=utxo,
        receiver_script=bytes.fromhex(public["receiver"]["script_pubkey"]),
        change_script=bytes.fromhex(public["sender"]["script_pubkey"]),
        payment_sats=args.payment_sats,
        fee_rate=args.fee_rate,
    )
    draft["sender_address"] = public["sender"]["address"]
    draft["receiver_address"] = public["receiver"]["address"]
    draft["selected_utxo"] = utxo
    if replaced_txid is not None:
        draft["replaces_txid"] = replaced_txid
    write_json(DRAFT_PATH, draft)
    parsed = save_transaction_analysis(bytes.fromhex(draft["raw_hex"]), "generated_transaction")
    print_json(
        {
            "draft_path": str(DRAFT_PATH),
            "txid": draft["txid"],
            "wtxid": draft["wtxid"],
            "sender": draft["sender_address"],
            "receiver": draft["receiver_address"],
            "payment_sats": draft["payment_sats"],
            "change_sats": draft["change_sats"],
            "fee_sats": draft["fee_sats"],
            "vsize": draft["vsize"],
            "replaces_txid": replaced_txid,
            "byte_coverage": parsed["byte_coverage"],
            "next_step": "inspect draft, then run btc-lab broadcast",
        }
    )


def command_broadcast(args: argparse.Namespace) -> None:
    draft = read_json(DRAFT_PATH)
    checks = verify_p2wpkh_draft(draft)
    if not all(value for key, value in checks.items() if key != "calculated_sighash"):
        raise RuntimeError(f"refusing broadcast: local verification failed: {checks}")
    returned_txid = client_from_args(args).broadcast(draft["raw_hex"])
    if returned_txid != draft["txid"]:
        raise RuntimeError(f"API returned unexpected txid {returned_txid}, expected {draft['txid']}")
    result = {"network": "testnet4", "txid": returned_txid, "local_verification": checks}
    write_json(BROADCAST_PATH, result)
    print_json(result)


def command_fetch_confirmation(args: argparse.Namespace) -> None:
    draft = read_json(DRAFT_PATH)
    client = client_from_args(args)
    status = client.transaction_status(draft["txid"])
    result: dict[str, Any] = {"txid": draft["txid"], "status": status}
    if status.get("confirmed"):
        block_hash = status["block_hash"]
        tx_hex = client.transaction_hex(draft["txid"])
        block_raw = client.block_raw(block_hash)
        RAW_DIR.mkdir(parents=True, exist_ok=True)
        (RAW_DIR / "transaction.hex").write_text(tx_hex + "\n", encoding="ascii")
        (RAW_DIR / "block.hex").write_text(block_raw.hex() + "\n", encoding="ascii")
        transaction = save_transaction_analysis(bytes.fromhex(tx_hex), "confirmed_transaction")
        block = save_block_analysis(block_raw, "confirmed_block")
        result.update(
            {
                "block_hash": block_hash,
                "block_height": status.get("block_height"),
                "transaction_match": transaction["txid"] == draft["txid"],
                "transaction_in_block": draft["txid"] in [tx["txid"] for tx in block["transactions"]],
                "block_merkle_valid": block["merkle_root_valid"],
                "block_pow_valid": block["header"]["pow_valid"],
            }
        )
    write_json(CONFIRMATION_PATH, result)
    print_json(result)


def _raw_from_tx_args(args: argparse.Namespace) -> bytes:
    if args.hex:
        return bytes.fromhex(args.hex.strip())
    if args.file:
        return bytes.fromhex(Path(args.file).read_text(encoding="ascii").strip())
    if DRAFT_PATH.exists():
        return bytes.fromhex(read_json(DRAFT_PATH)["raw_hex"])
    raise RuntimeError("provide --hex/--file or build a transaction first")


def command_parse_tx(args: argparse.Namespace) -> None:
    parsed = save_transaction_analysis(_raw_from_tx_args(args), args.stem)
    print_json(
        {
            "txid": parsed["txid"],
            "wtxid": parsed["wtxid"],
            "size": parsed["size"],
            "vsize": parsed["vsize"],
            "inputs": len(parsed["inputs"]),
            "outputs": len(parsed["outputs"]),
            "byte_coverage": parsed["byte_coverage"],
        }
    )


def command_parse_block(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    block_hash = args.hash
    if args.file:
        raw = bytes.fromhex(Path(args.file).read_text(encoding="ascii").strip())
    else:
        block_hash = block_hash or client.tip_hash()
        raw = client.block_raw(block_hash)
    parsed = save_block_analysis(raw, args.stem)
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    (RAW_DIR / f"{args.stem}.hex").write_text(raw.hex() + "\n", encoding="ascii")
    print_json(
        {
            "requested_block_hash": block_hash,
            "calculated_block_hash": parsed["block_hash"],
            "size": parsed["size"],
            "transaction_count": parsed["transaction_count"],
            "merkle_root_valid": parsed["merkle_root_valid"],
            "pow_valid": parsed["header"]["pow_valid"],
            "coinbase_height": parsed["coinbase_height"],
            "byte_coverage": parsed["byte_coverage"],
        }
    )


def command_verify(_: argparse.Namespace) -> None:
    draft = read_json(DRAFT_PATH)
    checks = verify_p2wpkh_draft(draft)
    if CONFIRMATION_PATH.exists():
        confirmation = read_json(CONFIRMATION_PATH)
        checks["confirmed"] = bool(confirmation.get("status", {}).get("confirmed"))
        if "transaction_in_block" in confirmation:
            checks["transaction_in_block"] = confirmation["transaction_in_block"]
            checks["block_merkle_valid"] = confirmation["block_merkle_valid"]
            checks["block_pow_valid"] = confirmation["block_pow_valid"]
    checks["all_available_checks_pass"] = all(
        value for key, value in checks.items() if key not in {"calculated_sighash", "confirmed"}
    )
    print_json(checks)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Bitcoin Testnet4 transaction and block byte laboratory")
    parser.add_argument("--api", default=DEFAULT_API, help="Esplora-compatible Testnet4 API base URL")
    subparsers = parser.add_subparsers(dest="command", required=True)

    wallet_init = subparsers.add_parser("wallet-init", help="create or load the disposable two-address wallet")
    wallet_init.set_defaults(func=command_wallet_init)

    funding = subparsers.add_parser("funding-status", help="query confirmed sender UTXOs")
    funding.set_defaults(func=command_funding_status)

    build = subparsers.add_parser("build", help="build and sign a one-input/two-output P2WPKH transaction")
    build.add_argument("--payment-sats", type=int, default=1000)
    build.add_argument("--fee-rate", type=float, default=2.0, help="satoshis per virtual byte")
    build.add_argument(
        "--replace-draft",
        action="store_true",
        help="reuse the existing draft's input for an opt-in RBF replacement",
    )
    build.set_defaults(func=command_build)

    broadcast = subparsers.add_parser("broadcast", help="verify locally and broadcast the draft")
    broadcast.set_defaults(func=command_broadcast)

    confirmation = subparsers.add_parser("fetch-confirmation", help="fetch status and parse its confirmed block")
    confirmation.set_defaults(func=command_fetch_confirmation)

    parse_tx = subparsers.add_parser("parse-tx", help="parse raw transaction hex")
    parse_tx.add_argument("--hex")
    parse_tx.add_argument("--file")
    parse_tx.add_argument("--stem", default="manual_transaction")
    parse_tx.set_defaults(func=command_parse_tx)

    parse_block_cmd = subparsers.add_parser("parse-block", help="parse a block by hash, file, or current tip")
    parse_block_cmd.add_argument("--hash")
    parse_block_cmd.add_argument("--file")
    parse_block_cmd.add_argument("--stem", default="latest_block")
    parse_block_cmd.set_defaults(func=command_parse_block)

    verify = subparsers.add_parser("verify", help="recompute the lab transaction signature and identifiers")
    verify.set_defaults(func=command_verify)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except Exception as error:
        print_json({"ok": False, "error": type(error).__name__, "message": str(error)})
        raise SystemExit(1) from error
