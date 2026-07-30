from btc_lab.encoding import hash160, p2wpkh_script
from btc_lab.transaction import build_and_sign_p2wpkh, verify_p2wpkh_draft


def test_build_and_verify_p2wpkh_transaction():
    coincurve = __import__("coincurve")
    sender_key = coincurve.PrivateKey(bytes.fromhex("01".zfill(64)))
    receiver_key = coincurve.PrivateKey(bytes.fromhex("02".zfill(64)))
    sender_pub = sender_key.public_key.format(compressed=True)
    receiver_pub = receiver_key.public_key.format(compressed=True)
    draft = build_and_sign_p2wpkh(
        private_key=sender_key.secret,
        public_key=sender_pub,
        utxo={"txid": "12" * 32, "vout": 1, "value": 10000},
        receiver_script=p2wpkh_script(receiver_pub),
        change_script=p2wpkh_script(sender_pub),
        payment_sats=1000,
        fee_rate=2,
    )
    result = verify_p2wpkh_draft(draft)
    assert all(value for key, value in result.items() if key != "calculated_sighash")
    assert bytes.fromhex(draft["previous_output_script"])[2:] == hash160(sender_pub)
    assert draft["transaction"]["inputs"][0]["sequence"] == 0xFFFFFFFD

    replacement = build_and_sign_p2wpkh(
        private_key=sender_key.secret,
        public_key=sender_pub,
        utxo={"txid": "12" * 32, "vout": 1, "value": 10000},
        receiver_script=p2wpkh_script(receiver_pub),
        change_script=p2wpkh_script(sender_pub),
        payment_sats=1000,
        fee_rate=10,
    )
    assert replacement["transaction"]["inputs"][0] == draft["transaction"]["inputs"][0]
    assert replacement["fee_sats"] > draft["fee_sats"]
    assert replacement["change_sats"] < draft["change_sats"]
    assert verify_p2wpkh_draft(replacement)["signature_valid"]
