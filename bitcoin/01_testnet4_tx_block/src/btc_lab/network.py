from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any


DEFAULT_API = "https://mempool.space/testnet4/api"
USER_AGENT = "btc-testnet4-course-lab/0.1"


class ApiError(RuntimeError):
    pass


class EsploraClient:
    def __init__(self, base_url: str = DEFAULT_API, timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _request(self, path: str, *, data: bytes | None = None, content_type: str | None = None) -> bytes:
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json, text/plain, */*"}
        if content_type:
            headers["Content-Type"] = content_type
        request = urllib.request.Request(self.base_url + path, data=data, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return response.read()
        except urllib.error.HTTPError as error:
            body = error.read().decode("utf-8", errors="replace")
            raise ApiError(f"HTTP {error.code} for {path}: {body}") from error
        except urllib.error.URLError as error:
            raise ApiError(f"network error for {path}: {error.reason}") from error

    def get_json(self, path: str) -> Any:
        return json.loads(self._request(path))

    def get_text(self, path: str) -> str:
        return self._request(path).decode("ascii").strip()

    def get_bytes(self, path: str) -> bytes:
        return self._request(path)

    def address_utxos(self, address: str) -> list[dict[str, Any]]:
        return self.get_json(f"/address/{address}/utxo")

    def transaction_status(self, txid: str) -> dict[str, Any]:
        return self.get_json(f"/tx/{txid}/status")

    def transaction_hex(self, txid: str) -> str:
        return self.get_text(f"/tx/{txid}/hex")

    def block_raw(self, block_hash: str) -> bytes:
        return self.get_bytes(f"/block/{block_hash}/raw")

    def tip_hash(self) -> str:
        return self.get_text("/blocks/tip/hash")

    def broadcast(self, raw_hex: str) -> str:
        return self._request("/tx", data=raw_hex.encode("ascii"), content_type="text/plain").decode("ascii").strip()

