"""黑名單 LINE Bot 內部 API 用戶端（同機 127.0.0.1，不走 tunnel）。"""
import os

import httpx

BASE = os.environ.get("BLACKLIST_API_URL", "http://127.0.0.1:8000").rstrip("/")
TOKEN = os.environ.get("BLACKLIST_API_TOKEN", "")


class BlError(Exception):
    pass


def _headers() -> dict:
    return {"Authorization": f"Bearer {TOKEN}"} if TOKEN else {}


def status(ip: str) -> dict:
    try:
        r = httpx.get(f"{BASE}/api/status", params={"ip": ip}, headers=_headers(), timeout=10)
    except httpx.HTTPError as e:
        raise BlError(str(e))
    if r.status_code != 200:
        raise BlError(f"HTTP {r.status_code} {r.text[:200]}")
    return r.json()


def update(op: str, ips: list[str]) -> dict:
    try:
        r = httpx.post(f"{BASE}/api/update", json={"op": op, "ips": ips}, headers=_headers(), timeout=30)
    except httpx.HTTPError as e:
        raise BlError(str(e))
    if r.status_code != 200:
        raise BlError(f"HTTP {r.status_code} {r.text[:200]}")
    return r.json()
