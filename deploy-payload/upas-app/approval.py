"""寫入操作的伺服器端人工審核（MFA 雙因子）：推送到「UPAS 審核」LINE Bot，
核准者本人按確認並輸入一次性確認碼才執行。

因子：
1. LINE 帳號身分 —— 只有 APPROVERS 內的 userId 且為審核單申請人本人可核准
2. 一次性確認碼（OTP）—— 建單時產生、只回傳給發起端（Hermes），不推送到 LINE；
   核准者須在 LINE 輸入該碼，發起通道與審核通道兩邊到齊才執行
3. 時效 —— 5 分鐘內有效、單次使用

AI（Hermes）拿得到 pending_id 與確認碼，但無法在 LINE 端完成核准，仍需本人操作。
審核單持久化於 SQLite（data/pending.db），服務重啟不遺失。
"""
import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import time

import httpx
from fastapi import APIRouter, HTTPException, Request
from starlette.concurrency import run_in_threadpool

from . import audit, commands

log = logging.getLogger("upas-approval")

CHANNEL_SECRET = os.environ.get("LINE_CHANNEL_SECRET", "").encode()
ACCESS_TOKEN = os.environ.get("LINE_CHANNEL_ACCESS_TOKEN", "")
APPROVERS = {u.strip() for u in os.environ.get("APPROVER_LINE_USER_IDS", "").split(",") if u.strip()}
TTL = 300
MAX_TRIES = 5
PUBLIC_URL = os.environ.get("PUBLIC_URL", "").rstrip("/")
TUNNEL_LOG = os.path.join(os.path.dirname(__file__), "..", "logs", "cloudflared.log")
DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "pending.db")

# rec: dict(pid, action, requester, created, status, result, approver, source_ip, otp, tries)
router = APIRouter()

CONFIRM_RE = re.compile(r"(?:確認|confirm|approve)\s+#?([0-9a-f]{8})\s+(\d{6})", re.I)
REJECT_RE = re.compile(r"(?:取消|reject|cancel)\s+#?([0-9a-f]{8})", re.I)


def enabled() -> bool:
    return bool(CHANNEL_SECRET and ACCESS_TOKEN and APPROVERS)


# ---- 持久化（SQLite） ----
def _db() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE IF NOT EXISTS pending (pid TEXT PRIMARY KEY, rec TEXT NOT NULL)")
    return conn


def _save(rec: dict):
    with _db() as conn:
        conn.execute("INSERT OR REPLACE INTO pending (pid, rec) VALUES (?, ?)",
                     (rec["pid"], json.dumps(rec, ensure_ascii=False)))


def _get(pid: str) -> dict | None:
    with _db() as conn:
        row = conn.execute("SELECT rec FROM pending WHERE pid=?", (pid,)).fetchone()
    return json.loads(row[0]) if row else None


def _purge():
    now = time.time()
    with _db() as conn:
        for (raw,) in conn.execute("SELECT rec FROM pending").fetchall():
            rec = json.loads(raw)
            if rec["status"] == "pending" and now - rec["created"] > TTL:
                rec["status"] = "expired"
                conn.execute("UPDATE pending SET rec=? WHERE pid=?",
                             (json.dumps(rec, ensure_ascii=False), rec["pid"]))
        conn.execute("DELETE FROM pending WHERE pid IN (SELECT pid FROM pending WHERE "
                     "CAST(json_extract(rec, '$.created') AS REAL) < ?)", (now - 86400,))


def _expire_one(rec: dict):
    if rec["status"] == "pending" and time.time() - rec["created"] > TTL:
        rec["status"] = "expired"
        _save(rec)


async def _line(path: str, payload: dict, method: str = "POST") -> httpx.Response:
    async with httpx.AsyncClient(timeout=10) as c:
        return await c.request(method, "https://api.line.me" + path, json=payload,
                               headers={"Authorization": f"Bearer {ACCESS_TOKEN}"})


async def request(action: dict, summary: str, detail: str, requester: str, source_ip: str) -> dict:
    """建立 pending 並推送審核通知。確認碼只回傳給發起端，不進 LINE 訊息。"""
    if not enabled():
        raise HTTPException(503, "審核機制未設定（LINE_CHANNEL_* / APPROVER_LINE_USER_IDS），寫入操作已停用")
    if requester not in APPROVERS:
        raise HTTPException(403, "X-Line-User 不在核准者名單")
    _purge()
    pid = secrets.token_hex(4)
    otp = f"{secrets.randbelow(1000000):06d}"
    rec = {"pid": pid, "action": action, "requester": requester, "created": time.time(),
           "status": "pending", "result": None, "approver": None, "source_ip": source_ip,
           "otp": otp, "tries": 0}
    _save(rec)
    text = (f"🔐 UPAS 審核 #{pid}\n操作：{summary}\n{detail}\n來源：Hermes（{source_ip}）\n"
            f"請按「確認執行」並輸入 6 碼確認碼（在 Hermes 對話中取得）。\n5 分鐘內有效。")
    confirm = {"type": "template", "altText": f"UPAS 審核 #{pid}：{summary}",
               "template": {"type": "confirm", "text": f"#{pid} {summary}"[:240], "actions": [
                   {"type": "postback", "label": "確認執行（輸入確認碼）", "data": f"approve:{pid}",
                    "inputOption": "openKeyboard", "fillInText": f"確認 {pid} ",
                    "displayText": f"確認 {pid}"},
                   {"type": "postback", "label": "取消", "data": f"reject:{pid}",
                    "displayText": f"取消 {pid}"}]}}
    r = await _line("/v2/bot/message/push", {"to": requester, "messages": [{"type": "text", "text": text}, confirm]})
    if r.status_code != 200:
        rec["status"] = "error"
        _save(rec)
        log.error("推送審核失敗 %s %s", r.status_code, r.text)
        raise HTTPException(502, "推送審核通知失敗")
    audit.write(requester, {**action, "pending_id": pid, "source_ip": source_ip}, "pending")
    return {"status": "pending", "pending_id": pid, "confirm_code": otp,
            "message": (f"已送出審核 #{pid}，確認碼 {otp}。請到「UPAS 審核」LINE 按『確認執行』"
                        f"並輸入此確認碼（5 分鐘內有效）。AI 無法代為確認。")}


def status(pid: str) -> dict:
    _purge()
    rec = _get(pid)
    if not rec:
        raise HTTPException(404, "查無此審核單")
    return {"pending_id": pid, "status": rec["status"], "result": rec["result"]}


async def _reply(token: str, text: str):
    await _line("/v2/bot/message/reply", {"replyToken": token, "messages": [{"type": "text", "text": text[:4900]}]})


@router.post("/callback", include_in_schema=False)
async def callback(req: Request):
    body = await req.body()
    expected = base64.b64encode(hmac.new(CHANNEL_SECRET, body, hashlib.sha256).digest()).decode()
    if not CHANNEL_SECRET or not hmac.compare_digest(req.headers.get("x-line-signature", ""), expected):
        raise HTTPException(400, "bad signature")
    for ev in json.loads(body).get("events", []):
        try:
            await _handle(ev)
        except Exception:
            log.exception("審核事件處理失敗")
    return "OK"


def _extract(ev: dict) -> tuple[str, str, str]:
    """從各種事件形態取出 (kind, pid, code)。
    相容：postback data（approve:pid[:code]）、鍵盤輸入文字（確認 pid code / 取消 pid）、
    postback.params 的文字。"""
    kind = pid = code = ""
    if ev.get("type") == "postback":
        data = (ev.get("postback") or {}).get("data", "")
        k, _, rest = data.partition(":")
        pid, _, code = rest.partition(":")
        kind = k
    texts = []
    msg = ev.get("message") or {}
    if msg.get("text"):
        texts.append(msg["text"])
    params = (ev.get("postback") or {}).get("params") or {}
    texts.extend(str(v) for v in params.values())
    for t in texts:
        if m := CONFIRM_RE.search(t):
            return "approve", m.group(1), m.group(2)
        if m := REJECT_RE.search(t):
            return "reject", m.group(1), ""
    return kind, pid, code


async def _handle(ev: dict):
    token = ev.get("replyToken")
    uid = (ev.get("source") or {}).get("userId", "")
    if not token:
        return
    if uid not in APPROVERS:
        await _reply(token, f"此帳號不是 UPAS 核准者。\nuserId：{uid}")
        return
    kind, pid, code = _extract(ev)
    if not kind:
        await _reply(token, "這個帳號只用於 UPAS 操作審核。\n確認請按審核卡按鈕並輸入確認碼，"
                            "或直接傳送：確認 <審核單號> <確認碼>")
        return
    _purge()
    rec = _get(pid) if pid else None
    if not rec or rec["status"] != "pending":
        await _reply(token, f"#{pid} 已{'逾時' if rec and rec['status'] == 'expired' else '處理過或不存在'}。")
        return
    if rec["requester"] != uid:
        await _reply(token, f"#{pid} 不是你的審核單。")
        return
    rec["approver"] = uid
    if kind == "reject":
        rec["status"] = "rejected"
        _save(rec)
        audit.write(uid, {**rec["action"], "pending_id": pid}, "rejected")
        await _reply(token, f"#{pid} 已取消。")
        return
    # approve：需驗證一次性確認碼（MFA 因子 2）
    _expire_one(rec)
    if rec["status"] != "pending":
        _save(rec)
        await _reply(token, f"#{pid} 已逾時（5 分鐘）。")
        return
    if not code:
        await _reply(token, f"#{pid} 缺少確認碼。\n請輸入：確認 {pid} <6 碼確認碼>")
        return
    if not hmac.compare_digest(code.strip(), rec["otp"]):
        rec["tries"] += 1
        if rec["tries"] >= MAX_TRIES:
            rec["status"] = "expired"
            _save(rec)
            audit.write(uid, {**rec["action"], "pending_id": pid}, "otp_locked")
            await _reply(token, f"#{pid} 確認碼錯誤次數過多，審核單已作廢。請重新送出操作。")
            return
        _save(rec)
        await _reply(token, f"確認碼錯誤（剩 {MAX_TRIES - rec['tries']} 次機會）。\n請輸入：確認 {pid} <6 碼確認碼>")
        return
    rec["status"] = "approved"
    _save(rec)
    result = await run_in_threadpool(commands.execute, rec["action"])
    rec["status"], rec["result"] = "done", result
    _save(rec)
    audit.write(uid, {**rec["action"], "pending_id": pid, "approver": uid}, result)
    await _reply(token, f"#{pid} {result}")


# ---- 自動設定審核 Bot 的 webhook（具名 tunnel 用 PUBLIC_URL；quick tunnel 追蹤 log 中的新網址） ----
async def webhook_sync_loop():
    last = ""
    while True:
        try:
            urls = []
            if PUBLIC_URL:  # 具名 tunnel：固定網址
                urls = [PUBLIC_URL]
            elif os.path.exists(TUNNEL_LOG):  # quick tunnel：從 log 取最新網址
                with open(TUNNEL_LOG, encoding="utf-8", errors="ignore") as f:
                    urls = re.findall(r"https://[a-z0-9-]+\.trycloudflare\.com", f.read())
            if enabled():
                if urls and urls[-1] != last:
                    r = await _line("/v2/bot/channel/webhook/endpoint", {"endpoint": urls[-1] + "/callback"}, "PUT")
                    if r.status_code == 200:
                        last = urls[-1]
                        log.info("審核 Bot webhook 已更新為 %s/callback", last)
                    else:
                        log.error("更新 webhook 失敗 %s %s", r.status_code, r.text)
        except Exception:
            log.exception("webhook 同步失敗")
        await asyncio.sleep(60)
