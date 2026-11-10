"""給 AI agent（Hermes）呼叫的 UPAS 工具 API。
驗證：HMAC 簽章（X-Timestamp / X-Signature）+ 來源 IP 白名單 + 失敗鎖定，見 security.py。
寫入類操作不直接執行，改送「UPAS 審核」LINE Bot 由人工確認，見 approval.py。"""
import asyncio
import logging
import os
import time
from collections import deque

from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

from fastapi import Depends, FastAPI, Header, HTTPException  # noqa: E402
from pydantic import BaseModel, Field  # noqa: E402
from starlette.concurrency import run_in_threadpool  # noqa: E402

from . import approval, bl_client, security  # noqa: E402
from .commands import EVENT_NAMES, client, is_ip, norm_mac, target  # noqa: E402
from .upas_client import UpasError  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
WRITE_LIMIT = int(os.environ.get("WRITE_LIMIT_PER_HOUR", "30"))
_writes: deque[float] = deque()

app = FastAPI(title="UPAS Tools API", docs_url=None, redoc_url=None, openapi_url=None)
app.include_router(approval.router)


@app.on_event("startup")
async def _start_webhook_sync():
    asyncio.create_task(approval.webhook_sync_loop())


def write_quota():
    now = time.time()
    while _writes and now - _writes[0] > 3600:
        _writes.popleft()
    if len(_writes) >= WRITE_LIMIT:
        raise HTTPException(429, f"寫入類操作超過每小時 {WRITE_LIMIT} 次上限")
    _writes.append(now)


def upas(fn, *a):
    try:
        return fn(*a)
    except UpasError as e:
        raise HTTPException(502, f"UPAS error: {e}")


@app.get("/health")
def health():
    return {"ok": True}


# ---------- 查詢 ----------
class IpIn(BaseModel):
    ip: str = Field(description="IPv4，例如 10.0.1.20")


class MacIn(BaseModel):
    mac: str = Field(description="MAC，可含 : 或 -")
    ip: str = Field("0.0.0.0", description="白名單登記的 IP；MAC only 白名單用 0.0.0.0")


class EventsIn(BaseModel):
    cause_types: list[int] = Field([3, 8], description="事件代碼；預設 3,8 外來設備")
    limit: int = Field(50, le=1000)


def block_status(evs: list) -> dict:
    latest: dict = {}
    for e in evs:
        if e.get("isblock"):
            name = EVENT_NAMES.get(e.get("causeType"), str(e.get("causeType")))
            latest[name] = max(latest.get(name, ""), e.get("occurTime") or "")
    reasons = [f"{n}（{t} 起）" for n, t in latest.items()]
    return {"blocked": bool(reasons), "reasons": reasons,
            "summary": ("目前被 UPAS 封鎖：" + "、".join(reasons)) if reasons else "目前未被 UPAS 封鎖"}


def describe_ip(ip: str) -> tuple[dict | None, str]:
    rt = upas(client.realtime_by_ip, ip)
    r = rt[0] if rt else None
    if not r:
        return None, f"{ip} 目前不在線"
    line = (f"{ip} 在線，MAC {r.get('mac')}，電腦 {r.get('compName') or '-'}，"
            f"Switch {r.get('swDesc') or r.get('swIP') or '-'} {r.get('swPort') or ''} VLAN {r.get('swVlan') or '-'}")
    if r.get("alarmInfo"):
        line += f"，{r['alarmInfo']}"
    return r, line


@app.post("/tools/query_ip", dependencies=[Depends(security.verify)])
def query_ip(body: IpIn):
    if not is_ip(body.ip):
        raise HTTPException(400, "ip 格式錯誤")
    r, line = describe_ip(body.ip)
    wl = upas(client.whitelist_by_ip, body.ip)
    w = wl.get("whitelist") if wl.get("responseCode") == "0" else None
    st = block_status(upas(client.events_for, body.ip, (r or {}).get("mac", "")))
    summary = f"{line}；{st['summary']}；白名單：{'有' if w else '無（若為 MAC only 白名單請用 query_mac 查）'}"
    return {"summary": summary, "blocked": st["blocked"], "block_reasons": st["reasons"],
            "online": bool(r), "realtime": r, "whitelist": w}


@app.post("/tools/query_mac", dependencies=[Depends(security.verify)])
def query_mac(body: MacIn):
    mac = norm_mac(body.mac)
    if not mac or not is_ip(body.ip):
        raise HTTPException(400, "mac/ip 格式錯誤")
    wl = upas(client.whitelist_by_ipmac, body.ip, mac)
    w = wl.get("whitelist") if wl.get("responseCode") == "0" else None
    st = block_status(upas(client.events_for, "", mac))
    return {"summary": f"{mac}：{st['summary']}；白名單：{'有' if w else '無'}",
            "blocked": st["blocked"], "block_reasons": st["reasons"], "whitelist": w}


@app.post("/tools/events", dependencies=[Depends(security.verify)])
def events(body: EventsIn):
    d = upas(client.events, 1, [str(c) for c in body.cause_types], body.limit)
    rows = sorted(d.get("networkevents") or [], key=lambda e: e.get("occurTime") or "", reverse=True)
    for e in rows:
        e["causeName"] = EVENT_NAMES.get(e.get("causeType"), "")
    return {"total": len(rows), "events": rows}


@app.get("/tools/event_codes", dependencies=[Depends(security.verify)])
def event_codes():
    return EVENT_NAMES


@app.get("/tools/comments", dependencies=[Depends(security.verify)])
def comments():
    return upas(client.comments)


@app.get("/tools/pending/{pid}", dependencies=[Depends(security.verify)])
def pending_status(pid: str):
    return approval.status(pid)


# ---------- 寫入（一律送人工審核） ----------
class BlockIn(BaseModel):
    target: str = Field(description="IP 或 MAC（擇一）")
    minutes: int | None = Field(None, ge=10, le=59999, description="阻斷分鐘數；省略=永久")
    comment_id: int | None = None


class ReleaseIn(BaseModel):
    target: str


class WlIn(BaseModel):
    mac: str
    ip: str = "0.0.0.0"
    comp_name: str = ""


def _target_detail(ip: str, mac: str) -> tuple[str, str]:
    """回傳 (說明文字, 線上 MAC)；IP 對象會查即時資訊，讓核准者看清楚是哪台。"""
    if ip:
        r, line = describe_ip(ip)
        return line, (r or {}).get("mac", "")
    wl = upas(client.whitelist_by_ipmac, "0.0.0.0", mac)
    w = wl.get("whitelist") if wl.get("responseCode") == "0" else None
    return f"MAC {mac}，白名單：{'有（' + (w.get('compName') or '-') + '）' if w else '無'}", mac


@app.post("/tools/block", dependencies=[Depends(write_quota)])
async def block(body: BlockIn, src: str = Depends(security.verify), x_line_user: str = Header(default="")):
    t = target(body.target)
    if not t:
        raise HTTPException(400, "target 必須是 IPv4 或 MAC")
    ip, mac = t
    detail, online_mac = await run_in_threadpool(_target_detail, ip, mac)
    if security.is_protected(ip, mac or online_mac):
        raise HTTPException(403, f"{body.target} 在保護清單內，禁止阻斷")
    action = {"op": "block", "ip": ip, "mac": mac, "minutes": body.minutes, "comment_id": body.comment_id}
    summary = f"阻斷 {ip or mac}，{'永久' if body.minutes is None else f'{body.minutes} 分鐘'}"
    return await approval.request(action, summary, detail, x_line_user, src)


@app.post("/tools/release", dependencies=[Depends(write_quota)])
async def release(body: ReleaseIn, src: str = Depends(security.verify), x_line_user: str = Header(default="")):
    t = target(body.target)
    if not t:
        raise HTTPException(400, "target 必須是 IPv4 或 MAC")
    detail, _ = await run_in_threadpool(_target_detail, *t)
    action = {"op": "release", "ip": t[0], "mac": t[1]}
    return await approval.request(action, f"解除阻斷 {t[0] or t[1]}", detail, x_line_user, src)


@app.post("/tools/whitelist_add", dependencies=[Depends(write_quota)])
async def whitelist_add(body: WlIn, src: str = Depends(security.verify), x_line_user: str = Header(default="")):
    mac = norm_mac(body.mac)
    if not mac or not is_ip(body.ip):
        raise HTTPException(400, "mac/ip 格式錯誤")
    action = {"op": "wl_add", "mac": mac, "ip": body.ip, "name": body.comp_name}
    summary = f"新增資產白名單 {mac} / {body.ip}" + (f"（{body.comp_name}）" if body.comp_name else "")
    return await approval.request(action, summary, f"MAC {mac}，IP {body.ip}", x_line_user, src)


@app.post("/tools/whitelist_delete", dependencies=[Depends(write_quota)])
async def whitelist_delete(body: WlIn, src: str = Depends(security.verify), x_line_user: str = Header(default="")):
    mac = norm_mac(body.mac)
    if not mac or not is_ip(body.ip):
        raise HTTPException(400, "mac/ip 格式錯誤")
    if security.is_protected(body.ip, mac):
        raise HTTPException(403, "在保護清單內，禁止刪除白名單")
    detail, _ = await run_in_threadpool(_target_detail, "", mac)
    action = {"op": "wl_del", "mac": mac, "ip": body.ip}
    return await approval.request(action, f"刪除白名單 {mac} / {body.ip}", detail, x_line_user, src)


# ---------- HFS 黑名單（blacklist-line-bot，同機 127.0.0.1） ----------
class BlStatusIn(BaseModel):
    ip: str = Field(description="IPv4")


class BlUpdateIn(BaseModel):
    ips: list[str] = Field(min_length=1, max_length=200, description="IPv4 清單")


@app.post("/tools/bl_status", dependencies=[Depends(security.verify)])
def bl_status(body: BlStatusIn):
    if not is_ip(body.ip):
        raise HTTPException(400, "ip 格式錯誤")
    try:
        return bl_client.status(body.ip)
    except bl_client.BlError as e:
        raise HTTPException(502, f"blacklist-bot error: {e}")


@app.post("/tools/bl_add", dependencies=[Depends(write_quota)])
async def bl_add(body: BlUpdateIn, src: str = Depends(security.verify), x_line_user: str = Header(default="")):
    return await _bl_write("bl_add", body.ips, x_line_user, src)


@app.post("/tools/bl_del", dependencies=[Depends(write_quota)])
async def bl_del(body: BlUpdateIn, src: str = Depends(security.verify), x_line_user: str = Header(default="")):
    return await _bl_write("bl_del", body.ips, x_line_user, src)


async def _bl_write(op: str, ips: list[str], x_line_user: str, src: str):
    if any(not is_ip(ip) for ip in ips):
        raise HTTPException(400, "ips 含非 IPv4")
    uniq = list(dict.fromkeys(ips))
    lines = []
    for ip in uniq[:20]:
        try:
            st = bl_client.status(ip)
            state = ("已在黑名單" if st.get("in_blacklist")
                     else "命中白名單（不會變更）" if st.get("whitelisted") else "不在黑名單")
            lines.append(f"{ip}：{state}")
        except bl_client.BlError as e:
            lines.append(f"{ip}：查詢失敗（{e}）")
    verb = "新增" if op == "bl_add" else "移除"
    summary = f"黑名單{verb} {len(uniq)} 筆"
    action = {"op": op, "ips": uniq}
    return await approval.request(action, summary, "\n".join(lines), x_line_user, src)
