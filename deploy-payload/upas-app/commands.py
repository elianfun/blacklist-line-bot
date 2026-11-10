"""LINE 文字指令解析與執行。"""
import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timedelta

from . import bl_client, confirm
from .upas_client import UpasClient, UpasError

client = UpasClient()

HELP = """UPAS 指令：
查 <IP>              IP 即時資訊 + 白名單
查 <MAC> [IP]        白名單（MAC only 免填 IP）
事件 [今天|N天] [代碼,...]  預設代碼 3,8（外來設備）
備註                 手動管制備註編號
阻斷 <IP或MAC> [分鐘|永久] [#備註id]  預設永久
解除 <IP或MAC>
白名單加 <MAC> [IP] [電腦名稱]  IP 省略=MAC only
白名單刪 <MAC> [IP]
寫入類指令需按「確認」才會執行。"""

EVENT_NAMES = {
    1: "非管理區段", 2: "內部改IP", 3: "外來設備(Static)", 4: "Sensor服務停止", 5: "Sensor無法連線",
    6: "外部搶IP", 7: "內部搶IP", 8: "外來設備(DHCP)", 11: "DHCP改Static", 12: "使用非指定Switchport",
    16: "使用非法DHCP IP", 17: "手動IP阻斷", 18: "手動MAC阻斷", 19: "電腦名稱命名錯誤",
    26: "Agent無回應", 27: "Windows未更新", 28: "防毒與病毒碼未更新", 31: "跨Vlan", 32: "偽冒MAC位址",
    49: "Agent未安裝", 53: "發現非法DHCP Server", 57: "電腦名稱異動", 58: "廣播封包超標",
    100: "禁用時段上線", 101: "一機兩網", 132: "未允許MAC使用保留IP", 150: "IPonly發生IP衝突",
}

CODES = {
    "block": {"0": "阻斷成功", "2": "處理失敗", "3": "IP/MAC 格式錯誤", "4": "暫時性阻斷缺少時效",
              "5": "IP/MAC 重複", "6": "時效超出範圍（分鐘需 10~59 或整點以上）", "7": "IP 與 MAC 只能擇一",
              "9": "缺少必要欄位", "99": "系統錯誤"},
    "release": {"0": "解除成功", "1": "部分解除成功", "3": "IP/MAC 格式錯誤", "9": "缺少必要欄位",
                "99": "刪除手動阻斷紀錄失敗"},
    "wl_add": {"0": "新增成功", "1": "授權數不足", "2": "IP/MAC 格式錯誤", "3": "IP/MAC 已存在於白名單",
               "4": "白名單鎖定", "5": "IP 不在 Sensor 子網或管理區段", "6": "IP 在 DHCP 派發範圍",
               "7": "暫時性白名單已有此 MAC", "8": "已存在於另一種白名單", "9": "缺少必要欄位"},
    "wl_del": {"0": "刪除成功", "1": "授權數不足", "2": "IP/MAC 格式錯誤", "3": "IP/MAC 不存在於白名單",
               "4": "白名單鎖定", "9": "缺少必要欄位"},
}


@dataclass
class Reply:
    text: str
    confirm_token: str | None = None


def norm_mac(s: str) -> str | None:
    m = re.sub(r"[:\-.]", "", s).upper()
    return m if re.fullmatch(r"[0-9A-F]{12}", m) else None


def is_ip(s: str) -> bool:
    try:
        ipaddress.IPv4Address(s)
        return True
    except ValueError:
        return False


def target(s: str) -> tuple[str, str] | None:
    """回傳 (ip, mac)，兩者擇一。"""
    if is_ip(s):
        return s, ""
    mac = norm_mac(s)
    return ("", mac) if mac else None


def handle_text(user_id: str, text: str) -> Reply:
    parts = text.strip().split()
    if not parts:
        return Reply(HELP)
    cmd, args = parts[0], parts[1:]
    try:
        if cmd in ("說明", "help", "?", "？"):
            return Reply(HELP)
        if cmd == "查":
            return Reply(query(args))
        if cmd == "事件":
            return Reply(events(args))
        if cmd == "備註":
            return Reply("\n".join(f"{c['id']}: {c['comment'] or '(空白)'}" for c in client.comments()))
        if cmd in ("阻斷", "解除", "白名單加", "白名單刪"):
            return prepare_write(user_id, cmd, args)
    except UpasError as e:
        return Reply(f"UPAS 呼叫失敗：{e}")
    return Reply("看不懂這個指令，輸入「說明」查看用法。")


def query(args: list[str]) -> str:
    if not args:
        return "用法：查 <IP> 或 查 <MAC> [IP]"
    if is_ip(args[0]):
        ip = args[0]
        lines = []
        rt = client.realtime_by_ip(ip)
        if rt:
            r = rt[0]
            lines += [f"【即時】{ip} 在線", f"MAC：{r.get('mac')}", f"電腦：{r.get('compName')}",
                      f"Switch：{r.get('swDesc') or r.get('swIP')} {r.get('swPort')} VLAN {r.get('swVlan')}",
                      f"Sensor：{r.get('sensorDesc')}", f"上線：{r.get('startTime')}"]
            if r.get("abormalCodes"):
                lines.append(f"異常：{r.get('abormalCodes')} {r.get('alarmInfo', '')}")
        else:
            lines.append(f"【即時】{ip} 目前不在線")
        wl = client.whitelist_by_ip(ip)
        lines.append(fmt_whitelist(wl))
        return "\n".join(lines)
    mac = norm_mac(args[0])
    if not mac:
        return "IP/MAC 格式錯誤"
    ip = args[1] if len(args) > 1 and is_ip(args[1]) else "0.0.0.0"
    return fmt_whitelist(client.whitelist_by_ipmac(ip, mac))


def fmt_whitelist(d: dict) -> str:
    w = d.get("whitelist")
    if d.get("responseCode") != "0" or not w:
        return "【白名單】查無（MAC only 的白名單請改用：查 <MAC>）"
    kind = "暫時性" if w.get("timeEffect") == 2 else "資產"
    s = [f"【白名單】{kind}", f"IP/MAC：{w.get('ip')} / {w.get('mac')}", f"電腦：{w.get('compName')}",
         f"群組：{w.get('group') or '-'}", f"最近使用：{w.get('recentD') or '-'}"]
    extras = [f"{x['fieldColumn']}={x['fieldValue']}" for x in w.get("whitelistExtras") or [] if x.get("fieldValue")]
    if extras:
        s.append("欄位：" + ", ".join(extras))
    return "\n".join(s)


def events(args: list[str]) -> str:
    days, codes = 1, ["3", "8"]
    for a in args:
        if a == "今天":
            days = 1
        elif m := re.fullmatch(r"(\d+)天", a):
            days = min(int(m.group(1)), 31)
        elif re.fullmatch(r"[\d,]+", a):
            codes = [c for c in a.split(",") if c]
    d = client.events(days, codes, limit=1000)
    if d.get("responseCode") != "0":
        return f"查詢失敗（responseCode {d.get('responseCode')}）"
    # Console 實測不理會 dateRange（只回約最近 24 小時），所以在這裡依日期再過濾一次
    since = (datetime.now() - timedelta(days=days - 1)).strftime("%Y-%m-%d 00:00:00")
    rows = [e for e in d.get("networkevents") or [] if (e.get("occurTime") or "") >= since]
    rows.sort(key=lambda e: e.get("occurTime") or "", reverse=True)
    names = "、".join(EVENT_NAMES.get(int(c), c) for c in codes)
    out = [f"{'今天' if days == 1 else f'近 {days} 天'}【{names}】共 {len(rows)} 筆"
           + ("（顯示最新 20）" if len(rows) > 20 else "")]
    if days > 1:
        out.append("※ Console 只提供約最近 24 小時的事件")
    for e in rows[:20]:
        out.append(f"{e.get('occurTime', '')[5:16]} {e.get('ip')} {e.get('mac')} "
                   f"{EVENT_NAMES.get(e.get('causeType'), e.get('causeType'))}"
                   f"{' 🔒' if e.get('isblock') else ''}")
    return "\n".join(out)


def prepare_write(user_id: str, cmd: str, args: list[str]) -> Reply:
    if cmd in ("阻斷", "解除"):
        if not args or not (t := target(args[0])):
            return Reply(f"用法：{cmd} <IP或MAC>")
        ip, mac = t
        action = {"op": "block" if cmd == "阻斷" else "release", "ip": ip, "mac": mac}
        desc = f"{cmd} {ip or mac}"
        if cmd == "阻斷":
            minutes, comment_id = None, None
            for a in args[1:]:
                if a == "永久":
                    minutes = None
                elif a.isdigit():
                    minutes = int(a)
                elif a.startswith("#") and a[1:].isdigit():
                    comment_id = int(a[1:])
            if minutes is not None and not (10 <= minutes <= 999 * 60 + 59):
                return Reply("阻斷分鐘數需介於 10 ~ 59999")
            action.update(minutes=minutes, comment_id=comment_id)
            desc += f"，{'永久' if minutes is None else f'{minutes} 分鐘'}"
            if comment_id is not None:
                desc += f"，備註 #{comment_id}"
    else:
        if not args or not (mac := norm_mac(args[0])):
            return Reply(f"用法：{cmd} <MAC> [IP]")
        ip = args[1] if len(args) > 1 and is_ip(args[1]) else "0.0.0.0"
        if cmd == "白名單加":
            name = next((a for a in args[1:] if not is_ip(a)), "")
            action = {"op": "wl_add", "mac": mac, "ip": ip, "name": name}
            desc = f"新增資產白名單 {mac} / {ip}" + (f"（{name}）" if name else "")
        else:
            action = {"op": "wl_del", "mac": mac, "ip": ip}
            desc = f"刪除白名單 {mac} / {ip}"
    token = confirm.put(user_id, action)
    return Reply(f"即將執行：{desc}\n請於 60 秒內按「確認」。", confirm_token=token)


def execute(action: dict) -> str:
    op = action["op"]
    if op in ("bl_add", "bl_del"):
        return _execute_bl(op, action)
    try:
        if op == "block":
            d = client.block(action["ip"], action["mac"], action.get("minutes"), action.get("comment_id"))
        elif op == "release":
            d = client.release(action["ip"], action["mac"])
        elif op == "wl_add":
            d = client.whitelist_add(action["mac"], action["ip"], action.get("name", ""))
        elif op == "wl_del":
            d = client.whitelist_delete(action["mac"], action["ip"])
        else:
            return "未知操作"
    except UpasError as e:
        return f"UPAS 呼叫失敗：{e}"
    code = str(d.get("responseCode"))
    msg = CODES[op].get(code, f"未知回應碼 {code}")
    note = f"\n備註：{d['note']}" if d.get("note") else ""
    return f"{'✅' if code == '0' else '❌'} {msg}{note}"


def _execute_bl(op: str, action: dict) -> str:
    """HFS 黑名單更新：呼叫同機 blacklist-line-bot 的內部 API（防呆在 bot 端）。"""
    add = op == "bl_add"
    try:
        res = bl_client.update("add" if add else "remove", action["ips"])
    except bl_client.BlError as e:
        return f"❌ 黑名單{'新增' if add else '移除'}失敗：{e}"
    if err := res.get("error"):
        return f"❌ 黑名單{'新增' if add else '移除'}失敗：{err}"
    if add:
        detail = (f"已新增 {len(res.get('added', []))} 筆"
                  f"（略過白名單 {len(res.get('skipped_whitelist', []))}、"
                  f"重複 {len(res.get('skipped_duplicate', []))}、"
                  f"格式錯誤 {len(res.get('skipped_invalid', []))}）")
    else:
        detail = (f"已移除 {len(res.get('removed', []))} 筆"
                  f"（查無 {len(res.get('not_found', []))}、格式錯誤 {len(res.get('invalid', []))}）")
    return f"✅ 黑名單{'新增' if add else '移除'}完成：{detail}，最終 {res.get('final_total')} 筆"
