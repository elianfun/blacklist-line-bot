import os
import re
import hmac
import base64
import hashlib
import logging
import subprocess
from pathlib import Path

from flask import Flask, request, abort
from dotenv import load_dotenv
import requests

from whitelist import build_whitelist, is_whitelisted, get_ip_obj, WHITELIST

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

CHANNEL_SECRET = os.environ["LINE_CHANNEL_SECRET"]
CHANNEL_ACCESS_TOKEN = os.environ["LINE_CHANNEL_ACCESS_TOKEN"]

AUTHORIZED_USERS_FILE = BASE_DIR / "authorized_users.txt"
LIVE_IP_TXT = Path("/home/inno/hfs/share/blacklist/ip.txt")
STAGING_IP_TXT = Path("/home/inno/blacklist-bot/staging/ip.txt")
APPLY_SCRIPT = "/usr/local/sbin/blacklist-apply-update.sh"

TOKEN_SPLIT_RE = re.compile(r"[\s,，、;；]+")
IP_LIKE_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("blacklist-bot")

app = Flask(__name__)
WHITELIST_NETWORKS = build_whitelist(WHITELIST)


def load_authorized_users():
    if not AUTHORIZED_USERS_FILE.exists():
        return set()
    return {
        line.strip()
        for line in AUTHORIZED_USERS_FILE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    }


def verify_signature(body: bytes, signature: str) -> bool:
    if not signature:
        return False
    mac = hmac.new(CHANNEL_SECRET.encode("utf-8"), body, hashlib.sha256)
    expected = base64.b64encode(mac.digest()).decode("utf-8")
    return hmac.compare_digest(expected, signature)


def reply_message(reply_token: str, text: str):
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {CHANNEL_ACCESS_TOKEN}",
    }
    payload = {"replyToken": reply_token, "messages": [{"type": "text", "text": text[:4900]}]}
    try:
        resp = requests.post(
            "https://api.line.me/v2/bot/message/reply",
            headers=headers,
            json=payload,
            timeout=10,
        )
        if resp.status_code != 200:
            logger.error("LINE reply failed: %s %s", resp.status_code, resp.text)
    except requests.RequestException:
        logger.exception("LINE reply request failed")


def parse_ip_message(text: str):
    """將訊息拆成 token，逐一檢查是否長得像 IP。
    回傳 (tokens, status)，status 為 "empty" / "mixed" / "ok"。
    只要有任何一個 token 不是 IP 格式，整則視為 "mixed"，不擷取部分 IP 處理，
    避免中文訊息裡意外夾雜的數字（版本號、日期、電話等）被誤判成 IP。
    """
    tokens = [t for t in TOKEN_SPLIT_RE.split(text.strip()) if t]
    if not tokens:
        return [], "empty"
    if any(not IP_LIKE_RE.match(t) for t in tokens):
        return tokens, "mixed"
    return tokens, "ok"


def process_ip_submission(ip_candidates):
    added, skipped_whitelist, skipped_invalid, skipped_duplicate = [], [], [], []

    current_ips = set()
    existing_whitelist_skipped = 0
    if LIVE_IP_TXT.exists():
        for line in LIVE_IP_TXT.read_text(encoding="utf-8").splitlines():
            ip_obj = get_ip_obj(line)
            if ip_obj:
                if is_whitelisted(ip_obj, WHITELIST_NETWORKS):
                    existing_whitelist_skipped += 1
                else:
                    current_ips.add(ip_obj)

    new_ips = set(current_ips)
    for raw in ip_candidates:
        ip_obj = get_ip_obj(raw)
        if not ip_obj:
            skipped_invalid.append(raw)
            continue
        if is_whitelisted(ip_obj, WHITELIST_NETWORKS):
            skipped_whitelist.append(raw)
            continue
        if ip_obj in current_ips:
            skipped_duplicate.append(raw)
            continue
        new_ips.add(ip_obj)
        added.append(str(ip_obj))

    changed = bool(added) or existing_whitelist_skipped > 0
    final_total = len(new_ips) if changed else len(current_ips) + existing_whitelist_skipped

    if changed:
        sorted_ips = sorted(new_ips)
        STAGING_IP_TXT.parent.mkdir(parents=True, exist_ok=True)
        STAGING_IP_TXT.write_text("\n".join(str(ip) for ip in sorted_ips) + "\n", encoding="utf-8")

        result = subprocess.run(
            ["sudo", "-n", APPLY_SCRIPT],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "apply script failed")

    return {
        "rule_count": len(WHITELIST_NETWORKS),
        "kept_from_file": len(current_ips),
        "existing_whitelist_skipped": existing_whitelist_skipped,
        "added": added,
        "skipped_whitelist": skipped_whitelist,
        "skipped_invalid": skipped_invalid,
        "skipped_duplicate": skipped_duplicate,
        "final_total": final_total,
    }


def build_report(result):
    lines = [
        f"已載入 {result['rule_count']} 條白名單規則。",
        f"已從 ip.txt 讀取，保留 {result['kept_from_file']} 個 IP（略過 {result['existing_whitelist_skipped']} 個白名單 IP）。",
    ]

    skip_parts = [f"{len(result['skipped_whitelist'])} 個白名單 IP"]
    if result["skipped_duplicate"]:
        skip_parts.append(f"{len(result['skipped_duplicate'])} 個重複 IP")
    if result["skipped_invalid"]:
        skip_parts.append(f"{len(result['skipped_invalid'])} 個格式錯誤")
    lines.append(f"已從 line bot 新增 {len(result['added'])} 個不重複 IP（略過 {'、'.join(skip_parts)}）。")

    lines.append("-" * 30)
    lines.extend(result["added"] if result["added"] else ["(無新增)"])
    lines.append("-" * 30)

    lines.append("處理完成！")
    lines.append(f"最終 ip.txt 共有 {result['final_total']} 筆 IP。")
    lines.append("已按 IP 大小完成排序。")
    return "\n".join(lines)


@app.route("/webhook", methods=["POST"])
def webhook():
    signature = request.headers.get("X-Line-Signature", "")
    body = request.get_data()
    if not verify_signature(body, signature):
        abort(400)

    data = request.get_json(silent=True) or {}
    authorized_users = load_authorized_users()

    for event in data.get("events", []):
        if event.get("type") != "message":
            continue

        message = event.get("message", {})
        reply_token = event.get("replyToken")
        user_id = event.get("source", {}).get("userId", "")

        if message.get("type") != "text":
            reply_message(reply_token, "目前只支援文字訊息，請傳送要加入黑名單的 IP。")
            continue

        text = message.get("text", "").strip()

        if user_id not in authorized_users:
            logger.warning("Unauthorized attempt from userId=%s text=%r", user_id, text)
            reply_message(
                reply_token,
                f"您尚未被授權使用此功能。\n您的 userId：\n{user_id}\n請將此 ID 交給管理員加入授權名單。",
            )
            continue

        tokens, status = parse_ip_message(text)
        if status == "empty":
            reply_message(reply_token, "請傳送要加入黑名單的 IP（可多筆，一行一個）。\n例如：\n1.2.3.4\n5.6.7.8")
            continue
        if status == "mixed":
            reply_message(
                reply_token,
                "偵測到訊息夾雜非 IP 的文字，為避免誤判，整則不處理。\n請只傳送 IP（可多筆，一行一個，空白/逗號/換行分隔皆可）。",
            )
            continue

        try:
            result = process_ip_submission(tokens)
        except Exception as exc:
            logger.exception("Failed to process IP submission")
            reply_message(reply_token, f"處理失敗：{exc}")
            continue

        reply_message(reply_token, build_report(result))

    return "OK", 200


@app.route("/healthz", methods=["GET"])
def healthz():
    return "OK", 200


if __name__ == "__main__":
    from waitress import serve

    serve(app, host="127.0.0.1", port=8000)
