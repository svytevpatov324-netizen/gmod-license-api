# main.py
import os
import time
import json
import base64
import hashlib
import hmac
from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

# ENV (на Render задавать в Settings → Environment)
DISCORD_WEBHOOK = os.getenv("DISCORD_WEBHOOK", "").strip()
HMAC_SECRET = os.getenv("HMAC_SECRET", "").strip()  # должен совпадать с SWRP_VERIFY.Config.Secret
LOG_TO_FILE = os.getenv("LOG_TO_FILE", "0") == "1"

# В памяти (по-умолчанию пусто) — сюда можно добавлять "completions" если бот будет их отдавать
PENDING_COMPLETIONS = []  # список dict: {"steamid": "...", "discord_id": "...", "verified_by": "..."}

def log(msg):
    s = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(s)
    if LOG_TO_FILE:
        with open("keys.log", "a", encoding="utf-8") as f:
            f.write(s + "\n")

def send_to_discord(content: str):
    if not DISCORD_WEBHOOK:
        raise RuntimeError("DISCORD_WEBHOOK not set")
    try:
        r = requests.post(DISCORD_WEBHOOK, json={"content": content}, timeout=10)
        r.raise_for_status()
        return True
    except Exception as e:
        log(f"Failed to send to Discord: {e}")
        raise

def verify_signature_lua_style(secret: str, raw: bytes, signature_header: str) -> bool:
    """
    Аддон в Lua формирует подпись так:
      signature = Base64Encode( SHA256(payload .. Secret) )
    Здесь проверяем именно этот формат.
    """
    if not secret:
        return True
    if not signature_header:
        return False
    try:
        m = hashlib.sha256()
        m.update(raw + secret.encode())
        expected_b64 = base64.b64encode(m.digest()).decode()
        return hmac.compare_digest(expected_b64, signature_header)
    except Exception:
        return False

def verify_signature_hmac(secret: str, raw: bytes, signature_header: str) -> bool:
    """
    Альтернативная схема — HMAC-SHA256(hex). (Оставлена на случай смены клиента)
    """
    if not secret:
        return True
    if not signature_header:
        return False
    try:
        expected = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature_header)
    except Exception:
        return False

def verify_request(raw: bytes, signature_header: str) -> bool:
    """
    Пробуем обе схемы: Lua-style и HMAC hex.
    """
    if not HMAC_SECRET:
        # если секрет не задан — принимаем любые запросы (небезопасно, но полезно для теста)
        return True
    # Lua style
    if verify_signature_lua_style(HMAC_SECRET, raw, signature_header):
        return True
    # HMAC hex style
    if verify_signature_hmac(HMAC_SECRET, raw, signature_header):
        return True
    return False

@app.route("/api/key/register", methods=["POST"])
def api_register():
    raw = request.get_data() or b""
    sig = request.headers.get("X-Signature", "") or ""
    if not verify_request(raw, sig):
        log("Rejected /api/key/register due to invalid signature")
        return jsonify({"error": "Invalid signature"}), 403

    data = request.get_json(silent=True) or {}
    steamid = data.get("steamid")
    key = data.get("key")
    nickname = data.get("nickname", "Unknown")
    server = data.get("server", "")
    action = data.get("action", "")

    if not steamid or not key:
        return jsonify({"error": "Missing steamid or key"}), 400

    # Формируем сообщение в Discord
    prefix = f"[{server}] " if server else ""
    content = f"{prefix}[GMod Key] {nickname} | {steamid} | {key} | action={action}"
    try:
        send_to_discord(content)
        log(f"Registered key from {steamid} ({nickname}): {key}")
    except Exception as e:
        return jsonify({"error": "Failed to forward to Discord", "detail": str(e)}), 500

    return jsonify({"success": True}), 200

@app.route("/api/verify/reset", methods=["POST"])
def api_reset():
    # аддон вызывает при сбросе ключа
    raw = request.get_data() or b""
    sig = request.headers.get("X-Signature", "") or ""
    if not verify_request(raw, sig):
        # аддон отправляет X-Server и X-Signature; но если нет — проверяем просто X-Secret
        # всё же вернём 403
        log("Rejected /api/verify/reset due to invalid signature")
        return jsonify({"error": "Invalid signature"}), 403

    data = request.get_json(silent=True) or {}
    steamid = data.get("steamid")
    reset_by = data.get("reset_by", "unknown")
    timestamp = data.get("timestamp", int(time.time()))

    if not steamid:
        return jsonify({"error": "Missing steamid"}), 400

    content = f"[Reset] SteamID {steamid} reset by {reset_by} at {timestamp}"
    try:
        send_to_discord(content)
        log(f"Reset requested for {steamid} by {reset_by}")
    except Exception as e:
        return jsonify({"error": "Failed to forward reset", "detail": str(e)}), 500

    return jsonify({"success": True}), 200

@app.route("/api/verify/pending-completions", methods=["GET"])
def api_pending_completions():
    # аддон вызывает этот GET с заголовком X-Secret = Secret
    xsec = request.headers.get("X-Secret", "") or ""
    if HMAC_SECRET and xsec != HMAC_SECRET:
        return jsonify({"error": "Invalid secret header"}), 403

    # Возвращаем текущие pending completions (пустой список по умолчанию)
    # Формат: {"completions": [{"steamid":"...", "discord_id":"..."} , ...]}
    return jsonify({"completions": PENDING_COMPLETIONS}), 200

@app.route("/api/health", methods=["GET"])
def api_health():
    return jsonify({"status": "ok", "time": int(time.time())}), 200

if __name__ == "__main__":
    port = int(os.getenv("PORT", "10000"))
    log(f"Starting app on port {port}")
    app.run(host="0.0.0.0", port=port)

