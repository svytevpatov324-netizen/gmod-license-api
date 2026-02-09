# main.py
import os
import hmac
import hashlib
import time
from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

# Настройки через переменные окружения в Render
DISCORD_WEBHOOK = os.getenv("DISCORD_WEBHOOK")  # https://discord.com/api/webhooks/ID/TOKEN
HMAC_SECRET = os.getenv("HMAC_SECRET", "")      # опционально: общий секрет для подписи
LOG_TO_FILE = os.getenv("LOG_TO_FILE", "0") == "1"  # если нужно логировать запросы

def verify_signature(secret: str, data: bytes, signature: str) -> bool:
    if not secret:
        return True
    if not signature:
        return False
    expected = hmac.new(secret.encode(), data, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)

def send_to_discord(content: str):
    if not DISCORD_WEBHOOK:
        raise RuntimeError("DISCORD_WEBHOOK not set")
    resp = requests.post(DISCORD_WEBHOOK, json={"content": content}, timeout=10)
    resp.raise_for_status()
    return resp

@app.route("/api/key/register", methods=["POST"])
def register_key():
    # Проверяем подпись (опционально)
    raw = request.get_data()
    sig = request.headers.get("X-Signature", "")

    if not verify_signature(HMAC_SECRET, raw, sig):
        return jsonify({"error": "Invalid signature"}), 403

    data = request.get_json(silent=True) or {}
    steamid = data.get("steamid")
    key = data.get("key")
    nickname = data.get("nickname", "Unknown")
    server = data.get("server", "")  # можно передавать IP/название сервера

    if not steamid or not key:
        return jsonify({"error": "Missing steamid or key"}), 400

    # Формат сообщения, который попадёт в Discord-канал
    content = f"[GMod Key] {nickname} | {steamid} | {key}"
    if server:
        content = f"[{server}] " + content

    try:
        send_to_discord(content)
    except Exception as e:
        return jsonify({"error": "Failed to send to Discord", "detail": str(e)}), 500

    # Опционально: логировать в файл
    if LOG_TO_FILE:
        with open("keys.log", "a", encoding="utf-8") as f:
            f.write(f"{time.time()} {content}\n")

    return jsonify({"success": True}), 200

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "time": int(time.time())})

if __name__ == "__main__":
    port = int(os.getenv("PORT", "10000"))
    app.run(host="0.0.0.0", port=port)
