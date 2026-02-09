# bot.py
import asyncio
import os
from dotenv import load_dotenv

import discord
from discord.ext import commands

from flask import Flask, request, jsonify
from threading import Thread
import hmac
import hashlib
import time

load_dotenv()
TOKEN = os.getenv("BOT_TOKEN")
GUILD_ID = int(os.getenv("GUILD_ID", "0") or 0)
DEV_ROLE_ID = int(os.getenv("DEV_ROLE_ID", "0") or 0)

ERA_API_HOST = os.getenv("ERA_API_HOST", "0.0.0.0")
ERA_API_PORT = int(os.getenv("ERA_API_PORT", "3000"))
ERA_SECRET = os.getenv("ERA_SECRET", "change-me-in-production")

intents = discord.Intents.all()
bot = commands.Bot(command_prefix="!", intents=intents)

try:
    bot.remove_command("help")
except Exception:
    pass

DEV_USERS = {
    349469100101074949,
    816245666635972609
}

# ============================================
# ХРАНИЛИЩЕ КЛЮЧЕЙ (для доступа из когов)
# ============================================

bot.pending_keys = {}  # steamid64 -> {key, nickname, expires_at}

# ============================================
# HTTP API (Flask в отдельном потоке)
# ============================================

app = Flask(__name__)

def verify_signature(data, signature):
    if ERA_SECRET == "change-me-in-production":
        return True
    expected = hmac.new(ERA_SECRET.encode(), data, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)

@app.route('/api/key/register', methods=['POST'])
def register_key():
    """GMod отправляет сюда ключ"""
    try:
        signature = request.headers.get('X-Signature', '')
        if not verify_signature(request.get_data(), signature):
            return jsonify({"error": "Invalid signature"}), 403
        
        data = request.get_json()
        steamid = data.get('steamid')
        key = data.get('key')
        nickname = data.get('nickname', 'Unknown')
        
        if not steamid or not key:
            return jsonify({"error": "Missing data"}), 400
        
        # Сохраняем в бота (доступно во всех когах через bot.pending_keys)
        bot.pending_keys[steamid] = {
            'key': key,
            'nickname': nickname,
            'expires_at': time.time() + 1800,  # 30 минут
            'used': False
        }
        
        print(f"[🔑] Ключ от {nickname} ({steamid}): {key}")
        
        return jsonify({"success": True}), 200
        
    except Exception as e:
        print(f"[❌] Ошибка: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "keys_count": len(bot.pending_keys)}), 200

def run_http():
    app.run(host=ERA_API_HOST, port=ERA_API_PORT, debug=False, use_reloader=False)

# Запускаем HTTP до старта бота
http_thread = Thread(target=run_http, daemon=True)
http_thread.start()
print(f"[🌐] HTTP API: http://{ERA_API_HOST}:{ERA_API_PORT}")

# ============================================
# ЗАГРУЗКА КОГОВ (твой оригинальный код)
# ============================================

async def load_extensions():
    cogs = [
        "cogs.help",
        "cogs.moderation", 
        "cogs.settings",
        "cogs.verification",        # <-- Тут делаешь свою верификацию
        "cogs.verification_commands", # <-- И тут
        "cogs.massban",
        "cogs.recruitment",
        "cogs.tickets",
        "cogs.info",
        "cogs.dev_blog"
    ]
    for cog in cogs:
        try:
            await bot.load_extension(cog)
            print(f"[✅] Загружен: {cog}")
        except Exception as e:
            print(f"[❌] Ошибка {cog}: {e}")

@bot.event
async def on_ready():
    print(f"[✅] Бот запущен: {bot.user}")
    
    # Проверка подключения GMod серверов
    if bot.pending_keys:
        print(f"[📡] Активных ключей в памяти: {len(bot.pending_keys)}")
    
    # DEV роли
    if GUILD_ID:
        guild = bot.get_guild(GUILD_ID)
        if guild:
            dev_role = guild.get_role(DEV_ROLE_ID) if DEV_ROLE_ID else None
            if dev_role:
                for member_id in DEV_USERS:
                    member = guild.get_member(member_id)
                    if member and dev_role not in member.roles:
                        try:
                            await member.add_roles(dev_role)
                            print(f"[🔧] DEV роль: {member}")
                        except Exception as e:
                            print(f"[❌] DEV роль ошибка: {e}")

async def main():
    await load_extensions()
    
    # Восстановление UI (если есть)
    try:
        from ui.verification_button import VerificationView
        bot.add_view(VerificationView())
    except Exception:
        pass
    
    if not TOKEN:
        print("[❌] BOT_TOKEN не задан!")
        return
        
    await bot.start(TOKEN)

if __name__ == "__main__":
    print(f"[DEBUG] TOKEN: {TOKEN[:20]}...")
    asyncio.run(main())
