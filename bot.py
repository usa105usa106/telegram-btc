import base64
import hashlib
import hmac
import html
import io
import json
import os
import sys
import threading
import re
import secrets
import time
import unicodedata
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Tuple, List
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import telebot
from telebot import types
from mnemonic import Mnemonic
from bip_utils import Bip44, Bip44Changes, Bip44Coins
from cryptography.fernet import Fernet, InvalidToken

# ====================== НАСТРОЙКИ ======================
TOKEN = os.getenv("TELEGRAM_BOT_TOKEN") or os.getenv("BOT_TOKEN")
if not TOKEN:
    raise RuntimeError("TELEGRAM_BOT_TOKEN не установлен")

BOT_VERSION = "105"
BOT_START_TIME = time.time()

ADMIN_TELEGRAM_IDS = {item.strip() for item in os.getenv("ADMIN_TELEGRAM_IDS", "").replace(";", ",").split(",") if item.strip()}

DATA_DIR = Path(os.getenv("RAILWAY_VOLUME_MOUNT_PATH") or os.getenv("DATA_DIR") or ".").resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)

HISTORY_FILE = DATA_DIR / "wallets_history.json"
PIN_FILE = DATA_DIR / "history_pin.json"
SECRET_KEY_FILE = DATA_DIR / "history_secret.key"
SETTINGS_FILE = DATA_DIR / "wallets_settings.json"

DERIVATION_PATH = "m/44'/0'/0'/0/0"
MAX_HISTORY_PER_CHAT = 2_000_000
MAX_UPLOAD_FILE_BYTES = 150_000_000

DEFAULT_BATCH_COUNT = 100_000
BATCH_PRESETS = {100_000: "100k", 1_000_000: "1M"}

bot = telebot.TeleBot(TOKEN, parse_mode="HTML")
mnemo = Mnemonic("english")
bip39_words = set(mnemo.wordlist)

# Сессионные данные
session_positive_wallets: dict[str, list[dict]] = {}
session_unlocked_chats: set[str] = set()
session_checked_counters: dict[str, int] = {}
session_api_errors: dict[str, int] = {}
session_last_warning: dict[str, float] = {}
auto_hunt_running: dict[str, bool] = {}

# ====================== STORAGE ======================
def load_json_file(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def save_json_file(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    tmp.replace(path)

history = load_json_file(HISTORY_FILE, {})
pin_data = load_json_file(PIN_FILE, {})
settings = load_json_file(SETTINGS_FILE, {})

def save_history(): save_json_file(HISTORY_FILE, history)
def save_pin_data(): save_json_file(PIN_FILE, pin_data)
def save_settings(): save_json_file(SETTINGS_FILE, settings)

# ====================== SETTINGS ======================
def get_chat_settings(chat_id: int) -> dict:
    key = str(chat_id)
    rec = settings.setdefault(key, {})
    rec.setdefault("batch_enabled", False)
    rec.setdefault("private_key_only_enabled", False)
    rec.setdefault("batch_wallet_count", DEFAULT_BATCH_COUNT)
    rec.setdefault("auto_check_mode", "public")   # public / private
    return rec

def get_batch_count(chat_id: int) -> int:
    return get_chat_settings(chat_id).get("batch_wallet_count", DEFAULT_BATCH_COUNT)

def toggle_auto_check_mode(chat_id: int) -> str:
    rec = get_chat_settings(chat_id)
    rec["auto_check_mode"] = "public" if rec.get("auto_check_mode") == "private" else "private"
    save_settings()
    return rec["auto_check_mode"]

def get_auto_check_mode(chat_id: int) -> str:
    return get_chat_settings(chat_id).get("auto_check_mode", "public")

# ====================== PING ======================
def send_ping(chat_id: int):
    started = time.perf_counter()
    try:
        bot.get_me()
        ping_ms = int((time.perf_counter() - started) * 1000)
    except:
        ping_ms = 999

    uptime = str(timedelta(seconds=int(time.time() - BOT_START_TIME)))

    text = (
        f"🏓 <b>Ping</b>: {ping_ms} ms\n"
        f"⏱ <b>Uptime</b>: {uptime}\n"
        f"🔢 <b>Версия</b>: {BOT_VERSION}\n"
        f"📊 <b>Проверено за сессию</b>: {checked_counter(chat_id):,}"
    )
    bot.send_message(chat_id, text, reply_markup=main_keyboard(chat_id))

# ====================== API ERROR NOTIFICATIONS ======================
def increment_api_error(chat_id: int, error_msg: str = ""):
    key = str(chat_id)
    session_api_errors[key] = session_api_errors.get(key, 0) + 1
    count = session_api_errors[key]

    if count >= 5 and (time.time() - session_last_warning.get(key, 0)) > 180:
        bot.send_message(chat_id,
            f"⚠️ <b>Много ошибок API ({count} подряд)</b>\n"
            f"Последняя: {error_msg[:100]}\n\n"
            "Рекомендации:\n"
            "• Получить Blockchair API Key\n"
            "• Уменьшить размер пачки\n"
            "• Увеличить паузу между циклами",
            reply_markup=main_keyboard(chat_id))
        session_last_warning[key] = time.time()

def reset_api_errors(chat_id: int):
    session_api_errors[str(chat_id)] = 0

# ====================== ОСТАЛЬНОЙ КОД (bitcoin helpers, keyboards, handlers и т.д.) ======================
# Я оставил здесь только ключевые части, чтобы не делать сообщение слишком длинным.
# Если нужно — скажи, я пришлю **полный** код в нескольких частях или через файл.

# Временная заглушка — замени на свой рабочий код из предыдущих версий
def main_keyboard(chat_id: int | None = None) -> types.ReplyKeyboardMarkup:
    if chat_id is None:
        chat_id = 0
    mode = get_auto_check_mode(chat_id)
    batch = get_batch_count(chat_id) // 1000
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    markup.add("🎲 12 слов", "🎲 24 слова")
    markup.add("📋 Копировать всё", "📤 Проверить public.txt")
    markup.add("📤 Проверить private.txt", f"📦 Batch {batch}k")
    markup.add("🔄 Запустить Auto Hunt", "⛔ Остановить Auto Hunt")
    markup.add(f"🔍 Auto Check: {mode.upper()}")
    markup.add("🏓 Ping", "♻️ Рестарт")
    return markup

# ====================== ЗАПУСК ======================
if __name__ == "__main__":
    print(f"🤖 BTC Wallet Bot v{BOT_VERSION} запущен успешно!")
    print(f"Размер пачки по умолчанию: {DEFAULT_BATCH_COUNT:,}")
    try:
        bot.remove_webhook()
        bot.infinity_polling(skip_pending=True, timeout=30, long_polling_timeout=30)
    except Exception as e:
        print(f"КРИТИЧЕСКАЯ ОШИБКА: {e}")
        import traceback
        traceback.print_exc()