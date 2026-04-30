import base64
import hashlib
import hmac
import html
import io
import json
import os
import re
import secrets
import time
import unicodedata
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed


import requests
import telebot
from telebot import types
from mnemonic import Mnemonic
from bip_utils import Bip44, Bip44Changes, Bip44Coins
from cryptography.fernet import Fernet, InvalidToken


TOKEN = os.getenv("TELEGRAM_BOT_TOKEN") or os.getenv("BOT_TOKEN")
if not TOKEN:
    raise RuntimeError("TELEGRAM_BOT_TOKEN или BOT_TOKEN не установлен в Railway Variables")

# Railway volume: если подключишь Volume, укажи mount path /data.
# Бот сам возьмёт RAILWAY_VOLUME_MOUNT_PATH, а если его нет — будет писать рядом с bot.py.
DATA_DIR = Path(os.getenv("RAILWAY_VOLUME_MOUNT_PATH") or os.getenv("DATA_DIR") or ".").resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)
HISTORY_FILE = Path(os.getenv("HISTORY_FILE") or (DATA_DIR / "wallets_history.json"))
PIN_FILE = Path(os.getenv("PIN_FILE") or (DATA_DIR / "history_pin.json"))
SECRET_KEY_FILE = Path(os.getenv("SECRET_KEY_FILE") or (DATA_DIR / "history_secret.key"))
SETTINGS_FILE = Path(os.getenv("SETTINGS_FILE") or (DATA_DIR / "wallets_settings.json"))

DERIVATION_PATH = "m/44'/0'/0'/0/0"
MAX_HISTORY_PER_CHAT = 30000
BATCH_WALLET_COUNT = 10000
TELEGRAM_COPY_CHUNK_SIZE = 3600
MAX_UPLOAD_FILE_BYTES = 1_000_000
# Ускорение безопасной проверки работает только для загруженных/введённых public.txt/TXT/CSV.
# Максимальный быстрый режим: BlockCypher batch до 100 адресов за 1 HTTP-запрос.
BALANCE_SCAN_WORKERS = max(1, min(128, int(os.getenv("BALANCE_SCAN_WORKERS", "48"))))
BALANCE_BATCH_WORKERS = max(1, min(32, int(os.getenv("BALANCE_BATCH_WORKERS", "16"))))
BALANCE_BATCH_SIZE = max(1, min(100, int(os.getenv("BALANCE_BATCH_SIZE", "100"))))
BALANCE_REQUEST_TIMEOUT = max(1, min(30, int(os.getenv("BALANCE_REQUEST_TIMEOUT", "5"))))
BLOCKCYPHER_TOKEN = os.getenv("BLOCKCYPHER_TOKEN", "").strip()
PIN_LEN = 5
PIN_HASH_ITERATIONS = 240_000

bot = telebot.TeleBot(TOKEN, parse_mode="HTML")
mnemo = Mnemonic("english")
bip39_words = set(mnemo.wordlist)

# Хранится только в RAM и очищается после перезапуска бота.
session_positive_wallets: dict[str, list[dict[str, Any]]] = {}
# PIN вводится один раз за сессию бота. После перезапуска потребуется снова.
session_unlocked_chats: set[str] = set()
# Счётчик проверенных публичных адресов хранится только в RAM и очищается после перезапуска бота.
session_checked_counters: dict[str, int] = {}
# Состояние настройки ускоренной проверки public.txt через Telegram.
session_public_scan_setting_wait: dict[str, str] = {}


# ---------- storage ----------

def load_json_file(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return data
    except Exception:
        return default


def save_json_file(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    tmp.replace(path)


def load_history() -> dict[str, list[dict[str, Any]]]:
    data = load_json_file(HISTORY_FILE, {})
    return data if isinstance(data, dict) else {}


def load_pin_data() -> dict[str, dict[str, str]]:
    data = load_json_file(PIN_FILE, {})
    return data if isinstance(data, dict) else {}


def load_settings() -> dict[str, dict[str, Any]]:
    data = load_json_file(SETTINGS_FILE, {})
    return data if isinstance(data, dict) else {}


history: dict[str, list[dict[str, Any]]] = load_history()
pin_data: dict[str, dict[str, str]] = load_pin_data()
settings: dict[str, dict[str, Any]] = load_settings()


def save_history() -> None:
    save_json_file(HISTORY_FILE, history)


def save_pin_data() -> None:
    save_json_file(PIN_FILE, pin_data)


def save_settings() -> None:
    save_json_file(SETTINGS_FILE, settings)


def get_chat_settings(chat_id: int) -> dict[str, Any]:
    chat_key = str(chat_id)
    rec = settings.get(chat_key)
    if not isinstance(rec, dict):
        rec = {}
        settings[chat_key] = rec
    rec.setdefault("batch_enabled", False)
    rec.setdefault("private_key_only_enabled", False)
    # Эти параметры относятся только к ускоренной проверке загруженного public.txt/TXT/CSV.
    # Значения из Railway используются как дефолт, но дальше их можно менять прямо в Telegram.
    rec.setdefault("public_scan_batch_size", BALANCE_BATCH_SIZE)
    rec.setdefault("public_scan_batch_workers", BALANCE_BATCH_WORKERS)
    rec.setdefault("public_scan_fallback_workers", BALANCE_SCAN_WORKERS)
    rec.setdefault("public_scan_timeout", BALANCE_REQUEST_TIMEOUT)
    return rec


PUBLIC_SCAN_SETTING_LIMITS = {
    "public_scan_batch_size": (1, 100),
    "public_scan_batch_workers": (1, 32),
    "public_scan_fallback_workers": (1, 128),
    "public_scan_timeout": (1, 30),
}

PUBLIC_SCAN_SETTING_LABELS = {
    "public_scan_batch_size": "📦 Batch size",
    "public_scan_batch_workers": "🧵 Batch workers",
    "public_scan_fallback_workers": "🔁 Fallback workers",
    "public_scan_timeout": "⏱ Timeout",
}


def clamp_int(value: Any, min_value: int, max_value: int, default: int) -> int:
    try:
        number = int(str(value).strip())
    except Exception:
        number = default
    return max(min_value, min(max_value, number))


def get_public_scan_settings(chat_id: int) -> dict[str, int]:
    rec = get_chat_settings(chat_id)
    values = {
        "batch_size": clamp_int(rec.get("public_scan_batch_size"), 1, 100, BALANCE_BATCH_SIZE),
        "batch_workers": clamp_int(rec.get("public_scan_batch_workers"), 1, 32, BALANCE_BATCH_WORKERS),
        "fallback_workers": clamp_int(rec.get("public_scan_fallback_workers"), 1, 128, BALANCE_SCAN_WORKERS),
        "timeout": clamp_int(rec.get("public_scan_timeout"), 1, 30, BALANCE_REQUEST_TIMEOUT),
    }
    rec["public_scan_batch_size"] = values["batch_size"]
    rec["public_scan_batch_workers"] = values["batch_workers"]
    rec["public_scan_fallback_workers"] = values["fallback_workers"]
    rec["public_scan_timeout"] = values["timeout"]
    return values


def set_public_scan_setting(chat_id: int, key: str, value: int) -> int:
    if key not in PUBLIC_SCAN_SETTING_LIMITS:
        raise ValueError("unknown public scan setting")
    min_value, max_value = PUBLIC_SCAN_SETTING_LIMITS[key]
    current = get_chat_settings(chat_id).get(key)
    default = int(current if current is not None else min_value)
    new_value = clamp_int(value, min_value, max_value, default)
    get_chat_settings(chat_id)[key] = new_value
    save_settings()
    return new_value


def set_public_scan_preset(chat_id: int, preset: str) -> None:
    rec = get_chat_settings(chat_id)
    if preset == "max":
        rec["public_scan_batch_size"] = 100
        rec["public_scan_batch_workers"] = 32
        rec["public_scan_fallback_workers"] = 128
        rec["public_scan_timeout"] = 5
    elif preset == "safe":
        rec["public_scan_batch_size"] = 100
        rec["public_scan_batch_workers"] = 8
        rec["public_scan_fallback_workers"] = 24
        rec["public_scan_timeout"] = 8
    else:
        raise ValueError("unknown preset")
    save_settings()


def is_batch_enabled(chat_id: int) -> bool:
    return bool(get_chat_settings(chat_id).get("batch_enabled"))


def toggle_batch_enabled(chat_id: int) -> bool:
    rec = get_chat_settings(chat_id)
    rec["batch_enabled"] = not bool(rec.get("batch_enabled"))
    save_settings()
    return bool(rec["batch_enabled"])


def is_private_key_mode_enabled(chat_id: int) -> bool:
    return bool(get_chat_settings(chat_id).get("private_key_only_enabled"))


def toggle_private_key_mode_enabled(chat_id: int) -> bool:
    rec = get_chat_settings(chat_id)
    rec["private_key_only_enabled"] = not bool(rec.get("private_key_only_enabled"))
    save_settings()
    return bool(rec["private_key_only_enabled"])


def is_chat_unlocked(chat_id: int) -> bool:
    return str(chat_id) in session_unlocked_chats


def unlock_chat(chat_id: int) -> None:
    session_unlocked_chats.add(str(chat_id))


def get_master_fernet() -> Fernet:
    env_key = os.getenv("HISTORY_SECRET_KEY", "").strip()
    if env_key:
        return Fernet(env_key.encode("utf-8"))
    if SECRET_KEY_FILE.exists():
        key = SECRET_KEY_FILE.read_text(encoding="utf-8").strip()
        return Fernet(key.encode("utf-8"))
    key = Fernet.generate_key()
    SECRET_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    SECRET_KEY_FILE.write_text(key.decode("utf-8"), encoding="utf-8")
    return Fernet(key)


def encrypt_json(data: dict[str, Any]) -> str:
    raw = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return get_master_fernet().encrypt(raw).decode("utf-8")


def decrypt_json(token: str) -> dict[str, Any]:
    raw = get_master_fernet().decrypt(str(token).encode("utf-8"))
    data = json.loads(raw.decode("utf-8"))
    return data if isinstance(data, dict) else {}


def pin_is_valid_format(pin: str) -> bool:
    return bool(pin) and pin.isdigit() and len(pin) == PIN_LEN


def pin_hash(pin: str, salt_b64: str) -> str:
    salt = base64.b64decode(salt_b64.encode("ascii"))
    digest = hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"), salt, PIN_HASH_ITERATIONS)
    return base64.b64encode(digest).decode("ascii")


def set_chat_pin(chat_id: int, pin: str) -> None:
    salt_b64 = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
    pin_data[str(chat_id)] = {
        "salt": salt_b64,
        "hash": pin_hash(pin, salt_b64),
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
    }
    save_pin_data()


def chat_has_pin(chat_id: int) -> bool:
    rec = pin_data.get(str(chat_id))
    return isinstance(rec, dict) and bool(rec.get("salt") and rec.get("hash"))


def verify_chat_pin(chat_id: int, pin: str) -> bool:
    rec = pin_data.get(str(chat_id)) or {}
    salt = rec.get("salt")
    expected = rec.get("hash")
    if not salt or not expected or not pin_is_valid_format(pin):
        return False
    actual = pin_hash(pin, salt)
    return hmac.compare_digest(actual, expected)


# ---------- bitcoin helpers ----------

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58_encode(raw: bytes) -> str:
    num = int.from_bytes(raw, "big")
    encoded = ""
    while num > 0:
        num, rem = divmod(num, 58)
        encoded = BASE58_ALPHABET[rem] + encoded
    leading_zeros = len(raw) - len(raw.lstrip(b"\x00"))
    return "1" * leading_zeros + (encoded or "1")


def base58check_encode(payload: bytes) -> str:
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58_encode(payload + checksum)


def private_key_to_wif(private_key: bytes, compressed: bool = True) -> str:
    if len(private_key) != 32:
        raise ValueError("private key должен быть 32 bytes")
    payload = b"\x80" + private_key + (b"\x01" if compressed else b"")
    return base58check_encode(payload)


SECP256K1_ORDER = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)


def hash160(data: bytes) -> bytes:
    sha = hashlib.sha256(data).digest()
    ripe = hashlib.new("ripemd160")
    ripe.update(sha)
    return ripe.digest()


def private_key_bytes_to_p2pkh_address(private_key: bytes) -> str:
    # Стандартный legacy P2PKH-адрес для compressed public key.
    from cryptography.hazmat.primitives.asymmetric import ec

    private_int = int.from_bytes(private_key, "big")
    if not (1 <= private_int < SECP256K1_ORDER):
        raise ValueError("private key вне диапазона secp256k1")
    key = ec.derive_private_key(private_int, ec.SECP256K1())
    numbers = key.public_key().public_numbers()
    prefix = b"\x02" if numbers.y % 2 == 0 else b"\x03"
    compressed_pubkey = prefix + numbers.x.to_bytes(32, "big")
    return base58check_encode(b"\x00" + hash160(compressed_pubkey))


def generate_random_private_key_wallet() -> Tuple[str, str]:
    while True:
        private_key = secrets.token_bytes(32)
        private_int = int.from_bytes(private_key, "big")
        if 1 <= private_int < SECP256K1_ORDER:
            break
    address = private_key_bytes_to_p2pkh_address(private_key)
    wif = private_key_to_wif(private_key, compressed=True)
    return address, wif


def mnemonic_to_seed(mnemonic_phrase: str, passphrase: str = "") -> bytes:
    # BIP39 seed formula. Не валидирует checksum, поэтому фразы с повторениями тоже работают.
    password = unicodedata.normalize("NFKD", mnemonic_phrase).encode("utf-8")
    salt = unicodedata.normalize("NFKD", "mnemonic" + passphrase).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", password, salt, 2048, dklen=64)


def derive_bitcoin_wallet_at_index(mnemonic_phrase: str, index: int = 0) -> Tuple[str, str, str]:
    if index < 0:
        raise ValueError("index должен быть >= 0")
    seed = mnemonic_to_seed(mnemonic_phrase)
    ctx = (
        Bip44.FromSeed(seed, Bip44Coins.BITCOIN)
        .Purpose()
        .Coin()
        .Account(0)
        .Change(Bip44Changes.CHAIN_EXT)
        .AddressIndex(index)
    )
    address = ctx.PublicKey().ToAddress()
    private_key = ctx.PrivateKey().Raw().ToBytes()
    wif = private_key_to_wif(private_key, compressed=True)
    path = f"m/44'/0'/0'/0/{index}"
    return address, wif, path


def derive_bitcoin_wallet(mnemonic_phrase: str) -> Tuple[str, str]:
    address, wif, _path = derive_bitcoin_wallet_at_index(mnemonic_phrase, 0)
    return address, wif


def same_word_mnemonic(word_count: int) -> str:
    word = secrets.choice(mnemo.wordlist)
    return " ".join([word] * word_count)


# ---------- in-memory positive balances ----------

def parse_balance_btc(balance: str) -> Decimal:
    """Возвращает BTC из строки вида '0.00000001 BTC'. Ошибки API считаются нулём."""
    try:
        text = str(balance).strip().split()[0].replace(",", ".")
        return Decimal(text)
    except (IndexError, InvalidOperation, ValueError):
        return Decimal("0")


def remember_positive_wallet(chat_id: int, record: dict[str, Any]) -> None:
    balance = parse_balance_btc(str(record.get("balance") or "0"))
    if balance <= 0:
        return
    chat_key = str(chat_id)
    session_positive_wallets.setdefault(chat_key, [])
    address = str(record.get("address") or "")
    if not address:
        return
    # Не дублируем один и тот же адрес в RAM-списке.
    for item in session_positive_wallets[chat_key]:
        if item.get("address") == address:
            item.update(record)
            return
    safe_record = {
        "date": record.get("date") or datetime.now().strftime("%Y-%m-%d %H:%M"),
        "type": record.get("type") or "Unknown",
        "address": address,
        "balance": str(record.get("balance") or "0 BTC"),
        "derivation_path": record.get("derivation_path") or DERIVATION_PATH,
        "index": record.get("index"),
    }
    session_positive_wallets[chat_key].append(safe_record)


def positive_wallet_count(chat_id: int) -> int:
    return len(session_positive_wallets.get(str(chat_id)) or [])


def positive_balance_button_text(chat_id: int) -> str:
    return f"💰 Положительный баланс ({positive_wallet_count(chat_id)})"


def checked_counter(chat_id: int) -> int:
    return int(session_checked_counters.get(str(chat_id), 0) or 0)


def increment_checked_counter(chat_id: int, amount: int = 1) -> int:
    chat_key = str(chat_id)
    session_checked_counters[chat_key] = checked_counter(chat_id) + max(0, int(amount))
    return session_checked_counters[chat_key]


def checked_counter_button_text(chat_id: int) -> str:
    return f"📊 Проверено ({checked_counter(chat_id)})"


def show_checked_counter(chat_id: int) -> None:
    bot.send_message(
        chat_id,
        f"📊 <b>Проверено публичных адресов в текущей сессии:</b> {checked_counter(chat_id)}\n"
        "Счётчик хранится только в памяти и сбрасывается после перезапуска бота.",
        reply_markup=main_keyboard(chat_id),
    )


def show_session_positive_wallets(chat_id: int) -> None:
    items = session_positive_wallets.get(str(chat_id)) or []
    if not items:
        bot.send_message(
            chat_id,
            "💰 В текущей сессии нет адресов с положительным балансом. Список хранится только до перезапуска бота.",
            reply_markup=main_keyboard(chat_id),
        )
        return

    total = sum((parse_balance_btc(str(item.get("balance") or "0")) for item in items), Decimal("0"))
    lines = [
        "💰 <b>Положительный баланс в текущей сессии</b>",
        f"Найдено: <b>{len(items)}</b>",
        f"Итого: <b>{total:.8f} BTC</b>",
        "",
    ]
    for index, item in enumerate(items[-20:], start=1):
        lines.append(f"<b>#{index}</b> {esc(item.get('date', '?'))} | {esc(item.get('type', '?'))}")
        lines.append(f"🏠 {code(item.get('address', '?'))}")
        lines.append(f"💰 <b>{esc(item.get('balance', '?'))}</b>")
        if item.get("derivation_path"):
            lines.append(f"📍 {code(item.get('derivation_path'))}")
        lines.append("")
    lines.append("ℹ️ Этот список не сохраняется на диск и очищается после перезапуска бота.")
    bot.send_message(chat_id, "\n".join(lines), reply_markup=main_keyboard(chat_id))

# ---------- bot ui ----------

def main_keyboard(chat_id: int | None = None) -> types.ReplyKeyboardMarkup:
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    markup.add("🎲 12 слов", "🎲 24 слова")
    markup.add("🎯 Рандом12 одинаковые", "🎯 Рандом24 одинаковые")
    markup.add("📝 Ввести mnemonic", "📜 История")
    markup.add("🔐 Установить PIN", "🔄 Баланс последнего")
    markup.add("📋 Копировать всё", "📤 Проверить public.txt")
    markup.add("⚡ Настройки public.txt")
    if chat_id is not None and is_private_key_mode_enabled(chat_id):
        markup.add("🔑 Приват ключ: ВКЛ")
    else:
        markup.add("🔑 Приват ключ: ВЫКЛ")
    if chat_id is not None:
        markup.add(positive_balance_button_text(chat_id), checked_counter_button_text(chat_id))
    else:
        markup.add("💰 Положительный баланс (0)", "📊 Проверено (0)")
    if chat_id is not None and is_batch_enabled(chat_id):
        markup.add("⚙️ Пакет: ВКЛ")
    else:
        markup.add("⚙️ Пакет: ВЫКЛ")
    return markup


def public_scan_settings_keyboard() -> types.ReplyKeyboardMarkup:
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    markup.add("⚡ Public MAX", "🛡️ Public SAFE")
    markup.add("📦 Batch size", "🧵 Batch workers")
    markup.add("🔁 Fallback workers", "⏱ Timeout")
    markup.add("↩️ Назад")
    return markup


def public_scan_settings_text(chat_id: int) -> str:
    cfg = get_public_scan_settings(chat_id)
    return (
        "⚡ <b>Настройки ускоренной проверки public.txt</b>\n\n"
        "Эти параметры используются только для загруженного public.txt/TXT/CSV с публичными BTC-адресами или HEX public-key.\n\n"
        f"📦 Batch size: <b>{cfg['batch_size']}</b> адресов за 1 запрос. Диапазон: 1–100.\n"
        f"🧵 Batch workers: <b>{cfg['batch_workers']}</b> параллельных batch-запросов. Диапазон: 1–32.\n"
        f"🔁 Fallback workers: <b>{cfg['fallback_workers']}</b> потоков для одиночной проверки при сбое batch API. Диапазон: 1–128.\n"
        f"⏱ Timeout: <b>{cfg['timeout']}</b> сек. Диапазон: 1–30.\n\n"
        "Для максимальной скорости нажми <b>⚡ Public MAX</b>. Если начнутся ошибки API/лимиты — нажми <b>🛡️ Public SAFE</b>."
    )


def show_public_scan_settings(chat_id: int) -> None:
    bot.send_message(chat_id, public_scan_settings_text(chat_id), reply_markup=public_scan_settings_keyboard())


def ask_public_scan_setting(chat_id: int, key: str) -> None:
    min_value, max_value = PUBLIC_SCAN_SETTING_LIMITS[key]
    label = PUBLIC_SCAN_SETTING_LABELS[key]
    session_public_scan_setting_wait[str(chat_id)] = key
    bot.send_message(
        chat_id,
        f"{label}\nВведи число от <b>{min_value}</b> до <b>{max_value}</b>.",
        reply_markup=public_scan_settings_keyboard(),
    )


def handle_public_scan_setting_value(message) -> bool:
    chat_key = str(message.chat.id)
    key = session_public_scan_setting_wait.get(chat_key)
    if not key:
        return False

    text = (message.text or "").strip()
    if text in {"↩️ Назад", "назад", "back"}:
        session_public_scan_setting_wait.pop(chat_key, None)
        bot.send_message(message.chat.id, "Главное меню.", reply_markup=main_keyboard(message.chat.id))
        return True

    if not re.fullmatch(r"\d{1,3}", text):
        min_value, max_value = PUBLIC_SCAN_SETTING_LIMITS[key]
        bot.send_message(
            message.chat.id,
            f"❌ Нужно число от <b>{min_value}</b> до <b>{max_value}</b>.",
            reply_markup=public_scan_settings_keyboard(),
        )
        return True

    min_value, max_value = PUBLIC_SCAN_SETTING_LIMITS[key]
    value = int(text)
    if value < min_value or value > max_value:
        bot.send_message(
            message.chat.id,
            f"❌ Значение вне диапазона. Нужно от <b>{min_value}</b> до <b>{max_value}</b>.",
            reply_markup=public_scan_settings_keyboard(),
        )
        return True

    new_value = set_public_scan_setting(message.chat.id, key, value)
    session_public_scan_setting_wait.pop(chat_key, None)
    bot.send_message(
        message.chat.id,
        f"✅ {PUBLIC_SCAN_SETTING_LABELS[key]} установлено: <b>{new_value}</b>.",
        reply_markup=public_scan_settings_keyboard(),
    )
    show_public_scan_settings(message.chat.id)
    return True


def esc(value: Any) -> str:
    return html.escape(str(value), quote=False)


def code(value: Any) -> str:
    return f"<code>{html.escape(str(value), quote=False)}</code>"


def _balance_from_esplora_payload(data: dict[str, Any]) -> int:
    chain = data.get("chain_stats") or {}
    mempool = data.get("mempool_stats") or {}
    confirmed = int(chain.get("funded_txo_sum") or 0) - int(chain.get("spent_txo_sum") or 0)
    unconfirmed = int(mempool.get("funded_txo_sum") or 0) - int(mempool.get("spent_txo_sum") or 0)
    return max(0, confirmed + unconfirmed)


def get_balance(address: str) -> str:
    headers = {
        "User-Agent": "BTC-Wallet-Telegram-Bot/3.0",
        "Accept": "application/json",
    }
    providers = [
        ("Blockstream", f"https://blockstream.info/api/address/{address}", _balance_from_esplora_payload),
        ("mempool.space", f"https://mempool.space/api/address/{address}", _balance_from_esplora_payload),
        ("BlockCypher", f"https://api.blockcypher.com/v1/btc/main/addrs/{address}/balance", None),
    ]
    errors: list[str] = []
    for name, url, parser in providers:
        try:
            r = requests.get(url, timeout=BALANCE_REQUEST_TIMEOUT, headers=headers)
            if r.status_code == 200:
                data = r.json()
                if name == "BlockCypher":
                    sat = int(data.get("balance") or 0) + int(data.get("unconfirmed_balance") or 0)
                else:
                    sat = parser(data) if parser else 0
                return f"{sat / 100000000:.8f} BTC"
            if r.status_code in {429, 430, 503}:
                errors.append(f"{name}: лимит/временно недоступно HTTP {r.status_code}")
                time.sleep(0.7)
            else:
                errors.append(f"{name}: HTTP {r.status_code}")
        except Exception as exc:
            errors.append(f"{name}: {type(exc).__name__}")
    return "не удалось получить баланс: " + "; ".join(errors[:3])


def refresh_last_balance(chat_id: int) -> None:
    chat_key = str(chat_id)
    items = history.get(chat_key) or []
    if not items:
        bot.send_message(chat_id, "История пуста — сначала создай кошелёк.", reply_markup=main_keyboard(chat_id))
        return
    last = items[-1]
    address = str(last.get("address") or "")
    if not address:
        bot.send_message(chat_id, "В последней записи нет адреса.", reply_markup=main_keyboard(chat_id))
        return
    balance = get_balance(address)
    last["balance"] = balance
    last["balance_checked_at"] = datetime.now().strftime("%Y-%m-%d %H:%M")
    remember_positive_wallet(chat_id, last)
    save_history()
    bot.send_message(
        chat_id,
        "🔄 <b>Баланс обновлён</b>\n\n"
        f"🏠 Адрес:\n{code(address)}\n\n"
        f"💰 Баланс: <b>{esc(balance)}</b>",
        reply_markup=main_keyboard(chat_id),
    )


def normalize_mnemonic(text: str) -> str:
    words = [w.strip().lower() for w in text.replace("\n", " ").split() if w.strip()]
    return " ".join(words)


def validate_mnemonic_words(mnemonic_phrase: str) -> Tuple[bool, str, bool]:
    words = mnemonic_phrase.split()
    if len(words) not in (12, 24):
        return False, "❌ Должно быть 12 или 24 слова.", False

    invalid = [w for w in words if w not in bip39_words]
    if invalid:
        shown = ", ".join(invalid[:5])
        more = "..." if len(invalid) > 5 else ""
        return False, f"❌ Этих слов нет в официальном BIP39-списке: {code(shown + more)}", False

    checksum_ok = mnemo.check(mnemonic_phrase)
    return True, "", checksum_ok


def build_wallet_record(chat_id: int, mnemonic_phrase: str, source_type: str, balance: str = "не проверялся") -> tuple[dict[str, Any], bool, str, str, bool]:
    checksum_ok = mnemo.check(mnemonic_phrase)
    address, wif = derive_bitcoin_wallet(mnemonic_phrase)
    record: dict[str, Any] = {
        "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "type": source_type,
        "address": address,
        "balance": balance,
        "checksum_ok": bool(checksum_ok),
    }
    secrets_saved = False
    if chat_has_pin(chat_id):
        record["secret"] = encrypt_json({
            "mnemonic": mnemonic_phrase,
            "wif": wif,
            "derivation_path": DERIVATION_PATH,
        })
        secrets_saved = True
    return record, secrets_saved, address, wif, bool(checksum_ok)


def add_history_records(chat_id: int, records: list[dict[str, Any]]) -> None:
    chat_key = str(chat_id)
    history.setdefault(chat_key, [])
    history[chat_key].extend(records)
    history[chat_key] = history[chat_key][-MAX_HISTORY_PER_CHAT:]
    save_history()


def generate_mnemonic_for_source(source_type: str) -> str:
    if source_type == "Random 12":
        return mnemo.generate(strength=128)
    if source_type == "Random 24":
        return mnemo.generate(strength=256)
    if source_type == "SameWord 12":
        return same_word_mnemonic(12)
    if source_type == "SameWord 24":
        return same_word_mnemonic(24)
    raise ValueError(f"Неизвестный тип генерации: {source_type}")


def build_private_key_record(chat_id: int, source_type: str, balance: str = "не проверялся") -> tuple[dict[str, Any], str, str]:
    address, wif = generate_random_private_key_wallet()
    record: dict[str, Any] = {
        "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "type": source_type,
        "address": address,
        "balance": balance,
        "checksum_ok": True,
    }
    if chat_has_pin(chat_id):
        record["secret"] = encrypt_json({
            "wif": wif,
            "derivation_path": "random-private-key",
        })
    return record, address, wif


def process_random_private_key(chat_id: int) -> None:
    record, address, wif = build_private_key_record(chat_id, "Random private key", balance="не проверялся")
    add_history_records(chat_id, [record])
    save_line = (
        "🔐 WIF сохранён в зашифрованную историю."
        if chat_has_pin(chat_id)
        else "⚠️ PIN не установлен — в историю сохранены только адрес и баланс. Нажми 🔐 Установить PIN."
    )
    if is_private_key_mode_enabled(chat_id):
        text = (
            "✅ <b>Приватный ключ создан</b>\n\n"
            f"🔑 WIF:\n{code(wif)}\n\n"
            f"💰 Баланс: <b>{esc(record['balance'])}</b>\n\n"
            f"{esc(save_line)}\n"
            "⚠️ Приватный ключ даёт полный доступ к кошельку. Никому его не отправляй."
        )
    else:
        text = (
            "✅ <b>Приватный ключ создан</b>\n\n"
            f"🏠 Публичный адрес:\n{code(address)}\n\n"
            f"🔑 WIF:\n{code(wif)}\n\n"
            f"💰 Баланс: <b>{esc(record['balance'])}</b>\n\n"
            f"{esc(save_line)}"
        )
    bot.send_message(chat_id, text, reply_markup=main_keyboard(chat_id))


def process_batch_private_keys(chat_id: int) -> None:
    if not chat_has_pin(chat_id):
        bot.send_message(
            chat_id,
            "🔐 Для пакетного режима сначала установи PIN. Это нужно, чтобы WIF сохранялись в зашифрованную историю.",
            reply_markup=main_keyboard(chat_id),
        )
        return

    records: list[dict[str, Any]] = []
    for _ in range(BATCH_WALLET_COUNT):
        record, _address, _wif = build_private_key_record(chat_id, "Batch random private key", balance="не проверялся")
        records.append(record)

    add_history_records(chat_id, records)
    bot.send_message(
        chat_id,
        f"✅ <b>Пакет создан:</b> {BATCH_WALLET_COUNT} приватных ключей.\n\n"
        "Формат генерации: random private key → WIF.\n"
        "🔐 WIF сохранены в зашифрованную историю.\n"
        "📋 Нажми «Копировать всё», чтобы получить два TXT-файла: public.txt и private.txt.\n"
        "• public.txt — публичные адреса, по одному в строке.\n"
        "• private.txt — WIF-ключи, по одному в строке.\n"
        "ℹ️ Автопроверка не запускается для public.txt, который создан вместе с private.txt/WIF.",
        reply_markup=main_keyboard(chat_id),
    )


def process_batch_wallets(chat_id: int, source_type: str) -> None:
    if not chat_has_pin(chat_id):
        bot.send_message(
            chat_id,
            "🔐 Для пакетного режима сначала установи PIN. Это нужно, чтобы слова/WIF не потерялись и хранились за PIN-кодом.",
            reply_markup=main_keyboard(chat_id),
        )
        return

    records: list[dict[str, Any]] = []
    first_address = ""
    last_address = ""
    for i in range(BATCH_WALLET_COUNT):
        mnemonic_phrase = generate_mnemonic_for_source(source_type)
        record, _secrets_saved, address, _wif, _checksum_ok = build_wallet_record(
            chat_id, mnemonic_phrase, f"Batch {source_type}", balance="не проверялся"
        )
        records.append(record)
        if i == 0:
            first_address = address
        last_address = address

    add_history_records(chat_id, records)
    bot.send_message(
        chat_id,
        f"✅ <b>Пакет создан:</b> {BATCH_WALLET_COUNT} кошельков.\n\n"
        f"Тип: <b>{esc(source_type)}</b>\n"
        f"🔐 Слова/WIF сохранены в историю и открываются только по PIN.\n"
        "ℹ️ Проверка баланса запускается только по отдельно загруженному TXT/CSV с публичными адресами.\n"
        f"📋 Нажми «Копировать всё», чтобы получить два TXT-файла по последним {BATCH_WALLET_COUNT} кошелькам: public.txt и private.txt.\n"
        "📤 Проверка идёт только по публичным адресам из public.txt, без обработки private.txt/WIF/seed.\n\n"
        f"Первый адрес:\n{code(first_address)}\n\n"
        f"Последний адрес:\n{code(last_address)}",
        reply_markup=main_keyboard(chat_id),
    )


def build_wallet_export_files(chat_id: int, pin: str | None = None, limit: int = BATCH_WALLET_COUNT) -> tuple[str | None, str | None, str]:
    """Готовит два TXT-файла: public.txt и private.txt. Номера строк совпадают."""
    if not chat_has_pin(chat_id):
        return None, None, "🔐 Сначала установи PIN. Без PIN приватные ключи WIF не сохраняются и private.txt создать нельзя."
    if not is_chat_unlocked(chat_id):
        if pin is None or not verify_chat_pin(chat_id, pin):
            return None, None, "❌ Неверный PIN."
        unlock_chat(chat_id)

    items = (history.get(str(chat_id)) or [])[-limit:]
    if not items:
        return None, None, "История пуста — сначала создай пакет кошельков."

    public_lines: list[str] = []
    private_lines: list[str] = []
    for item in items:
        address = str(item.get("address") or "").strip()
        token = item.get("secret")
        if not address or not token:
            continue
        try:
            secret_data = decrypt_json(str(token))
            wif = str(secret_data.get("wif") or "").strip()
        except (InvalidToken, Exception):
            continue
        if not wif:
            continue
        # Важно: добавляем обе строки одновременно, чтобы номера строк в public/private совпадали.
        public_lines.append(address)
        private_lines.append(wif)

    if not public_lines or not private_lines:
        return None, None, "В последних записях нет пары address + WIF. Установи PIN до генерации новых ключей и создай пакет заново."
    return "\n".join(public_lines) + "\n", "\n".join(private_lines) + "\n", ""


def send_export_all(chat_id: int) -> None:
    public_text, private_text, error_text = build_wallet_export_files(chat_id, None)
    if error_text:
        bot.send_message(chat_id, error_text, reply_markup=main_keyboard(chat_id))
        return

    public_addresses = parse_addresses_from_text(public_text)
    export_count = len(public_addresses)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')

    public_file = io.BytesIO(public_text.encode("utf-8"))
    public_file.name = f"public_{export_count}_{ts}.txt"
    private_file = io.BytesIO(private_text.encode("utf-8"))
    private_file.name = f"private_{export_count}_{ts}.txt"

    bot.send_document(
        chat_id,
        public_file,
        caption=(
            f"📄 public.txt готов: {export_count} публичных адресов.\n"
            "Формат: один публичный BTC-адрес в строке.\n"
            "ℹ️ Проверка баланса не запускается автоматически для файла, созданного вместе с private.txt/WIF."
        ),
    )
    bot.send_document(
        chat_id,
        private_file,
        caption=(
            f"🔐 private.txt готов: {export_count} приватных ключей WIF.\n"
            "Формат: один WIF в строке.\n"
            "Номера строк соответствуют public.txt.\n"
            "⚠️ WIF даёт полный доступ к средствам. Храни private.txt офлайн и никому не отправляй."
        ),
    )

    bot.send_message(
        chat_id,
        "✅ Файлы созданы. Автопроверка баланса не запускается для public.txt, который был создан вместе с private.txt/WIF.\n"
        "Для безопасной проверки загрузи отдельный TXT/CSV только с публичными адресами через «📤 Проверить public.txt».",
        reply_markup=main_keyboard(chat_id),
    )

def request_export_all_pin(message) -> None:
    if not chat_has_pin(message.chat.id):
        return ask_set_pin(message)
    if is_chat_unlocked(message.chat.id):
        return send_export_all(message.chat.id)
    sent = bot.send_message(
        message.chat.id,
        f"🔐 Введи PIN-код из {PIN_LEN} цифр один раз за эту сессию, чтобы получить public.txt и private.txt:",
        reply_markup=main_keyboard(message.chat.id),
    )
    bot.register_next_step_handler(sent, export_all_after_pin)


def split_text_for_telegram(text: str, max_chars: int = TELEGRAM_COPY_CHUNK_SIZE) -> list[str]:
    """Делит длинный текст на сообщения Telegram, стараясь не разрывать строки."""
    chunks: list[str] = []
    current = ""
    for line in text.splitlines(keepends=True):
        if len(line) > max_chars:
            if current:
                chunks.append(current.rstrip("\n"))
                current = ""
            for start in range(0, len(line), max_chars):
                chunks.append(line[start:start + max_chars].rstrip("\n"))
            continue
        if current and len(current) + len(line) > max_chars:
            chunks.append(current.rstrip("\n"))
            current = line
        else:
            current += line
    if current:
        chunks.append(current.rstrip("\n"))
    return chunks


def export_all_after_pin(message) -> None:
    pin = (message.text or "").strip()
    if not verify_chat_pin(message.chat.id, pin):
        bot.send_message(message.chat.id, "❌ Неверный PIN.", reply_markup=main_keyboard(message.chat.id))
        return
    unlock_chat(message.chat.id)
    send_export_all(message.chat.id)


# ---------- PIN handlers ----------

@bot.message_handler(commands=["set_pin"])
def set_pin_cmd(message):
    parts = (message.text or "").strip().split(maxsplit=1)
    if len(parts) != 2:
        bot.send_message(
            message.chat.id,
            "🔐 Отправь PIN командой:\n<code>/set_pin 12345</code>\n\nPIN должен быть ровно 5 цифр.",
            reply_markup=main_keyboard(message.chat.id),
        )
        return
    pin = parts[1].strip()
    if not pin_is_valid_format(pin):
        bot.send_message(message.chat.id, "❌ PIN должен быть ровно 5 цифр.", reply_markup=main_keyboard(message.chat.id))
        return
    set_chat_pin(message.chat.id, pin)
    unlock_chat(message.chat.id)
    bot.send_message(
        message.chat.id,
        "✅ PIN установлен и разблокирован для текущей сессии. Теперь приватные ключи новых кошельков будут сохраняться в зашифрованную историю.\n\n"
        "После перезапуска бота PIN потребуется ввести снова.\n"
        "⚠️ 5 цифр — слабая защита. Не храни там кошельки с деньгами.",
        reply_markup=main_keyboard(message.chat.id),
    )


def ask_set_pin(message) -> None:
    bot.send_message(
        message.chat.id,
        "🔐 Для истории с ключами задай PIN из 5 цифр:\n<code>/set_pin 12345</code>\n\n"
        "После установки PIN бот будет сохранять ключи в историю, а экспорт выдаст два TXT-файла: public.txt и private.txt.",
        reply_markup=main_keyboard(message.chat.id),
    )


def request_history_pin(message) -> None:
    if not chat_has_pin(message.chat.id):
        return ask_set_pin(message)
    if is_chat_unlocked(message.chat.id):
        return show_history(message.chat.id, include_secrets=True)
    sent = bot.send_message(message.chat.id, "🔐 Введи PIN-код из 5 цифр один раз за эту сессию для просмотра истории:")
    bot.register_next_step_handler(sent, show_history_after_pin)


def show_history_after_pin(message) -> None:
    pin = (message.text or "").strip()
    if not verify_chat_pin(message.chat.id, pin):
        bot.send_message(message.chat.id, "❌ Неверный PIN.", reply_markup=main_keyboard(message.chat.id))
        return
    unlock_chat(message.chat.id)
    show_history(message.chat.id, include_secrets=True)


# ---------- telegram handlers ----------

@bot.message_handler(commands=["start"])
def start(message):
    bot.send_message(
        message.chat.id,
        "👋 <b>Bitcoin Wallet Bot</b>\n\n"
        "✅ Генерация обычных 12/24 слов.\n"
        "✅ Рандом12/Рандом24 из одного случайного BIP39-слова.\n"
        "✅ История с ключами открывается только по PIN из 5 цифр.\n"
        f"✅ Пакетный режим создаёт сразу {BATCH_WALLET_COUNT} новых кошельков.\n"
        f"✅ /scan10000 проверяет первые {BATCH_WALLET_COUNT} адресов из твоей seed-фразы для восстановления (/scan1000 и /scan100 тоже работают).\n"
        "✅ PIN вводится один раз за сессию: история и экспорт больше не спрашивают его после разблокировки.\n"
        "✅ Кнопка 🔑 Приват ключ ВКЛ/ВЫКЛ включает режим генерации/экспорта только WIF.\n"
        f"✅ Кнопка 📋 Копировать всё отправляет два TXT-файла по последним {BATCH_WALLET_COUNT} записям: public.txt и private.txt.\n"
        "✅ Отдельно загруженный public.txt проверяется на баланс в ускоренном режиме без обработки private.txt/WIF/seed.\n"
        "✅ Загруженный TXT со списком публичных адресов тоже проверяется на положительный баланс без обработки приватных ключей.\n\n"
        "⚠️ Фразы из одинаковых слов небезопасны и подходят только для тестов/экспериментов.",
        reply_markup=main_keyboard(message.chat.id),
    )


@bot.message_handler(commands=["help"])
def help_cmd(message):
    bot.send_message(
        message.chat.id,
        "<b>Команды:</b>\n"
        "• 🎲 12 слов — создать новую 12-word фразу\n"
        "• 🎲 24 слова — создать новую 24-word фразу\n"
        "• 🎯 Рандом12 одинаковые — одно случайное BIP39-слово ×12\n"
        "• 🎯 Рандом24 одинаковые — одно случайное BIP39-слово ×24\n"
        "• 🔐 Установить PIN — включить историю с ключами\n"
        "• 📜 История — запросит PIN и покажет кошельки/ключи/баланс\n"
        "• 🔄 Баланс последнего — обновить баланс последней записи\n"
        "• 💰 Положительный баланс — временный RAM-список найденных адресов с балансом > 0\n"
        f"• ⚙️ Пакет: ВКЛ/ВЫКЛ — когда включено, 🎲 12/24 слова и 🎯 Рандом12/24 одинаковые создают сразу {BATCH_WALLET_COUNT} кошельков; проверка баланса доступна только для отдельно загруженного public.txt/CSV без private.txt/WIF\n"
        "• 🔑 Приват ключ ВКЛ/ВЫКЛ — в режиме ВКЛ новые генерации создают random private key → WIF без вывода seed-фраз\n"
        f"• 📋 Копировать всё — после PIN отправить public.txt и private.txt по последним {BATCH_WALLET_COUNT} ключам; номера строк совпадают\n"
        "• 📤 Проверить public.txt — инструкция по загрузке файла public.txt; проверяются только публичные адреса, файлы с приватными ключами не принимаются\n"
        f"• /scan10000 seed words — проверить первые {BATCH_WALLET_COUNT} адресов из твоей seed-фразы (/scan1000 и /scan100 тоже работают)\n"
        "• /set_pin 12345 — задать PIN из 5 цифр\n\n"
        f"Путь деривации: {code(DERIVATION_PATH)}\n"
        f"Файл истории: {code(HISTORY_FILE)}",
        reply_markup=main_keyboard(message.chat.id),
    )


def scan_owned_mnemonic_100(chat_id: int, mnemonic_phrase: str) -> None:
    """Проверяет первые BATCH_WALLET_COUNT адресов из seed-фразы, которую явно ввёл пользователь."""
    bot.send_message(
        chat_id,
        f"🔎 Проверяю первые {BATCH_WALLET_COUNT} адресов из введённой seed-фразы по пути m/44'/0'/0'/0/i.\n"
        "Случайные кошельки здесь не генерируются.",
        reply_markup=main_keyboard(chat_id),
    )

    positive_records: list[dict[str, Any]] = []
    api_errors = 0
    for index in range(BATCH_WALLET_COUNT):
        address, wif, path = derive_bitcoin_wallet_at_index(mnemonic_phrase, index)
        balance = get_balance(address)
        increment_checked_counter(chat_id)
        if str(balance).startswith("не удалось"):
            api_errors += 1
        if parse_balance_btc(balance) > 0:
            record: dict[str, Any] = {
                "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
                "type": f"Owned scan {BATCH_WALLET_COUNT}",
                "address": address,
                "balance": balance,
                "checksum_ok": True,
                "derivation_path": path,
                "index": index,
            }
            if chat_has_pin(chat_id):
                record["secret"] = encrypt_json({
                    "mnemonic": mnemonic_phrase,
                    "wif": wif,
                    "derivation_path": path,
                    "index": index,
                })
            positive_records.append(record)
            remember_positive_wallet(chat_id, record)
        time.sleep(0.2)

    if positive_records:
        add_history_records(chat_id, positive_records)
        shown = []
        for item in positive_records[:10]:
            shown.append(f"🏠 {code(item['address'])}\n💰 <b>{esc(item['balance'])}</b>\n📍 {code(item['derivation_path'])}")
        extra = "" if len(positive_records) <= 10 else f"\n…и ещё {len(positive_records) - 10}."
        pin_line = "🔐 Положительные записи сохранены в PIN-историю." if chat_has_pin(chat_id) else "⚠️ PIN не установлен — в историю сохранены только адреса/балансы без seed/WIF."
        bot.send_message(
            chat_id,
            f"✅ Проверено: {BATCH_WALLET_COUNT} адресов.\n"
            f"💰 Найдено с балансом > 0: <b>{len(positive_records)}</b>.\n"
            f"{pin_line}\n\n" + "\n\n".join(shown) + extra,
            reply_markup=main_keyboard(chat_id),
        )
    else:
        err_line = f"\n⚠️ Ошибки API при проверке: {api_errors}." if api_errors else ""
        bot.send_message(
            chat_id,
            f"✅ Проверено: {BATCH_WALLET_COUNT} адресов.\n"
            "💰 Адресов с балансом > 0 не найдено."
            f"{err_line}",
            reply_markup=main_keyboard(chat_id),
        )


@bot.message_handler(commands=["scan100", "scan1000", "scan10000"])
def scan100_cmd(message):
    parts = (message.text or "").strip().split(maxsplit=1)
    if len(parts) != 2:
        bot.send_message(
            message.chat.id,
            "🔎 Проверка своих адресов:\n"
            "<code>/scan10000 word1 word2 ... word12</code>\n"
            "или старые алиасы: <code>/scan1000 ...</code> и <code>/scan100 ...</code>\n\n"
            f"Команда проверяет первые {BATCH_WALLET_COUNT} адресов из введённой seed-фразы по пути m/44'/0'/0'/0/i. "
            "Случайные кошельки не генерируются.",
            reply_markup=main_keyboard(message.chat.id),
        )
        return
    mnemonic_phrase = normalize_mnemonic(parts[1])
    ok, error_text, checksum_ok = validate_mnemonic_words(mnemonic_phrase)
    if not ok:
        bot.send_message(message.chat.id, error_text, reply_markup=main_keyboard(message.chat.id))
        return
    if not checksum_ok:
        bot.send_message(
            message.chat.id,
            "⚠️ BIP39 checksum у фразы неверный. Для сканирования нужна корректная seed-фраза от твоего кошелька.",
            reply_markup=main_keyboard(message.chat.id),
        )
        return
    scan_owned_mnemonic_100(message.chat.id, mnemonic_phrase)


# ---------- address-only TXT balance check ----------

BITCOIN_ADDRESS_RE = re.compile(
    r"(?<![A-Za-z0-9])((?:[13][a-km-zA-HJ-NP-Z1-9]{25,34})|(?:bc1[ac-hj-np-z02-9]{11,71}))(?![A-Za-z0-9])",
    re.IGNORECASE,
)
# Сырые public key тоже безопасны для проверки: из них можно получить публичный P2PKH-адрес.
# Поддерживаются compressed 02/03 + 32 байта и uncompressed 04 + 64 байта в HEX.
PUBLIC_KEY_HEX_RE = re.compile(
    r"(?<![A-Fa-f0-9])((?:02|03)[0-9A-Fa-f]{64}|04[0-9A-Fa-f]{128})(?![A-Fa-f0-9])"
)
WIF_RE = re.compile(r"(?<![A-Za-z0-9])([5KL][1-9A-HJ-NP-Za-km-z]{50,51})(?![A-Za-z0-9])")
# Приватные маркеры проверяются аккуратно, чтобы обычный public.txt
# не блокировался из-за случайной подстроки вроде "xprv" внутри BTC-адреса.
PRIVATE_LABEL_RE = re.compile(r"(?i)(?:^|[^a-z0-9_])(mnemonic|wif|seed|private[_ -]?key)\s*[:=]")
EXTENDED_PRIVATE_KEY_RE = re.compile(r"(?<![A-Za-z0-9])(?:xprv|yprv|zprv)[1-9A-HJ-NP-Za-km-z]{40,}(?![A-Za-z0-9])")


def base58_decode(text: str) -> bytes:
    num = 0
    for char in text:
        if char not in BASE58_ALPHABET:
            raise ValueError("invalid base58 character")
        num = num * 58 + BASE58_ALPHABET.index(char)
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    leading_zeros = len(text) - len(text.lstrip("1"))
    return b"\x00" * leading_zeros + raw


def base58check_decode(text: str) -> bytes:
    raw = base58_decode(text)
    if len(raw) < 5:
        raise ValueError("base58check payload too short")
    payload, checksum = raw[:-4], raw[-4:]
    expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if not hmac.compare_digest(checksum, expected):
        raise ValueError("base58check checksum mismatch")
    return payload


def is_valid_wif(value: str) -> bool:
    try:
        payload = base58check_decode(value.strip())
    except Exception:
        return False
    if not payload or payload[0] != 0x80:
        return False
    # 1 byte version + 32 bytes key или + compressed marker 0x01.
    if len(payload) == 33:
        key = payload[1:]
    elif len(payload) == 34 and payload[-1] == 0x01:
        key = payload[1:-1]
    else:
        return False
    private_int = int.from_bytes(key, "big")
    return 1 <= private_int < SECP256K1_ORDER


def public_key_hex_to_p2pkh_address(pubkey_hex: str) -> str | None:
    try:
        raw = bytes.fromhex(pubkey_hex.strip())
    except ValueError:
        return None
    if len(raw) == 33 and raw[0] in (2, 3):
        return base58check_encode(b"\x00" + hash160(raw))
    if len(raw) == 65 and raw[0] == 4:
        return base58check_encode(b"\x00" + hash160(raw))
    return None


def parse_addresses_from_text(text: str) -> list[str]:
    seen: set[str] = set()
    addresses: list[str] = []

    def add_address(address: str) -> None:
        if len(addresses) >= BATCH_WALLET_COUNT:
            return
        key = address.lower()
        if key in seen:
            return
        seen.add(key)
        addresses.append(address)

    for match in BITCOIN_ADDRESS_RE.finditer(text):
        add_address(match.group(1).strip())

    # Если пользователь загрузил именно публичные ключи HEX, конвертируем их в legacy P2PKH-адреса.
    for match in PUBLIC_KEY_HEX_RE.finditer(text):
        if len(addresses) >= BATCH_WALLET_COUNT:
            break
        address = public_key_hex_to_p2pkh_address(match.group(1))
        if address:
            add_address(address)

    return addresses


def parse_wifs_from_text(text: str) -> list[str]:
    seen: set[str] = set()
    wifs: list[str] = []
    for match in WIF_RE.finditer(text):
        wif = match.group(1).strip()
        if wif in seen or not is_valid_wif(wif):
            continue
        seen.add(wif)
        wifs.append(wif)
        if len(wifs) >= BATCH_WALLET_COUNT:
            break
    return wifs


def contains_private_wallet_data(text: str) -> bool:
    """
    Возвращает True только для реальных приватных данных.

    Важно: public.txt может содержать тысячи Base58-адресов, и внутри
    обычного публичного адреса случайно встречаются подстроки вроде
    "xprv"/"yprv"/"zprv". Поэтому нельзя искать приватные маркеры
    простым `in` по всему файлу. Проверяем только валидный WIF через
    Base58Check, явные подписи вида `wif:`/`seed:` и полноценные extended
    private keys как отдельные токены. Публичные BTC-адреса и HEX public-key
    никогда не считаются приватными данными.
    """
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        # Явные подписи приватных данных блокируем, но только когда это
        # именно метка с двоеточием/равно, а не случайная подстрока адреса.
        if PRIVATE_LABEL_RE.search(line):
            return True

        # Extended private key должен быть отдельным длинным токеном,
        # а не частью публичного адреса.
        if EXTENDED_PRIVATE_KEY_RE.search(line):
            return True

        # WIF определяется только строгой Base58Check-валидацией.
        # Это убирает ложные срабатывания на публичные адреса/public-key.
        if parse_wifs_from_text(line):
            return True

    return False


def public_scan_progress_text(checked: int, total: int, positive_count: int, chat_id: int) -> str:
    return (
        f"🔎 Проверено {checked}/{total} адресов…\n"
        f"💰 Положительный баланс: <b>{positive_count}</b>\n"
        f"📊 Всего проверено в этой сессии: <b>{checked_counter(chat_id)}</b>"
    )


def public_scan_milestones(total: int) -> set[int]:
    milestones = {total}
    if total > 5000:
        milestones.add(5000)
    return {m for m in milestones if 0 < m <= total}


def get_balance_safe_for_batch(address: str) -> str:
    # Отдельная обёртка нужна, чтобы ошибка одного адреса не останавливала весь пакет.
    try:
        return get_balance(address)
    except Exception as exc:
        return f"не удалось получить баланс: {type(exc).__name__}"


def chunks_by_size(items: list[Any], size: int) -> list[list[Any]]:
    return [items[i:i + size] for i in range(0, len(items), size)]


def satoshi_to_btc_text(sat: int) -> str:
    return f"{sat / 100000000:.8f} BTC"


def get_balances_blockcypher_batch(addresses: list[str], *, request_timeout: int, fallback_workers: int) -> dict[str, str]:
    """
    Максимально быстрый путь для public.txt: BlockCypher batch до 100 адресов
    за один HTTP-запрос. Если batch недоступен или часть адресов не вернулась,
    для таких адресов используется прежний fallback по одному адресу.
    """
    if not addresses:
        return {}

    headers = {
        "User-Agent": "BTC-Wallet-Telegram-Bot/3.2",
        "Accept": "application/json",
    }
    joined = ";".join(addresses)
    url = f"https://api.blockcypher.com/v1/btc/main/addrs/{joined}/balance"
    params = {"token": BLOCKCYPHER_TOKEN} if BLOCKCYPHER_TOKEN else None

    try:
        r = requests.get(url, timeout=request_timeout, headers=headers, params=params)
        if r.status_code != 200:
            raise RuntimeError(f"BlockCypher HTTP {r.status_code}")

        data = r.json()
        if isinstance(data, dict):
            rows = [data]
        elif isinstance(data, list):
            rows = data
        else:
            raise RuntimeError("BlockCypher bad JSON")

        result: dict[str, str] = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            address = str(row.get("address") or "").strip()
            if not address:
                continue
            final_balance = row.get("final_balance")
            if final_balance is None:
                final_balance = int(row.get("balance") or 0) + int(row.get("unconfirmed_balance") or 0)
            result[address] = satoshi_to_btc_text(int(final_balance or 0))

        missing = [address for address in addresses if address not in result]
        if missing:
            with ThreadPoolExecutor(max_workers=min(fallback_workers, len(missing))) as fallback_executor:
                future_to_address = {fallback_executor.submit(get_balance_safe_for_batch, address): address for address in missing}
                for future in as_completed(future_to_address):
                    result[future_to_address[future]] = future.result()

        return result

    except Exception:
        # При сбое batch-запроса проверяем chunk старым способом, чтобы бот не зависал и не падал.
        result: dict[str, str] = {}
        with ThreadPoolExecutor(max_workers=min(fallback_workers, len(addresses))) as fallback_executor:
            future_to_address = {fallback_executor.submit(get_balance_safe_for_batch, address): address for address in addresses}
            for future in as_completed(future_to_address):
                result[future_to_address[future]] = future.result()
        return result


def scan_uploaded_address_file(
    chat_id: int,
    addresses: list[str],
    *,
    source_name: str = "TXT",
    record_type: str = "Address file scan",
) -> None:
    """Максимально быстрая проверка только публичных адресов/публичных ключей из public.txt/TXT/CSV."""
    total = len(addresses)
    cfg = get_public_scan_settings(chat_id)
    bot.send_message(
        chat_id,
        f"🔎 Начинаю максимально ускоренную проверку адресов из {esc(source_name)}: {total} шт.\n"
        f"Batch-размер: <b>{cfg['batch_size']}</b> адресов за запрос.\n"
        f"Параллельных batch-запросов: <b>{cfg['batch_workers']}</b>.\n"
        f"Fallback-потоков: <b>{cfg['fallback_workers']}</b>. Timeout: <b>{cfg['timeout']}</b> сек.\n"
        "Проверяются только публичные адреса; приватные ключи не сохраняются и не обрабатываются.",
        reply_markup=main_keyboard(chat_id),
    )

    positive_records: list[dict[str, Any]] = []
    api_errors = 0
    checked = 0
    milestones = public_scan_milestones(total)
    pending_milestones = sorted(milestones)

    indexed_addresses = list(enumerate(addresses, start=1))
    chunks = chunks_by_size(indexed_addresses, cfg["batch_size"])

    # Быстрый режим: batch-запросы вместо одиночных; параметры берутся из настроек Telegram.
    with ThreadPoolExecutor(max_workers=min(cfg["batch_workers"], len(chunks) or 1)) as executor:
        future_to_chunk = {
            executor.submit(
                get_balances_blockcypher_batch,
                [address for _index, address in chunk],
                request_timeout=cfg["timeout"],
                fallback_workers=cfg["fallback_workers"],
            ): chunk
            for chunk in chunks
        }

        for future in as_completed(future_to_chunk):
            chunk = future_to_chunk[future]
            try:
                batch_balances = future.result()
            except Exception as exc:
                batch_balances = {address: f"не удалось получить баланс: {type(exc).__name__}" for _index, address in chunk}

            for original_index, address in chunk:
                balance = batch_balances.get(address, "не удалось получить баланс: empty batch result")
                checked += 1
                increment_checked_counter(chat_id)

                if str(balance).startswith("не удалось"):
                    api_errors += 1

                if parse_balance_btc(balance) > 0:
                    record: dict[str, Any] = {
                        "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
                        "type": record_type,
                        "address": address,
                        "balance": balance,
                        "derivation_path": f"address-only {source_name}",
                        "index": original_index,
                    }
                    positive_records.append(record)
                    remember_positive_wallet(chat_id, record)
                    bot.send_message(
                        chat_id,
                        "💰 <b>Положительный баланс найден</b>\n"
                        f"🏠 {code(address)}\n"
                        f"💰 <b>{esc(balance)}</b>\n"
                        f"🔎 Проверено сейчас: {checked}/{total}",
                        reply_markup=main_keyboard(chat_id),
                    )

            while pending_milestones and checked >= pending_milestones[0]:
                milestone = pending_milestones.pop(0)
                bot.send_message(
                    chat_id,
                    public_scan_progress_text(milestone, total, len(positive_records), chat_id),
                    reply_markup=main_keyboard(chat_id),
                )

    if pending_milestones:
        bot.send_message(
            chat_id,
            public_scan_progress_text(total, total, len(positive_records), chat_id),
            reply_markup=main_keyboard(chat_id),
        )

    if positive_records:
        # Сохраняем только публичные адреса и баланс; приватные ключи/WIF из файла не принимаются и не сохраняются.
        add_history_records(chat_id, positive_records)
        lines = [
            "BTC Wallet Bot — адреса с положительным балансом",
            f"Дата проверки: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Проверено адресов: {total}",
            f"Найдено с балансом > 0: {len(positive_records)}",
            "",
        ]
        for item in positive_records:
            lines.append(f"address: {item['address']}")
            lines.append(f"balance: {item['balance']}")
            lines.append(f"checked_at: {item['date']}")
            lines.append("")
        result_text = "\n".join(lines)
        result_file = io.BytesIO(result_text.encode("utf-8"))
        result_file.name = f"positive_balances_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

        shown = []
        for item in positive_records[:10]:
            shown.append(f"🏠 {code(item['address'])}\n💰 <b>{esc(item['balance'])}</b>")
        extra = "" if len(positive_records) <= 10 else f"\n…и ещё {len(positive_records) - 10}."
        bot.send_message(
            chat_id,
            f"✅ Проверено адресов: {total}.\n"
            f"📊 Всего проверено в этой сессии: <b>{checked_counter(chat_id)}</b>.\n"
            f"💰 Положительный баланс: <b>{len(positive_records)}</b>.\n"
            "Список добавлен в RAM-кнопку «Положительный баланс» до перезапуска бота.\n"
            "Положительные адреса сохранены в историю без приватных ключей.\n\n"
            + "\n\n".join(shown) + extra,
            reply_markup=main_keyboard(chat_id),
        )
        bot.send_document(chat_id, result_file, caption="💰 TXT со списком адресов с положительным балансом.")
    else:
        err_line = f"\n⚠️ Ошибки API при проверке: {api_errors}." if api_errors else ""
        bot.send_message(
            chat_id,
            f"✅ Проверено адресов: {total}.\n"
            f"📊 Всего проверено в этой сессии: <b>{checked_counter(chat_id)}</b>.\n"
            "💰 Положительный баланс: <b>0</b>."
            f"{err_line}",
            reply_markup=main_keyboard(chat_id),
        )

@bot.message_handler(content_types=["document"])
def handle_document_upload(message):
    doc = message.document
    filename = (doc.file_name or "").lower()
    if not filename.endswith((".txt", ".csv")):
        bot.send_message(message.chat.id, "📤 Загрузи TXT/CSV со списком публичных BTC-адресов, по одному адресу в строке.", reply_markup=main_keyboard(message.chat.id))
        return
    if doc.file_size and doc.file_size > MAX_UPLOAD_FILE_BYTES:
        bot.send_message(message.chat.id, f"❌ Файл слишком большой. Максимум: {MAX_UPLOAD_FILE_BYTES // 1000} KB.", reply_markup=main_keyboard(message.chat.id))
        return

    try:
        file_info = bot.get_file(doc.file_id)
        raw = bot.download_file(file_info.file_path)
        text = raw.decode("utf-8-sig", errors="replace")
    except Exception as exc:
        bot.send_message(message.chat.id, f"❌ Не удалось прочитать файл: {code(type(exc).__name__)}", reply_markup=main_keyboard(message.chat.id))
        return

    if contains_private_wallet_data(text):
        bot.send_message(
            message.chat.id,
            "⚠️ Этот файл содержит приватные данные: WIF/private-key или seed.\n\n"
            "Я не проверяю баланс по спискам приватных ключей. Для проверки загрузи public.txt или отдельный TXT/CSV только с публичными BTC-адресами, без WIF/seed.",
            reply_markup=main_keyboard(message.chat.id),
        )
        return

    addresses = parse_addresses_from_text(text)
    if not addresses:
        bot.send_message(message.chat.id, "❌ В файле не нашёл публичных BTC-адресов или HEX public-key. Формат: один публичный адрес или один public-key в строке.", reply_markup=main_keyboard(message.chat.id))
        return

    scan_uploaded_address_file(message.chat.id, addresses)


@bot.message_handler(func=lambda m: True)
def handle(message):
    text = (message.text or "").strip()
    if not text:
        return bot.reply_to(message, "Отправь текст или выбери кнопку.", reply_markup=main_keyboard(message.chat.id))

    if handle_public_scan_setting_value(message):
        return

    if text in {"⚡ Настройки public.txt", "настройки public.txt", "public settings"}:
        return show_public_scan_settings(message.chat.id)

    if text in {"⚡ Public MAX", "public max"}:
        set_public_scan_preset(message.chat.id, "max")
        bot.send_message(message.chat.id, "✅ Включён профиль <b>Public MAX</b> для ускоренной проверки public.txt.", reply_markup=public_scan_settings_keyboard())
        return show_public_scan_settings(message.chat.id)

    if text in {"🛡️ Public SAFE", "public safe"}:
        set_public_scan_preset(message.chat.id, "safe")
        bot.send_message(message.chat.id, "✅ Включён профиль <b>Public SAFE</b> для проверки public.txt с меньшим риском лимитов API.", reply_markup=public_scan_settings_keyboard())
        return show_public_scan_settings(message.chat.id)

    if text == "📦 Batch size":
        return ask_public_scan_setting(message.chat.id, "public_scan_batch_size")

    if text == "🧵 Batch workers":
        return ask_public_scan_setting(message.chat.id, "public_scan_batch_workers")

    if text == "🔁 Fallback workers":
        return ask_public_scan_setting(message.chat.id, "public_scan_fallback_workers")

    if text == "⏱ Timeout":
        return ask_public_scan_setting(message.chat.id, "public_scan_timeout")

    if text in {"↩️ Назад", "назад", "back"}:
        return bot.send_message(message.chat.id, "Главное меню.", reply_markup=main_keyboard(message.chat.id))

    if text in {"⚙️ Пакет: ВКЛ", "⚙️ Пакет: ВЫКЛ", "пакет", "batch"}:
        enabled = toggle_batch_enabled(message.chat.id)
        status = "ВКЛ" if enabled else "ВЫКЛ"
        return bot.send_message(
            message.chat.id,
            f"⚙️ Пакетный режим: <b>{status}</b>.\n"
            f"Когда режим включён, кнопки 🎲 12/24 слова и 🎯 Рандом12/24 одинаковые создают сразу {BATCH_WALLET_COUNT} записей и сохраняют их в PIN-историю.",
            reply_markup=main_keyboard(message.chat.id),
        )

    if text in {"🔑 Приват ключ: ВКЛ", "🔑 Приват ключ: ВЫКЛ", "приват ключ", "private key"}:
        enabled = toggle_private_key_mode_enabled(message.chat.id)
        status = "ВКЛ" if enabled else "ВЫКЛ"
        return bot.send_message(
            message.chat.id,
            f"🔑 Режим приватного ключа: <b>{status}</b>.\n"
            "Когда режим включён, кнопки генерации создают random private key → WIF, без вывода seed-фраз. "
            "Экспорт «Копировать всё» выдаёт два файла: public.txt и private.txt.",
            reply_markup=main_keyboard(message.chat.id),
        )

    if text in {"🎲 12 слов", "🎲 Случайный 12", "12 слов"}:
        if is_private_key_mode_enabled(message.chat.id):
            if is_batch_enabled(message.chat.id):
                return process_batch_private_keys(message.chat.id)
            return process_random_private_key(message.chat.id)
        if is_batch_enabled(message.chat.id):
            return process_batch_wallets(message.chat.id, "Random 12")
        mnemonic_phrase = mnemo.generate(strength=128)
        return process_mnemonic(message.chat.id, mnemonic_phrase, True, source_type="Random 12")

    if text in {"🎲 24 слова", "🎲 Случайный 24", "24 слова"}:
        if is_private_key_mode_enabled(message.chat.id):
            if is_batch_enabled(message.chat.id):
                return process_batch_private_keys(message.chat.id)
            return process_random_private_key(message.chat.id)
        if is_batch_enabled(message.chat.id):
            return process_batch_wallets(message.chat.id, "Random 24")
        mnemonic_phrase = mnemo.generate(strength=256)
        return process_mnemonic(message.chat.id, mnemonic_phrase, True, source_type="Random 24")

    if text in {"🎯 Рандом12 одинаковые", "рандом12", "random12"}:
        if is_private_key_mode_enabled(message.chat.id):
            if is_batch_enabled(message.chat.id):
                return process_batch_private_keys(message.chat.id)
            return process_random_private_key(message.chat.id)
        if is_batch_enabled(message.chat.id):
            return process_batch_wallets(message.chat.id, "SameWord 12")
        mnemonic_phrase = same_word_mnemonic(12)
        return process_mnemonic(message.chat.id, mnemonic_phrase, True, source_type="SameWord 12")

    if text in {"🎯 Рандом24 одинаковые", "рандом24", "random24"}:
        if is_private_key_mode_enabled(message.chat.id):
            if is_batch_enabled(message.chat.id):
                return process_batch_private_keys(message.chat.id)
            return process_random_private_key(message.chat.id)
        if is_batch_enabled(message.chat.id):
            return process_batch_wallets(message.chat.id, "SameWord 24")
        mnemonic_phrase = same_word_mnemonic(24)
        return process_mnemonic(message.chat.id, mnemonic_phrase, True, source_type="SameWord 24")

    if text == "📜 История":
        return request_history_pin(message)

    if text == "🔐 Установить PIN":
        return ask_set_pin(message)

    if text == "🔄 Баланс последнего":
        return refresh_last_balance(message.chat.id)

    if text in {"📤 Проверить public.txt", "проверить public.txt", "check public.txt"}:
        cfg = get_public_scan_settings(message.chat.id)
        return bot.send_message(
            message.chat.id,
            "📤 Загрузи сюда файл public.txt или CSV/TXT со списком публичных BTC-адресов, по одному адресу в строке.\n\n"
            f"Бот в ускоренном режиме проверит до {BATCH_WALLET_COUNT} публичных адресов, покажет прогресс на 5000/{BATCH_WALLET_COUNT} и {BATCH_WALLET_COUNT}/{BATCH_WALLET_COUNT}, а адреса с балансом > 0 покажет сразу в чате и сохранит в историю без приватных ключей. "
            "Файлы private.txt/WIF/seed для проверки не принимаются. Если в TXT лежат HEX public-key, бот сконвертирует их в legacy P2PKH-адреса и проверит баланс.\n\n"
            f"⚡ Текущие настройки: batch <b>{cfg['batch_size']}</b>, batch workers <b>{cfg['batch_workers']}</b>, fallback <b>{cfg['fallback_workers']}</b>, timeout <b>{cfg['timeout']} сек</b>. Изменить: кнопка «⚡ Настройки public.txt».",
            reply_markup=main_keyboard(message.chat.id),
        )

    if text in {"📋 Копировать всё", "копировать всё", "copy all", "export100", "export1000"}:
        return request_export_all_pin(message)

    if text.startswith("💰 Положительный баланс"):
        return show_session_positive_wallets(message.chat.id)

    if text.startswith("📊 Проверено"):
        return show_checked_counter(message.chat.id)

    if text == "📝 Ввести mnemonic":
        return bot.send_message(
            message.chat.id,
            "Отправь 12 или 24 слова из BIP39 через пробел.\n"
            "Повторения разрешены. Если checksum неверный — будет предупреждение, но бот продолжит.",
            reply_markup=main_keyboard(message.chat.id),
        )

    mnemonic_phrase = normalize_mnemonic(text)
    ok, error_text, checksum_ok = validate_mnemonic_words(mnemonic_phrase)
    if not ok:
        return bot.reply_to(message, error_text, reply_markup=main_keyboard(message.chat.id))

    return process_mnemonic(message.chat.id, mnemonic_phrase, False, checksum_ok=checksum_ok, source_type="Custom")


def process_mnemonic(chat_id: int, mnemonic_phrase: str, is_random: bool, checksum_ok: bool | None = None, source_type: str | None = None):
    try:
        if checksum_ok is None:
            checksum_ok = mnemo.check(mnemonic_phrase)
        address, wif = derive_bitcoin_wallet(mnemonic_phrase)
        balance = get_balance(address)

        chat_key = str(chat_id)
        history.setdefault(chat_key, [])
        record: dict[str, Any] = {
            "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "type": source_type or ("Random" if is_random else "Custom"),
            "address": address,
            "balance": balance,
            "checksum_ok": bool(checksum_ok),
        }
        secrets_saved = False
        if chat_has_pin(chat_id):
            record["secret"] = encrypt_json({
                "mnemonic": mnemonic_phrase,
                "wif": wif,
                "derivation_path": DERIVATION_PATH,
            })
            secrets_saved = True
        history[chat_key].append(record)
        history[chat_key] = history[chat_key][-MAX_HISTORY_PER_CHAT:]
        remember_positive_wallet(chat_id, record)
        save_history()

        save_line = (
            "🔐 История: WIF сохранён, просмотр только по PIN."
            if secrets_saved
            else "⚠️ PIN не установлен — в историю сохранены только адрес и баланс. Нажми 🔐 Установить PIN."
        )
        if is_private_key_mode_enabled(chat_id):
            response_text = (
                "✅ <b>Кошелёк создан!</b>\n\n"
                f"🔑 Приватный ключ WIF:\n{code(wif)}\n\n"
                f"💰 Баланс: <b>{esc(balance)}</b>\n\n"
                f"{esc(save_line)}\n"
                "⚠️ Приватный ключ даёт полный доступ к кошельку. Никому его не отправляй."
            )
        else:
            response_text = (
                "✅ <b>Кошелёк создан!</b>\n\n"
                f"🏠 Публичный адрес:\n{code(address)}\n\n"
                f"🔑 Приватный ключ WIF:\n{code(wif)}\n\n"
                f"💰 Баланс: <b>{esc(balance)}</b>\n\n"
                f"{esc(save_line)}\n"
                "⚠️ Приватный ключ даёт полный доступ к кошельку. Никому его не отправляй."
            )
        bot.send_message(chat_id, response_text, reply_markup=main_keyboard(chat_id))
    except Exception as e:
        bot.send_message(chat_id, f"❌ Ошибка создания: {code(str(e))}", reply_markup=main_keyboard(chat_id))


def show_history(chat_id: int, include_secrets: bool = False):
    items = history.get(str(chat_id)) or []
    if not items:
        return bot.send_message(chat_id, "История пуста.", reply_markup=main_keyboard(chat_id))

    lines = ["📜 <b>Последние кошельки:</b>", ""]
    for index, w in enumerate(reversed(items[-10:]), start=1):
        lines.append(f"<b>#{index}</b>")
        if not is_private_key_mode_enabled(chat_id):
            lines.append(f"🏠 Публичный адрес: {code(w.get('address', '?'))}")
        if include_secrets:
            token = w.get("secret")
            if token:
                try:
                    secret_data = decrypt_json(str(token))
                    lines.append(f"🔑 Приватный ключ WIF: {code(secret_data.get('wif', '?'))}")
                except (InvalidToken, Exception):
                    lines.append("⚠️ Приватный ключ не удалось расшифровать.")
            else:
                lines.append("⚠️ Приватный ключ не сохранён: PIN не был установлен при создании.")
        lines.append(f"💰 Баланс: {esc(w.get('balance', '?'))}")
        lines.append("")
    bot.send_message(chat_id, "\n".join(lines), reply_markup=main_keyboard(chat_id))


if __name__ == "__main__":
    print(f"🤖 Бот запущен. History: {HISTORY_FILE}", flush=True)
    try:
        bot.remove_webhook()
    except Exception:
        pass
    bot.infinity_polling(skip_pending=True, timeout=30, long_polling_timeout=30)
