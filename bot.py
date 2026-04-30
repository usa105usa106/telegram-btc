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
    return rec


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
            r = requests.get(url, timeout=15, headers=headers)
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
        "💰 При создании public.txt через «Копировать всё» бот сразу запустит автопроверку баланса по публичным адресам.",
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
        "💰 После создания public.txt через «Копировать всё» бот автоматически проверит баланс по публичным адресам.\n"
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
            "🔎 Автопроверка баланса по этому public.txt запускается сразу после отправки файлов."
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

    if public_addresses:
        scan_uploaded_address_file(
            chat_id,
            public_addresses,
            source_name="созданного public.txt",
            record_type="Auto public.txt scan",
        )
    else:
        bot.send_message(
            chat_id,
            "⚠️ public.txt создан, но публичные адреса для автопроверки не распознаны.",
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
        "✅ Новый public.txt автоматически проверяется на баланс сразу после создания; проверка идёт без обработки private.txt/WIF/seed.\n"
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
        f"• ⚙️ Пакет: ВКЛ/ВЫКЛ — когда включено, 🎲 12/24 слова и 🎯 Рандом12/24 одинаковые создают сразу {BATCH_WALLET_COUNT} кошельков; автопроверка запускается при создании public.txt через «Копировать всё»\n"
        "• 🔑 Приват ключ ВКЛ/ВЫКЛ — в режиме ВКЛ новые генерации создают random private key → WIF без вывода seed-фраз\n"
        f"• 📋 Копировать всё — после PIN отправить public.txt и private.txt по последним {BATCH_WALLET_COUNT} ключам; номера строк совпадают; public.txt сразу проверяется на баланс\n"
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
PRIVATE_WALLET_MARKERS = (
    "mnemonic:",
    "wif:",
    "seed:",
    "private_key",
    "private key",
    "xprv",
    "yprv",
    "zprv",
)


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
    lower_text = text.lower()
    if any(marker in lower_text for marker in PRIVATE_WALLET_MARKERS):
        return True
    # ВАЖНО: WIF считаем приватным только после Base58Check-валидации.
    # Это убирает ложные срабатывания на обычных публичных адресах/публичных ключах.
    return bool(parse_wifs_from_text(text))

def scan_uploaded_address_file(
    chat_id: int,
    addresses: list[str],
    *,
    source_name: str = "TXT",
    record_type: str = "Address file scan",
) -> None:
    bot.send_message(
        chat_id,
        f"🔎 Начинаю проверку адресов из {esc(source_name)}: {len(addresses)} шт.\n"
        "Проверяются только публичные адреса; приватные ключи не сохраняются и не обрабатываются.",
        reply_markup=main_keyboard(chat_id),
    )

    positive_records: list[dict[str, Any]] = []
    api_errors = 0
    for index, address in enumerate(addresses, start=1):
        balance = get_balance(address)
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
                "index": index,
            }
            positive_records.append(record)
            remember_positive_wallet(chat_id, record)
        if index % 100 == 0 and index < len(addresses):
            bot.send_message(
                chat_id,
                f"🔎 Проверено {index}/{len(addresses)} адресов…\n"
                f"📊 Всего проверено в этой сессии: {checked_counter(chat_id)}",
            )
        time.sleep(0.2)

    if positive_records:
        # Сохраняем только публичные адреса и баланс; приватные ключи/WIF из файла не принимаются и не сохраняются.
        add_history_records(chat_id, positive_records)
        lines = [
            "BTC Wallet Bot — адреса с положительным балансом",
            f"Дата проверки: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Проверено адресов: {len(addresses)}",
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
            f"✅ Проверено адресов: {len(addresses)}.\n"
            f"📊 Всего проверено в этой сессии: <b>{checked_counter(chat_id)}</b>.\n"
            f"💰 Найдено с балансом > 0: <b>{len(positive_records)}</b>.\n"
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
            f"✅ Проверено адресов: {len(addresses)}.\n"
            f"📊 Всего проверено в этой сессии: <b>{checked_counter(chat_id)}</b>.\n"
            "💰 Адресов с балансом > 0 не найдено."
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
        return bot.send_message(
            message.chat.id,
            "📤 Загрузи сюда файл public.txt или CSV/TXT со списком публичных BTC-адресов, по одному адресу в строке.\n\n"
            f"Бот проверит до {BATCH_WALLET_COUNT} публичных адресов, покажет адреса с балансом > 0 и сохранит их в историю без приватных ключей. "
            "Файлы private.txt/WIF/seed для проверки не принимаются. Если в TXT лежат HEX public-key, бот сконвертирует их в legacy P2PKH-адреса и проверит баланс.",
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
