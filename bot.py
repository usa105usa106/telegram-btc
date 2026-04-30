import base64
import hashlib
import hmac
import html
import io
import json
import os
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
MAX_HISTORY_PER_CHAT = 5000
BATCH_WALLET_COUNT = 1000
TELEGRAM_COPY_CHUNK_SIZE = 3600
PIN_LEN = 5
PIN_HASH_ITERATIONS = 240_000

bot = telebot.TeleBot(TOKEN, parse_mode="HTML")
mnemo = Mnemonic("english")
bip39_words = set(mnemo.wordlist)

# Хранится только в RAM и очищается после перезапуска бота.
session_positive_wallets: dict[str, list[dict[str, Any]]] = {}


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
    return rec


def is_batch_enabled(chat_id: int) -> bool:
    return bool(get_chat_settings(chat_id).get("batch_enabled"))


def toggle_batch_enabled(chat_id: int) -> bool:
    rec = get_chat_settings(chat_id)
    rec["batch_enabled"] = not bool(rec.get("batch_enabled"))
    save_settings()
    return bool(rec["batch_enabled"])


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
    markup.add("📋 Копировать всё")
    if chat_id is not None:
        markup.add(positive_balance_button_text(chat_id))
    else:
        markup.add("💰 Положительный баланс (0)")
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
        f"💰 Баланс в пакетном режиме не проверяется автоматически; для нужного адреса используй ручную проверку.\n"
        f"📋 Нажми «Копировать всё», чтобы получить все {BATCH_WALLET_COUNT} seed-фраз/WIF прямо сообщениями в Telegram.\n\n"
        f"Первый адрес:\n{code(first_address)}\n\n"
        f"Последний адрес:\n{code(last_address)}",
        reply_markup=main_keyboard(chat_id),
    )


def build_wallet_export_text(chat_id: int, pin: str, limit: int = BATCH_WALLET_COUNT) -> tuple[str | None, str]:
    """Готовит текстовый экспорт последних кошельков. Секреты раскрываются только после PIN."""
    if not chat_has_pin(chat_id):
        return None, "🔐 Сначала установи PIN. Без PIN seed/WIF не сохраняются и экспортировать их нельзя."
    if not verify_chat_pin(chat_id, pin):
        return None, "❌ Неверный PIN."

    items = (history.get(str(chat_id)) or [])[-limit:]
    if not items:
        return None, "История пуста — сначала создай пакет кошельков."

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "BTC Wallet Bot — экспорт последних кошельков",
        f"Дата экспорта: {now}",
        f"Количество записей: {len(items)}",
        "",
        "ВНИМАНИЕ: seed-фраза и WIF дают полный доступ к кошельку. Храни файл офлайн и никому не отправляй.",
        "",
    ]

    exported_secrets = 0
    for idx, item in enumerate(items, start=1):
        lines.append(f"#{idx}")
        lines.append(f"date: {item.get('date', '?')}")
        lines.append(f"type: {item.get('type', '?')}")
        lines.append(f"address: {item.get('address', '?')}")
        lines.append(f"balance: {item.get('balance', '?')}")
        lines.append(f"checksum_ok: {item.get('checksum_ok', '?')}")

        token = item.get("secret")
        if token:
            try:
                secret_data = decrypt_json(str(token))
                mnemonic_value = secret_data.get("mnemonic", "?")
                wif_value = secret_data.get("wif", "?")
                derivation_path = secret_data.get("derivation_path", item.get("derivation_path", DERIVATION_PATH))
                index_value = secret_data.get("index", item.get("index"))
                lines.append(f"mnemonic: {mnemonic_value}")
                lines.append(f"wif: {wif_value}")
                lines.append(f"derivation_path: {derivation_path}")
                if index_value is not None:
                    lines.append(f"index: {index_value}")
                exported_secrets += 1
            except (InvalidToken, Exception):
                lines.append("mnemonic: НЕ УДАЛОСЬ РАСШИФРОВАТЬ")
                lines.append("wif: НЕ УДАЛОСЬ РАСШИФРОВАТЬ")
        else:
            lines.append("mnemonic: НЕ СОХРАНЕНО — PIN не был установлен при создании")
            lines.append("wif: НЕ СОХРАНЕНО — PIN не был установлен при создании")
        lines.append("")

    lines.append(f"Расшифровано seed/WIF: {exported_secrets} из {len(items)}")
    return "\n".join(lines), ""


def request_export_all_pin(message) -> None:
    if not chat_has_pin(message.chat.id):
        return ask_set_pin(message)
    sent = bot.send_message(
        message.chat.id,
        f"🔐 Введи PIN-код из {PIN_LEN} цифр, чтобы вывести последние {BATCH_WALLET_COUNT} кошельков прямо сообщениями в Telegram:",
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
    export_text, error_text = build_wallet_export_text(message.chat.id, pin)
    if error_text:
        bot.send_message(message.chat.id, error_text, reply_markup=main_keyboard(message.chat.id))
        return

    export_count = min(BATCH_WALLET_COUNT, len(history.get(str(message.chat.id)) or []))
    chunks = split_text_for_telegram(export_text)
    bot.send_message(
        message.chat.id,
        f"📋 Экспорт готов: последние {export_count} кошельков. Отправляю текстом в Telegram: {len(chunks)} частей.\n"
        "⚠️ В сообщениях будут seed-фразы и WIF. Копируй и храни их офлайн.",
        reply_markup=main_keyboard(message.chat.id),
    )
    for index, chunk in enumerate(chunks, start=1):
        header = f"📋 Копировать всё — часть {index}/{len(chunks)}\n\n"
        bot.send_message(
            message.chat.id,
            header + chunk,
            parse_mode=None,
            disable_web_page_preview=True,
        )
        time.sleep(0.15)
    bot.send_message(message.chat.id, "✅ Экспорт в чат завершён.", reply_markup=main_keyboard(message.chat.id))


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
    bot.send_message(
        message.chat.id,
        "✅ PIN установлен. Теперь новые кошельки будут сохраняться в историю вместе со словами/WIF.\n\n"
        "⚠️ 5 цифр — слабая защита. Не храни там кошельки с деньгами.",
        reply_markup=main_keyboard(message.chat.id),
    )


def ask_set_pin(message) -> None:
    bot.send_message(
        message.chat.id,
        "🔐 Для истории с ключами задай PIN из 5 цифр:\n<code>/set_pin 12345</code>\n\n"
        "После установки PIN бот будет сохранять в историю: слова, адрес, WIF, баланс.",
        reply_markup=main_keyboard(message.chat.id),
    )


def request_history_pin(message) -> None:
    if not chat_has_pin(message.chat.id):
        return ask_set_pin(message)
    sent = bot.send_message(message.chat.id, "🔐 Введи PIN-код из 5 цифр для просмотра истории:")
    bot.register_next_step_handler(sent, show_history_after_pin)


def show_history_after_pin(message) -> None:
    pin = (message.text or "").strip()
    if not verify_chat_pin(message.chat.id, pin):
        bot.send_message(message.chat.id, "❌ Неверный PIN.", reply_markup=main_keyboard(message.chat.id))
        return
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
        f"✅ /scan1000 проверяет первые {BATCH_WALLET_COUNT} адресов из твоей seed-фразы для восстановления (/scan100 тоже работает).\n"
        f"✅ Кнопка 📋 Копировать всё выводит последние {BATCH_WALLET_COUNT} кошельков сообщениями в Telegram после PIN.\n\n"
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
        f"• ⚙️ Пакет: ВКЛ/ВЫКЛ — когда включено, 🎲 12 слов и 🎲 24 слова создают сразу {BATCH_WALLET_COUNT} кошельков без автосканирования баланса\n"
        f"• 📋 Копировать всё — после PIN вывести в Telegram последние {BATCH_WALLET_COUNT} кошельков/seed/WIF\n"
        f"• /scan1000 seed words — проверить первые {BATCH_WALLET_COUNT} адресов из твоей seed-фразы (/scan100 тоже работает)\n"
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


@bot.message_handler(commands=["scan100", "scan1000"])
def scan100_cmd(message):
    parts = (message.text or "").strip().split(maxsplit=1)
    if len(parts) != 2:
        bot.send_message(
            message.chat.id,
            "🔎 Проверка своих адресов:\n"
            "<code>/scan1000 word1 word2 ... word12</code>\n"
            "или старый алиас: <code>/scan100 word1 word2 ... word12</code>\n\n"
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
            "⚠️ BIP39 checksum у фразы неверный. Для scan100 нужна корректная seed-фраза от твоего кошелька.",
            reply_markup=main_keyboard(message.chat.id),
        )
        return
    scan_owned_mnemonic_100(message.chat.id, mnemonic_phrase)


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
            f"Когда режим включён, кнопки 🎲 12 слов и 🎲 24 слова создают сразу {BATCH_WALLET_COUNT} новых кошельков и сохраняют их в PIN-историю.",
            reply_markup=main_keyboard(message.chat.id),
        )

    if text in {"🎲 12 слов", "🎲 Случайный 12", "12 слов"}:
        if is_batch_enabled(message.chat.id):
            return process_batch_wallets(message.chat.id, "Random 12")
        mnemonic_phrase = mnemo.generate(strength=128)
        return process_mnemonic(message.chat.id, mnemonic_phrase, True, source_type="Random 12")

    if text in {"🎲 24 слова", "🎲 Случайный 24", "24 слова"}:
        if is_batch_enabled(message.chat.id):
            return process_batch_wallets(message.chat.id, "Random 24")
        mnemonic_phrase = mnemo.generate(strength=256)
        return process_mnemonic(message.chat.id, mnemonic_phrase, True, source_type="Random 24")

    if text in {"🎯 Рандом12 одинаковые", "рандом12", "random12"}:
        mnemonic_phrase = same_word_mnemonic(12)
        return process_mnemonic(message.chat.id, mnemonic_phrase, True, source_type="SameWord 12")

    if text in {"🎯 Рандом24 одинаковые", "рандом24", "random24"}:
        mnemonic_phrase = same_word_mnemonic(24)
        return process_mnemonic(message.chat.id, mnemonic_phrase, True, source_type="SameWord 24")

    if text == "📜 История":
        return request_history_pin(message)

    if text == "🔐 Установить PIN":
        return ask_set_pin(message)

    if text == "🔄 Баланс последнего":
        return refresh_last_balance(message.chat.id)

    if text in {"📋 Копировать всё", "копировать всё", "copy all", "export100", "export1000"}:
        return request_export_all_pin(message)

    if text.startswith("💰 Положительный баланс"):
        return show_session_positive_wallets(message.chat.id)

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

        checksum_line = "✅ BIP39 checksum: OK" if checksum_ok else "⚠️ BIP39 checksum: неверный, но адрес создан из введённых слов"
        save_line = (
            "🔐 История: слова/WIF сохранены, просмотр только по PIN."
            if secrets_saved
            else "⚠️ PIN не установлен — в историю сохранены только адрес и баланс. Нажми 🔐 Установить PIN."
        )
        bot.send_message(
            chat_id,
            "✅ <b>Кошелёк создан!</b>\n\n"
            f"📝 Слова:\n{code(mnemonic_phrase)}\n\n"
            f"🏠 Адрес P2PKH:\n{code(address)}\n\n"
            f"🔑 WIF:\n{code(wif)}\n\n"
            f"📍 Derivation path: {code(DERIVATION_PATH)}\n"
            f"{esc(checksum_line)}\n"
            f"💰 Баланс: <b>{esc(balance)}</b>\n\n"
            f"{esc(save_line)}\n"
            "⚠️ Фразы из одинаковых слов крайне небезопасны. Не пополняй такие кошельки.",
            reply_markup=main_keyboard(chat_id),
        )
    except Exception as e:
        bot.send_message(chat_id, f"❌ Ошибка создания: {code(str(e))}", reply_markup=main_keyboard(chat_id))


def show_history(chat_id: int, include_secrets: bool = False):
    items = history.get(str(chat_id)) or []
    if not items:
        return bot.send_message(chat_id, "История пуста.", reply_markup=main_keyboard(chat_id))

    lines = ["📜 <b>Последние кошельки:</b>", ""]
    for index, w in enumerate(reversed(items[-10:]), start=1):
        checksum = "OK" if w.get("checksum_ok", True) else "WARN"
        lines.append(f"<b>#{index}</b> {esc(w.get('date', '?'))} | {esc(w.get('type', '?'))} | checksum {checksum}")
        lines.append(f"🏠 {code(w.get('address', '?'))}")
        lines.append(f"💰 {esc(w.get('balance', '?'))}")
        if include_secrets:
            token = w.get("secret")
            if token:
                try:
                    secret_data = decrypt_json(str(token))
                    lines.append(f"📝 {code(secret_data.get('mnemonic', '?'))}")
                    lines.append(f"🔑 WIF: {code(secret_data.get('wif', '?'))}")
                    lines.append(f"📍 {code(secret_data.get('derivation_path', DERIVATION_PATH))}")
                except (InvalidToken, Exception):
                    lines.append("⚠️ Ключи не удалось расшифровать.")
            else:
                lines.append("⚠️ В этой старой записи ключи не сохранены: PIN тогда не был установлен.")
        lines.append("")
    bot.send_message(chat_id, "\n".join(lines), reply_markup=main_keyboard(chat_id))


if __name__ == "__main__":
    print(f"🤖 Бот запущен. History: {HISTORY_FILE}", flush=True)
    try:
        bot.remove_webhook()
    except Exception:
        pass
    bot.infinity_polling(skip_pending=True, timeout=30, long_polling_timeout=30)
