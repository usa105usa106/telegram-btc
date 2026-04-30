import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import time
import unicodedata
from datetime import datetime
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

DERIVATION_PATH = "m/44'/0'/0'/0/0"
MAX_HISTORY_PER_CHAT = 50
PIN_LEN = 5
PIN_HASH_ITERATIONS = 240_000

bot = telebot.TeleBot(TOKEN, parse_mode="HTML")
mnemo = Mnemonic("english")
bip39_words = set(mnemo.wordlist)


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


history: dict[str, list[dict[str, Any]]] = load_history()
pin_data: dict[str, dict[str, str]] = load_pin_data()


def save_history() -> None:
    save_json_file(HISTORY_FILE, history)


def save_pin_data() -> None:
    save_json_file(PIN_FILE, pin_data)


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


def derive_bitcoin_wallet(mnemonic_phrase: str) -> Tuple[str, str]:
    seed = mnemonic_to_seed(mnemonic_phrase)
    ctx = (
        Bip44.FromSeed(seed, Bip44Coins.BITCOIN)
        .Purpose()
        .Coin()
        .Account(0)
        .Change(Bip44Changes.CHAIN_EXT)
        .AddressIndex(0)
    )
    address = ctx.PublicKey().ToAddress()
    private_key = ctx.PrivateKey().Raw().ToBytes()
    wif = private_key_to_wif(private_key, compressed=True)
    return address, wif


def same_word_mnemonic(word_count: int) -> str:
    word = secrets.choice(mnemo.wordlist)
    return " ".join([word] * word_count)


# ---------- bot ui ----------

def main_keyboard() -> types.ReplyKeyboardMarkup:
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    markup.add("🎲 12 слов", "🎲 24 слова")
    markup.add("🎯 Рандом12 одинаковые", "🎯 Рандом24 одинаковые")
    markup.add("📝 Ввести mnemonic", "📜 История")
    markup.add("🔐 Установить PIN", "🔄 Баланс последнего")
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
        bot.send_message(chat_id, "История пуста — сначала создай кошелёк.", reply_markup=main_keyboard())
        return
    last = items[-1]
    address = str(last.get("address") or "")
    if not address:
        bot.send_message(chat_id, "В последней записи нет адреса.", reply_markup=main_keyboard())
        return
    balance = get_balance(address)
    last["balance"] = balance
    last["balance_checked_at"] = datetime.now().strftime("%Y-%m-%d %H:%M")
    save_history()
    bot.send_message(
        chat_id,
        "🔄 <b>Баланс обновлён</b>\n\n"
        f"🏠 Адрес:\n{code(address)}\n\n"
        f"💰 Баланс: <b>{esc(balance)}</b>",
        reply_markup=main_keyboard(),
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


# ---------- PIN handlers ----------

@bot.message_handler(commands=["set_pin"])
def set_pin_cmd(message):
    parts = (message.text or "").strip().split(maxsplit=1)
    if len(parts) != 2:
        bot.send_message(
            message.chat.id,
            "🔐 Отправь PIN командой:\n<code>/set_pin 12345</code>\n\nPIN должен быть ровно 5 цифр.",
            reply_markup=main_keyboard(),
        )
        return
    pin = parts[1].strip()
    if not pin_is_valid_format(pin):
        bot.send_message(message.chat.id, "❌ PIN должен быть ровно 5 цифр.", reply_markup=main_keyboard())
        return
    set_chat_pin(message.chat.id, pin)
    bot.send_message(
        message.chat.id,
        "✅ PIN установлен. Теперь новые кошельки будут сохраняться в историю вместе со словами/WIF.\n\n"
        "⚠️ 5 цифр — слабая защита. Не храни там кошельки с деньгами.",
        reply_markup=main_keyboard(),
    )


def ask_set_pin(message) -> None:
    bot.send_message(
        message.chat.id,
        "🔐 Для истории с ключами задай PIN из 5 цифр:\n<code>/set_pin 12345</code>\n\n"
        "После установки PIN бот будет сохранять в историю: слова, адрес, WIF, баланс.",
        reply_markup=main_keyboard(),
    )


def request_history_pin(message) -> None:
    if not chat_has_pin(message.chat.id):
        return ask_set_pin(message)
    sent = bot.send_message(message.chat.id, "🔐 Введи PIN-код из 5 цифр для просмотра истории:")
    bot.register_next_step_handler(sent, show_history_after_pin)


def show_history_after_pin(message) -> None:
    pin = (message.text or "").strip()
    if not verify_chat_pin(message.chat.id, pin):
        bot.send_message(message.chat.id, "❌ Неверный PIN.", reply_markup=main_keyboard())
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
        "✅ История с ключами открывается только по PIN из 5 цифр.\n\n"
        "⚠️ Фразы из одинаковых слов небезопасны и подходят только для тестов/экспериментов.",
        reply_markup=main_keyboard(),
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
        "• /set_pin 12345 — задать PIN из 5 цифр\n\n"
        f"Путь деривации: {code(DERIVATION_PATH)}\n"
        f"Файл истории: {code(HISTORY_FILE)}",
        reply_markup=main_keyboard(),
    )


@bot.message_handler(func=lambda m: True)
def handle(message):
    text = (message.text or "").strip()
    if not text:
        return bot.reply_to(message, "Отправь текст или выбери кнопку.", reply_markup=main_keyboard())

    if text in {"🎲 12 слов", "🎲 Случайный 12", "12 слов"}:
        mnemonic_phrase = mnemo.generate(strength=128)
        return process_mnemonic(message.chat.id, mnemonic_phrase, True, source_type="Random 12")

    if text in {"🎲 24 слова", "🎲 Случайный 24", "24 слова"}:
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

    if text == "📝 Ввести mnemonic":
        return bot.send_message(
            message.chat.id,
            "Отправь 12 или 24 слова из BIP39 через пробел.\n"
            "Повторения разрешены. Если checksum неверный — будет предупреждение, но бот продолжит.",
            reply_markup=main_keyboard(),
        )

    mnemonic_phrase = normalize_mnemonic(text)
    ok, error_text, checksum_ok = validate_mnemonic_words(mnemonic_phrase)
    if not ok:
        return bot.reply_to(message, error_text, reply_markup=main_keyboard())

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
            reply_markup=main_keyboard(),
        )
    except Exception as e:
        bot.send_message(chat_id, f"❌ Ошибка создания: {code(str(e))}", reply_markup=main_keyboard())


def show_history(chat_id: int, include_secrets: bool = False):
    items = history.get(str(chat_id)) or []
    if not items:
        return bot.send_message(chat_id, "История пуста.", reply_markup=main_keyboard())

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
    bot.send_message(chat_id, "\n".join(lines), reply_markup=main_keyboard())


if __name__ == "__main__":
    print(f"🤖 Бот запущен. History: {HISTORY_FILE}", flush=True)
    try:
        bot.remove_webhook()
    except Exception:
        pass
    bot.infinity_polling(skip_pending=True, timeout=30, long_polling_timeout=30)
