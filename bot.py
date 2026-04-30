import hashlib
import html
import json
import os
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


TOKEN = os.getenv("TELEGRAM_BOT_TOKEN") or os.getenv("BOT_TOKEN")
if not TOKEN:
    raise RuntimeError("TELEGRAM_BOT_TOKEN или BOT_TOKEN не установлен в Railway Variables")

# Railway volume: если подключишь Volume, укажи mount path /data.
# Бот сам возьмёт RAILWAY_VOLUME_MOUNT_PATH, а если его нет — будет писать рядом с bot.py.
DATA_DIR = Path(os.getenv("RAILWAY_VOLUME_MOUNT_PATH") or os.getenv("DATA_DIR") or ".").resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)
HISTORY_FILE = Path(os.getenv("HISTORY_FILE") or (DATA_DIR / "wallets_history.json"))

DERIVATION_PATH = "m/44'/0'/0'/0/0"
MAX_HISTORY_PER_CHAT = 20

bot = telebot.TeleBot(TOKEN, parse_mode="HTML")
mnemo = Mnemonic("english")
bip39_words = set(mnemo.wordlist)


# ---------- storage ----------

def load_history() -> dict[str, list[dict[str, Any]]]:
    if not HISTORY_FILE.exists():
        return {}
    try:
        with HISTORY_FILE.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


history: dict[str, list[dict[str, Any]]] = load_history()


def save_history() -> None:
    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = HISTORY_FILE.with_suffix(HISTORY_FILE.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(history, f, ensure_ascii=False, indent=2)
    tmp.replace(HISTORY_FILE)


def sanitize_history() -> None:
    """Не храним приватные данные на диске."""
    changed = False
    for chat_id, items in list(history.items()):
        if not isinstance(items, list):
            history[chat_id] = []
            changed = True
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            for secret_key in ("mnemonic", "wif", "private_key", "seed"):
                if secret_key in item:
                    item.pop(secret_key, None)
                    changed = True
    if changed:
        save_history()


sanitize_history()


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


# ---------- bot ui ----------

def main_keyboard() -> types.ReplyKeyboardMarkup:
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    markup.add("🎲 12 слов", "🎲 24 слова")
    markup.add("📝 Ввести mnemonic", "📜 История")
    markup.add("🔄 Баланс последнего")
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
        "User-Agent": "BTC-Wallet-Telegram-Bot/2.0",
        "Accept": "application/json",
    }
    providers = [
        ("Blockstream", f"https://blockstream.info/api/address/{address}", _balance_from_esplora_payload),
        ("mempool.space", f"https://mempool.space/api/address/{address}", _balance_from_esplora_payload),
    ]
    errors: list[str] = []
    for name, url, parser in providers:
        try:
            r = requests.get(url, timeout=15, headers=headers)
            if r.status_code == 200:
                sat = parser(r.json())
                return f"{sat / 100000000:.8f} BTC"
            if r.status_code in {429, 430, 503}:
                errors.append(f"{name}: лимит/временно недоступно HTTP {r.status_code}")
                time.sleep(0.7)
            else:
                errors.append(f"{name}: HTTP {r.status_code}")
        except Exception as exc:
            errors.append(f"{name}: {type(exc).__name__}")
    return "не удалось получить баланс: " + "; ".join(errors[:2])


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


@bot.message_handler(commands=["start"])
def start(message):
    bot.send_message(
        message.chat.id,
        "👋 <b>Bitcoin Wallet Bot</b>\n\n"
        "✅ Railway-версия готова.\n"
        "✅ Генерация 12/24 слов работает через long polling.\n"
        "✅ Повторения BIP39-слов разрешены. Если checksum неверный — бот покажет предупреждение, но всё равно создаст адрес.\n\n"
        "⚠️ Не вводи seed-фразы от кошельков, где уже есть деньги.",
        reply_markup=main_keyboard(),
    )


@bot.message_handler(commands=["help"])
def help_cmd(message):
    bot.send_message(
        message.chat.id,
        "<b>Команды:</b>\n"
        "• 🎲 12 слов — создать новую 12-word фразу\n"
        "• 🎲 24 слова — создать новую 24-word фразу\n"
        "• 📝 Ввести mnemonic — проверить/импортировать фразу\n"
        "• 📜 История — последние адреса без приватных ключей\n\n"
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
        return process_mnemonic(message.chat.id, mnemonic_phrase, True)

    if text in {"🎲 24 слова", "🎲 Случайный 24", "24 слова"}:
        mnemonic_phrase = mnemo.generate(strength=256)
        return process_mnemonic(message.chat.id, mnemonic_phrase, True)

    if text == "📜 История":
        return show_history(message.chat.id)

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

    return process_mnemonic(message.chat.id, mnemonic_phrase, False, checksum_ok=checksum_ok)


def process_mnemonic(chat_id: int, mnemonic_phrase: str, is_random: bool, checksum_ok: bool | None = None):
    try:
        if checksum_ok is None:
            checksum_ok = mnemo.check(mnemonic_phrase)
        address, wif = derive_bitcoin_wallet(mnemonic_phrase)
        balance = get_balance(address)

        chat_key = str(chat_id)
        history.setdefault(chat_key, [])
        history[chat_key].append({
            "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "type": "Random" if is_random else "Custom",
            "address": address,
            "balance": balance,
            "checksum_ok": bool(checksum_ok),
        })
        history[chat_key] = history[chat_key][-MAX_HISTORY_PER_CHAT:]
        save_history()

        checksum_line = "✅ BIP39 checksum: OK" if checksum_ok else "⚠️ BIP39 checksum: неверный, но адрес создан из введённых слов"
        bot.send_message(
            chat_id,
            "✅ <b>Кошелёк создан!</b>\n\n"
            f"📝 Слова:\n{code(mnemonic_phrase)}\n\n"
            f"🏠 Адрес P2PKH:\n{code(address)}\n\n"
            f"🔑 WIF:\n{code(wif)}\n\n"
            f"📍 Derivation path: {code(DERIVATION_PATH)}\n"
            f"{esc(checksum_line)}\n"
            f"💰 Баланс: <b>{esc(balance)}</b>\n\n"
            "⚠️ Сохрани слова и WIF сам. В историю бот записывает только адрес и баланс.",
            reply_markup=main_keyboard(),
        )
    except Exception as e:
        bot.send_message(chat_id, f"❌ Ошибка создания: {code(str(e))}", reply_markup=main_keyboard())


def show_history(chat_id: int):
    items = history.get(str(chat_id)) or []
    if not items:
        return bot.send_message(chat_id, "История пуста.", reply_markup=main_keyboard())

    lines = ["📜 <b>Последние кошельки:</b>", ""]
    for w in reversed(items[-5:]):
        checksum = "OK" if w.get("checksum_ok", True) else "WARN"
        lines.append(f"{esc(w.get('date', '?'))} | {esc(w.get('type', '?'))} | checksum {checksum}")
        lines.append(f"{code(w.get('address', '?'))} | {esc(w.get('balance', '?'))}")
        lines.append("")
    bot.send_message(chat_id, "\n".join(lines), reply_markup=main_keyboard())


if __name__ == "__main__":
    print(f"🤖 Бот запущен. History: {HISTORY_FILE}", flush=True)
    # Важно для Railway long polling: убрать старый webhook и не обрабатывать старые pending updates.
    try:
        bot.remove_webhook()
    except Exception:
        pass
    bot.infinity_polling(skip_pending=True, timeout=30, long_polling_timeout=30)
