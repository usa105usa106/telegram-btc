import os
import telebot
from telebot import types
import json
from datetime import datetime
import requests
from mnemonic import Mnemonic
from hdwallet import HDWallet
from hdwallet.cryptocurrencies import Bitcoin as BTC  # ← переименовали

TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
if not TOKEN:
    raise ValueError("❌ TELEGRAM_BOT_TOKEN не установлен!")

bot = telebot.TeleBot(TOKEN)
HISTORY_FILE = "wallets_history.json"

if os.path.exists(HISTORY_FILE):
    with open(HISTORY_FILE, "r", encoding="utf-8") as f:
        history = json.load(f)
else:
    history = {}

mnemo = Mnemonic("english")

def get_balance(address: str) -> str:
    try:
        r = requests.get(f"https://api.blockchair.com/bitcoin/dashboards/address/{address}?limit=0", timeout=10)
        if r.status_code == 200:
            bal = r.json().get("data", {}).get(address, {}).get("address", {}).get("balance", 0)
            return f"{bal / 100000000:.8f} BTC"
        return "API error"
    except:
        return "Не удалось получить баланс"

def save_history():
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history, f, ensure_ascii=False, indent=2)

@bot.message_handler(commands=['start'])
def start(message):
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    markup.add("🎲 12 слов", "🎲 24 слова")
    markup.add("📝 Ввести mnemonic", "📜 История")
    bot.send_message(message.chat.id,
        "👋 Bitcoin Wallet Bot\n\n✅ Работает на Railway\n⚠️ Никому не показывай приватные ключи!",
        reply_markup=markup)

def generate_random_mnemonic(strength=128):
    return mnemo.generate(strength=strength)

@bot.message_handler(func=lambda m: True)
def handle(message):
    text = message.text.strip()
    if text in ["🎲 12 слов", "🎲 Случайный 12"]:
        mnemonic = generate_random_mnemonic(128)
        process_mnemonic(message.chat.id, mnemonic, True)
    elif text in ["🎲 24 слова", "🎲 Случайный 24"]:
        mnemonic = generate_random_mnemonic(256)
        process_mnemonic(message.chat.id, mnemonic, True)
    elif text == "📜 История":
        show_history(message.chat.id)
    elif text == "📝 Ввести mnemonic":
        bot.send_message(message.chat.id, "Отправь 12 или 24 слова через пробел:")
    else:
        words = text.split()
        if len(words) not in (12, 24):
            bot.reply_to(message, "❌ Должно быть ровно 12 или 24 слова!")
            return
        mnemonic = " ".join(words)
        if not mnemo.check(mnemonic):
            bot.reply_to(message, "❌ Некоторые слова не из BIP39!")
            return
        process_mnemonic(message.chat.id, mnemonic, False)

def process_mnemonic(chat_id, mnemonic, is_random):
    try:
        # Исправленная инициализация
        wallet = HDWallet(cryptocurrency=BTC)
        wallet.from_mnemonic(mnemonic=mnemonic)
        
        address = wallet.p2pkh_address()
        wif = wallet.wif()
        balance = get_balance(address)

        if str(chat_id) not in history:
            history[str(chat_id)] = []
        
        history[str(chat_id)].append({
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": "Random" if is_random else "Custom",
            "mnemonic": mnemonic,
            "address": address,
            "wif": wif,
            "balance": balance
        })
        save_history()

        bot.send_message(chat_id, f"""
✅ Кошелёк успешно создан!

📝 Mnemonic ({len(mnemonic.split())} слов):
`{mnemonic}`

🏠 Адрес (P2PKH):
`{address}`

🔑 WIF Private Key:
`{wif}`

💰 Баланс: {balance}
        """, parse_mode="Markdown")
    except Exception as e:
        bot.send_message(chat_id, f"❌ Ошибка: {str(e)}")

def show_history(chat_id):
    if str(chat_id) not in history or not history[str(chat_id)]:
        bot.send_message(chat_id, "📭 История пуста.")
        return
    text = "📜 Последние 10 кошельков:\n\n"
    for item in reversed(history[str(chat_id)][-10:]):
        text += f"{item['date']} — {item['type']}\n`{item['address']}` — {item['balance']}\n\n"
    bot.send_message(chat_id, text, parse_mode="Markdown")

print("🤖 Бот успешно запущен...")
bot.infinity_polling()