import os
import telebot
from telebot import types
import json
from datetime import datetime
import requests
from mnemonic import Mnemonic
from hdwallet import HDWallet
from hdwallet.cryptocurrencies import Bitcoin

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
bip39_words = set(mnemo.wordlist)

def get_balance(address: str) -> str:
    try:
        r = requests.get(f"https://api.blockchair.com/bitcoin/dashboards/address/{address}", timeout=10)
        if r.status_code == 200:
            bal = r.json().get("data", {}).get(address, {}).get("address", {}).get("balance", 0)
            return f"{bal / 100000000:.8f} BTC"
    except:
        pass
    return "Не удалось получить баланс"

def save_history():
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history, f, ensure_ascii=False, indent=2)

@bot.message_handler(commands=['start'])
def start(message):
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    markup.add("🎲 12 слов", "🎲 24 слова")
    markup.add("📝 Ввести mnemonic", "📜 История")
    bot.send_message(message.chat.id, "👋 Bitcoin Wallet Bot\n\nПовторения разрешены ✅", reply_markup=markup)

@bot.message_handler(func=lambda m: True)
def handle(message):
    text = message.text.strip()
    if text in ["🎲 12 слов", "🎲 Случайный 12"]:
        mnemonic = mnemo.generate(strength=128)
        process_mnemonic(message.chat.id, mnemonic, True)
    elif text in ["🎲 24 слова", "🎲 Случайный 24"]:
        mnemonic = mnemo.generate(strength=256)
        process_mnemonic(message.chat.id, mnemonic, True)
    elif text == "📜 История":
        show_history(message.chat.id)
    elif text == "📝 Ввести mnemonic":
        bot.send_message(message.chat.id, "Отправь 12 или 24 слова (повторения разрешены):")
    else:
        words = text.split()
        if len(words) not in (12, 24):
            return bot.reply_to(message, "❌ Должно быть 12 или 24 слова!")
        
        # Проверка только по словарю (повторения ОК)
        invalid = [w for w in words if w.lower() not in bip39_words]
        if invalid:
            return bot.reply_to(message, f"❌ Неизвестные слова: {invalid[:3]}...\nИспользуй только из BIP39.")
        
        mnemonic = " ".join(words)
        process_mnemonic(message.chat.id, mnemonic, False)

def process_mnemonic(chat_id, mnemonic, is_random):
    try:
        wallet = HDWallet(cryptocurrency=Bitcoin)
        wallet.from_mnemonic(mnemonic)
        
        address = wallet.p2pkh_address()
        wif = wallet.wif()
        balance = get_balance(address)

        if str(chat_id) not in history:
            history[str(chat_id)] = []
        history[str(chat_id)].append({
            "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "type": "Random" if is_random else "Custom",
            "mnemonic": mnemonic,
            "address": address,
            "wif": wif,
            "balance": balance
        })
        save_history()

        bot.send_message(chat_id, f"""
✅ Кошелёк создан!

📝 Слова:
`{mnemonic}`

🏠 Адрес:
`{address}`

🔑 WIF:
`{wif}`

💰 Баланс: {balance}
""", parse_mode="Markdown")
    except Exception as e:
        bot.send_message(chat_id, f"❌ Ошибка создания: {str(e)}")

def show_history(chat_id):
    if not history.get(str(chat_id)):
        return bot.send_message(chat_id, "История пуста.")
    txt = "📜 Последние кошельки:\n\n"
    for w in reversed(history[str(chat_id)][-5:]):
        txt += f"{w['date']} | {w['type']}\n`{w['address']}` | {w['balance']}\n\n"
    bot.send_message(chat_id, txt, parse_mode="Markdown")

print("🤖 Бот запущен")
bot.infinity_polling()