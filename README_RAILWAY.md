# Bitcoin Wallet Bot — Railway repo

## Деплой на Railway

1. Залей эти файлы в GitHub-репозиторий.
2. В Railway создай новый проект из GitHub repo.
3. В `Variables` добавь:
   - `TELEGRAM_BOT_TOKEN` — токен от BotFather.
   - Можно вместо него использовать `BOT_TOKEN`.
4. Start command уже задан в `railway.json`: `python bot.py`.
5. Для сохранения истории между redeploy/restart подключи Railway Volume, например на `/data`, и добавь `DATA_DIR=/data`.

## Важно

- Бот работает через Telegram long polling, поэтому открытый HTTP-порт не нужен.
- Запускай только один инстанс бота с одним токеном, иначе Telegram polling будет конфликтовать.
- История хранит только адрес и баланс. Seed/mnemonic/WIF на диск не сохраняются.
- Повторения BIP39-слов разрешены. Если checksum неверный, бот покажет предупреждение, но адрес всё равно создаст из введённых слов.

## Локальный запуск

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export TELEGRAM_BOT_TOKEN="123456:token"
python bot.py
```
