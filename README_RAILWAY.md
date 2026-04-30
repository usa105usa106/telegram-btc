# BTC Wallet Bot — same-word generators + PIN history

Railway-версия Telegram-бота для генерации Bitcoin P2PKH кошельков.

## Что добавлено

- Обычные кнопки генерации: `🎲 12 слов`, `🎲 24 слова`.
- Новые кнопки:
  - `🎯 Рандом12 одинаковые` — бот выбирает 1 случайное слово из BIP39-списка 2048 слов и делает фразу из 12 одинаковых слов.
  - `🎯 Рандом24 одинаковые` — аналогично, но 24 одинаковых слова.
- История с PIN:
  - `🔐 Установить PIN` или команда `/set_pin 12345`.
  - PIN должен быть ровно 5 цифр.
  - `📜 История` всегда просит PIN перед показом истории.
  - После установки PIN новые записи истории сохраняют адрес, баланс, mnemonic, WIF и derivation path.
- Баланс проверяется через Blockstream, mempool.space и BlockCypher.

## Важно по безопасности

Фразы из одинаковых слов крайне небезопасны. Не переводите реальные деньги на такие кошельки.

PIN из 5 цифр защищает просмотр истории в Telegram. Секреты в файле истории шифруются Fernet-ключом, который хранится в `history_secret.key` или может быть задан через Railway Variable `HISTORY_SECRET_KEY`.

Если потерять `history_secret.key` или `HISTORY_SECRET_KEY`, старые сохранённые WIF/mnemonic из истории расшифровать не получится.

## Railway Variables

Минимально:

```env
TELEGRAM_BOT_TOKEN=123456:ABCDEF
```

Опционально:

```env
DATA_DIR=/data
HISTORY_SECRET_KEY=base64_fernet_key
```

Для постоянного хранения подключи Railway Volume и mount path `/data`.

## Запуск

Railway использует:

```bash
worker: python bot.py
```

## Команды

- `/start`
- `/help`
- `/set_pin 12345`
