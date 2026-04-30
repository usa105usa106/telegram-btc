# ETH/BTC AutoTrade AI Telegram Bot

Telegram bot for BTC/ETH futures signals and optional auto-trading.

**Important:** this bot cannot guarantee profit. Crypto futures are high-risk. Start with PAPER mode and small risk. LIVE mode is locked behind `/arm_live`.

## Features

- BTC/ETH only.
- Two strategy profiles:
  - **Scalp**: 5m base + 15m/1h confirmations, up to 10 trades/hour.
  - **Swing**: 1h base + 4h/1d confirmations, 1–2 trades/day.
- Multi-factor scoring: EMA trend, RSI, MACD momentum, ATR volatility, volume, slope, Bollinger z-score, multi-timeframe confirmation, funding-rate penalty.
- Online self-learning model: separate logistic profiles for symbol/mode/side; learns from closed TP/SL results.
- Modes: OFF, PAPER, LIVE.
- LIVE safety gate: `/arm_live` required before real orders.
- Position sizing by risk percent, daily loss limit, cooldowns, per-hour/per-day trade limits.
- Exchange access through CCXT: MEXC, BingX, Bybit, Binance.
- Telegram API settings via `/api_set`, or safer via Railway Variables.
- `/backtest` runs a simplified backtest on recent exchange candles.

## Railway deploy

1. Create Telegram bot with BotFather.
2. Create Railway project from this repository.
3. Add variables:

```env
BOT_TOKEN=123456:telegram-token
ADMIN_IDS=123456789
```

Optional API variables, safer than sending keys in chat:

```env
EXCHANGE_ID=mexc
EXCHANGE_API_KEY=...
EXCHANGE_API_SECRET=...
EXCHANGE_API_PASSWORD=
```

4. Add a Railway Volume if you want persistent settings/model/trade history.
5. Deploy. Start command is in `railway.json` and `Procfile`.

## First launch

In Telegram:

```text
/start
/status
/backtest
/scan
```

Switch modes:

```text
/mode scalp
/mode swing
/trade_mode paper
/risk 0.35
/leverage 2
```

Enable/disable auto entries in `/settings` using the inline button.

## LIVE mode

LIVE is intentionally hard to enable:

```text
/api_set mexc KEY SECRET
/trade_mode live
/arm_live
```

Then turn on autotrade in `/settings`.

To lock LIVE again:

```text
/disarm_live
/trade_mode off
```

## Notes

- CCXT exchange support differs by exchange. Protective orders are best-effort and also monitored locally by the bot loop.
- Keep one polling instance per bot token. Do not run multiple Railway replicas with the same Telegram token.
- Backtest is simplified and does not prove future profitability.


## Если пишет «Только админ»

1. В Telegram отправь боту `/myid`.
2. Скопируй число из строки `Твой Telegram ID`.
3. В Railway Variables добавь или исправь:

```env
ADMIN_IDS=твой_id_без_пробелов
```

Поддерживаются также `ADMIN_ID`, `TELEGRAM_ADMIN_IDS`, `TELEGRAM_ADMIN_ID`, а разделители могут быть запятая, пробел или новая строка.

Если `ADMIN_IDS` не задан, первый пользователь, который нажмёт `/start`, автоматически станет админом и ID сохранится в `state.json`.

Полностью отключить проверку админа можно так:

```env
ADMIN_REQUIRED=false
```

Для LIVE-торговли лучше не отключать проверку админа.


## Важно: токен Telegram

Если Railway Logs пишет `BOT_TOKEN / TELEGRAM_BOT_TOKEN не задан` или `Не задан токен Telegram-бота`, значит в сервисе не добавлена переменная с токеном от @BotFather.

В Railway открой **Service → Variables** и добавь ровно одну из переменных:

```env
BOT_TOKEN=1234567890:AA...
```

Также бот принимает алиасы: `TELEGRAM_BOT_TOKEN`, `TELEGRAM_TOKEN`, `TG_BOT_TOKEN`, `TOKEN`.

После добавления переменной нажми **Redeploy** или перезапусти сервис.
