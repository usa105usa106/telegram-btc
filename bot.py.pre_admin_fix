import asyncio
import html
import json
import logging
import math
import os
import time
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any, Optional

import ccxt.async_support as ccxt
from aiogram import Bot, Dispatcher, F
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.filters import Command, CommandObject, CommandStart
from aiogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, Message, ReplyKeyboardMarkup, KeyboardButton
from dotenv import load_dotenv

load_dotenv()

BOT_VERSION = "ETH/BTC AutoTrade AI v1.0.0"
BOT_TOKEN = os.getenv("BOT_TOKEN") or os.getenv("TELEGRAM_BOT_TOKEN") or ""
ADMIN_IDS = {int(x) for x in os.getenv("ADMIN_IDS", "").replace(" ", "").split(",") if x.lstrip("-").isdigit()}
DATA_DIR = Path(os.getenv("RAILWAY_VOLUME_MOUNT_PATH") or os.getenv("DATA_DIR") or "data")
DATA_DIR.mkdir(parents=True, exist_ok=True)
SETTINGS_FILE = DATA_DIR / "settings.json"
STATE_FILE = DATA_DIR / "state.json"
MODEL_FILE = DATA_DIR / "model_state.json"
API_FILE = DATA_DIR / "api_keys.json"
TRADE_LOG_FILE = DATA_DIR / "trade_log.jsonl"

SYMBOLS = ["BTC", "ETH"]
SUPPORTED_EXCHANGES = {"mexc", "bingx", "bybit", "binance"}

DEFAULT_SETTINGS: dict[str, Any] = {
    "exchange_id": os.getenv("EXCHANGE_ID", "mexc").lower(),
    "trade_mode": "paper",        # off, paper, live
    "strategy_mode": "scalp",     # scalp, swing
    "signals_enabled": True,
    "autotrade_enabled": False,    # даже paper/live не откроет сделку, пока этот флаг OFF
    "risk_per_trade_pct": 0.35,
    "max_daily_loss_pct": 2.0,
    "max_open_trades": 2,
    "leverage": 2,
    "account_equity_usdt": 100.0,  # для PAPER и расчёта риска
    "min_probability_scalp": 74,
    "min_probability_swing": 78,
    "loop_interval_sec": 45,
    "cooldown_scalp_min": 6,
    "cooldown_swing_min": 360,
    "max_trades_per_hour_scalp": 10,
    "max_trades_per_day_swing": 2,
    "use_neural_filter": True,
    "min_neural_probability": 52,
    "live_confirm_required": True,
    "protective_orders": True,
    "notify_no_signal": False,
}

MODE_PROFILES = {
    "scalp": {
        "base_tf": "5m",
        "confirm_tfs": ["15m", "1h"],
        "limit_base": 260,
        "limit_confirm": 220,
        "atr_sl": 1.05,
        "tp1_rr": 1.15,
        "tp2_rr": 1.75,
        "tp3_rr": 2.6,
        "trail_after_tp1_atr": 0.65,
        "max_hold_minutes": 95,
        "min_atr_pct": 0.08,
        "max_atr_pct": 2.8,
    },
    "swing": {
        "base_tf": "1h",
        "confirm_tfs": ["4h", "1d"],
        "limit_base": 420,
        "limit_confirm": 260,
        "atr_sl": 1.55,
        "tp1_rr": 1.7,
        "tp2_rr": 2.8,
        "tp3_rr": 4.2,
        "trail_after_tp1_atr": 1.2,
        "max_hold_minutes": 2880,
        "min_atr_pct": 0.25,
        "max_atr_pct": 6.5,
    },
}

bot: Optional[Bot] = None
dp = Dispatcher()

main_keyboard = ReplyKeyboardMarkup(
    keyboard=[
        [KeyboardButton(text="📊 Статус"), KeyboardButton(text="🔎 Скан")],
        [KeyboardButton(text="⚡ Скальп"), KeyboardButton(text="🧲 Свинг")],
        [KeyboardButton(text="🧪 PAPER"), KeyboardButton(text="🛑 OFF")],
        [KeyboardButton(text="🤖 AI/обучение"), KeyboardButton(text="📈 Бэктест")],
        [KeyboardButton(text="🔑 API"), KeyboardButton(text="⚙️ Настройки")],
    ],
    resize_keyboard=True,
)

# ---------------- storage ----------------

def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        logging.exception("Не удалось прочитать %s", path)
        return default


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def load_settings() -> dict[str, Any]:
    settings = dict(DEFAULT_SETTINGS)
    stored = load_json(SETTINGS_FILE, {})
    if isinstance(stored, dict):
        settings.update(stored)
    if settings["exchange_id"] not in SUPPORTED_EXCHANGES:
        settings["exchange_id"] = "mexc"
    if settings["trade_mode"] not in {"off", "paper", "live"}:
        settings["trade_mode"] = "paper"
    if settings["strategy_mode"] not in MODE_PROFILES:
        settings["strategy_mode"] = "scalp"
    settings["risk_per_trade_pct"] = clamp(float(settings.get("risk_per_trade_pct", 0.35)), 0.05, 2.0)
    settings["leverage"] = int(clamp(int(settings.get("leverage", 2)), 1, 10))
    settings["account_equity_usdt"] = max(10.0, float(settings.get("account_equity_usdt", 100.0)))
    return settings


def save_settings(settings: dict[str, Any]) -> None:
    save_json(SETTINGS_FILE, settings)


def load_state() -> dict[str, Any]:
    state = load_json(STATE_FILE, {})
    if not isinstance(state, dict):
        state = {}
    state.setdefault("subscribers", [])
    state.setdefault("open_trades", [])
    state.setdefault("last_signal_ts", {})
    state.setdefault("daily", {})
    state.setdefault("live_armed", False)
    return state


def save_state(state: dict[str, Any]) -> None:
    save_json(STATE_FILE, state)


def today_key() -> str:
    return time.strftime("%Y-%m-%d", time.gmtime())


def is_admin(message_or_user_id: Any) -> bool:
    if isinstance(message_or_user_id, int):
        uid = message_or_user_id
    else:
        uid = getattr(getattr(message_or_user_id, "from_user", None), "id", None)
    return bool(uid and uid in ADMIN_IDS)


def clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def fmt_price(value: float) -> str:
    if value >= 1000:
        return f"{value:,.2f}".replace(",", " ")
    if value >= 10:
        return f"{value:.3f}"
    return f"{value:.5f}"


def pct(a: float, b: float) -> float:
    return (b - a) / a * 100.0 if a else 0.0

# ---------------- indicators ----------------

def ema(values: list[float], period: int) -> list[float]:
    if not values:
        return []
    k = 2.0 / (period + 1)
    out = [values[0]]
    for v in values[1:]:
        out.append(v * k + out[-1] * (1 - k))
    return out


def sma(values: list[float], period: int) -> list[Optional[float]]:
    out: list[Optional[float]] = []
    s = 0.0
    for i, v in enumerate(values):
        s += v
        if i >= period:
            s -= values[i - period]
        out.append(s / period if i >= period - 1 else None)
    return out


def stdev(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    m = sum(values) / len(values)
    return math.sqrt(sum((x - m) ** 2 for x in values) / (len(values) - 1))


def rsi(values: list[float], period: int = 14) -> list[Optional[float]]:
    if len(values) < period + 1:
        return [None] * len(values)
    out: list[Optional[float]] = [None] * len(values)
    gains = []
    losses = []
    for i in range(1, period + 1):
        diff = values[i] - values[i - 1]
        gains.append(max(diff, 0))
        losses.append(max(-diff, 0))
    avg_gain = sum(gains) / period
    avg_loss = sum(losses) / period
    out[period] = 100.0 if avg_loss == 0 else 100 - 100 / (1 + avg_gain / avg_loss)
    for i in range(period + 1, len(values)):
        diff = values[i] - values[i - 1]
        avg_gain = (avg_gain * (period - 1) + max(diff, 0)) / period
        avg_loss = (avg_loss * (period - 1) + max(-diff, 0)) / period
        out[i] = 100.0 if avg_loss == 0 else 100 - 100 / (1 + avg_gain / avg_loss)
    return out


def atr(highs: list[float], lows: list[float], closes: list[float], period: int = 14) -> list[Optional[float]]:
    if not closes:
        return []
    trs = [highs[0] - lows[0]]
    for i in range(1, len(closes)):
        trs.append(max(highs[i] - lows[i], abs(highs[i] - closes[i - 1]), abs(lows[i] - closes[i - 1])))
    out: list[Optional[float]] = [None] * len(closes)
    if len(trs) < period:
        return out
    val = sum(trs[:period]) / period
    out[period - 1] = val
    for i in range(period, len(trs)):
        val = (val * (period - 1) + trs[i]) / period
        out[i] = val
    return out


def macd(values: list[float]) -> tuple[list[float], list[float], list[float]]:
    e12 = ema(values, 12)
    e26 = ema(values, 26)
    line = [a - b for a, b in zip(e12, e26)]
    sig = ema(line, 9)
    hist = [a - b for a, b in zip(line, sig)]
    return line, sig, hist


def linear_slope_pct(values: list[float]) -> float:
    if len(values) < 5 or values[0] <= 0:
        return 0.0
    n = len(values)
    xs = range(n)
    mx = (n - 1) / 2
    my = sum(values) / n
    denom = sum((x - mx) ** 2 for x in xs)
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, values)) / max(denom, 1e-9)
    return slope * (n - 1) / values[0] * 100


def parse_ohlcv(rows: list[list[float]]) -> list[dict[str, float]]:
    out = []
    for r in rows:
        if len(r) >= 6:
            out.append({"ts": float(r[0]), "open": float(r[1]), "high": float(r[2]), "low": float(r[3]), "close": float(r[4]), "volume": float(r[5])})
    return out

# ---------------- adaptive model ----------------

class OnlineLogisticModel:
    """Лёгкая самообучающаяся модель без тяжёлых зависимостей.

    Хранит веса отдельно для scalp/swing + BTC/ETH + LONG/SHORT.
    Обновляется после закрытия сделки: profit>0 = 1, loss = 0.
    """

    def __init__(self, path: Path):
        self.path = path
        self.data = load_json(path, {})
        if not isinstance(self.data, dict):
            self.data = {}
        self.data.setdefault("profiles", {})
        self.data.setdefault("closed_trades", 0)

    def key(self, mode: str, symbol: str, side: str) -> str:
        return f"{mode}:{symbol}:{side}"

    def profile(self, mode: str, symbol: str, side: str, n_features: int) -> dict[str, Any]:
        key = self.key(mode, symbol, side)
        p = self.data["profiles"].setdefault(key, {"bias": 0.0, "weights": [0.0] * n_features, "updates": 0, "wins": 0, "losses": 0})
        if len(p.get("weights", [])) != n_features:
            p["weights"] = [0.0] * n_features
            p["bias"] = 0.0
        return p

    @staticmethod
    def sigmoid(x: float) -> float:
        if x > 35:
            return 1.0
        if x < -35:
            return 0.0
        return 1.0 / (1.0 + math.exp(-x))

    def predict(self, mode: str, symbol: str, side: str, features: list[float]) -> float:
        p = self.profile(mode, symbol, side, len(features))
        z = float(p.get("bias", 0.0)) + sum(w * x for w, x in zip(p["weights"], features))
        return self.sigmoid(z) * 100.0

    def update(self, mode: str, symbol: str, side: str, features: list[float], label: int) -> None:
        p = self.profile(mode, symbol, side, len(features))
        prob = self.predict(mode, symbol, side, features) / 100.0
        err = float(label) - prob
        lr = 0.035
        l2 = 0.0008
        p["bias"] = float(p.get("bias", 0.0)) + lr * err
        p["weights"] = [(1 - l2) * w + lr * err * x for w, x in zip(p["weights"], features)]
        p["updates"] = int(p.get("updates", 0)) + 1
        if label:
            p["wins"] = int(p.get("wins", 0)) + 1
        else:
            p["losses"] = int(p.get("losses", 0)) + 1
        self.data["closed_trades"] = int(self.data.get("closed_trades", 0)) + 1
        self.save()

    def save(self) -> None:
        save_json(self.path, self.data)

    def stats_text(self) -> str:
        profiles = self.data.get("profiles", {})
        updates = sum(int(p.get("updates", 0)) for p in profiles.values())
        wins = sum(int(p.get("wins", 0)) for p in profiles.values())
        losses = sum(int(p.get("losses", 0)) for p in profiles.values())
        wr = wins / max(1, wins + losses) * 100
        return f"профилей {len(profiles)}, обновлений {updates}, winrate обучения {wr:.1f}% ({wins}/{wins+losses})"

MODEL = OnlineLogisticModel(MODEL_FILE)

# ---------------- exchange ----------------

def exchange_config(settings: dict[str, Any]) -> dict[str, Any]:
    exchange_id = settings["exchange_id"]
    keys = load_api_keys().get(exchange_id, {})
    api_key = keys.get("apiKey") or os.getenv("EXCHANGE_API_KEY", "")
    secret = keys.get("secret") or os.getenv("EXCHANGE_API_SECRET", "")
    password = keys.get("password") or os.getenv("EXCHANGE_API_PASSWORD", "")
    cfg: dict[str, Any] = {
        "enableRateLimit": True,
        "apiKey": api_key,
        "secret": secret,
        "options": {"defaultType": "swap", "adjustForTimeDifference": True},
    }
    if password:
        cfg["password"] = password
    return cfg


def make_exchange(settings: dict[str, Any]) -> Any:
    exchange_id = settings["exchange_id"]
    cls = getattr(ccxt, exchange_id)
    ex = cls(exchange_config(settings))
    return ex


async def close_exchange(ex: Any) -> None:
    try:
        await ex.close()
    except Exception:
        pass


async def market_symbol(ex: Any, coin: str) -> str:
    markets = await ex.load_markets()
    coin = coin.upper()
    for symbol, market in markets.items():
        if market.get("base") == coin and market.get("quote") == "USDT" and (market.get("swap") or market.get("future") or market.get("contract")):
            return symbol
    for symbol, market in markets.items():
        if market.get("base") == coin and market.get("quote") == "USDT":
            return symbol
    # Fallback for most linear futures implementations.
    return f"{coin}/USDT:USDT"


async def fetch_candles(ex: Any, symbol: str, timeframe: str, limit: int) -> list[dict[str, float]]:
    rows = await ex.fetch_ohlcv(symbol, timeframe=timeframe, limit=limit)
    return parse_ohlcv(rows)


async def fetch_last_price(ex: Any, symbol: str) -> float:
    ticker = await ex.fetch_ticker(symbol)
    price = ticker.get("last") or ticker.get("mark") or ticker.get("close") or ticker.get("bid") or ticker.get("ask")
    return float(price)


async def fetch_funding_pct(ex: Any, symbol: str) -> float:
    try:
        if getattr(ex, "has", {}).get("fetchFundingRate"):
            data = await ex.fetch_funding_rate(symbol)
            value = data.get("fundingRate") or data.get("rate") or 0.0
            return float(value) * 100.0
    except Exception:
        return 0.0
    return 0.0


def load_api_keys() -> dict[str, Any]:
    data = load_json(API_FILE, {})
    return data if isinstance(data, dict) else {}


def save_api_keys(data: dict[str, Any]) -> None:
    save_json(API_FILE, data)

# ---------------- strategy ----------------

@dataclass
class Signal:
    coin: str
    market_symbol: str
    side: str
    probability: float
    rule_score: float
    neural_probability: float
    entry: float
    stop: float
    tp1: float
    tp2: float
    tp3: float
    atr_value: float
    atr_pct: float
    rr1: float
    features: list[float]
    reasons: list[str]
    mode: str
    timeframe: str
    funding_pct: float = 0.0


def analyze_timeframe(candles: list[dict[str, float]]) -> dict[str, Any]:
    closes = [c["close"] for c in candles]
    highs = [c["high"] for c in candles]
    lows = [c["low"] for c in candles]
    vols = [c["volume"] for c in candles]
    if len(closes) < 80:
        raise ValueError("мало свечей")
    e21 = ema(closes, 21)
    e50 = ema(closes, 50)
    e200 = ema(closes, min(200, max(50, len(closes)//2)))
    rs = rsi(closes, 14)
    _, _, hist = macd(closes)
    at = atr(highs, lows, closes, 14)
    close = closes[-1]
    atr_now = at[-1] or (close * 0.005)
    avg_vol = sum(vols[-31:-1]) / max(1, len(vols[-31:-1]))
    vol_ratio = vols[-1] / avg_vol if avg_vol > 0 else 1.0
    slope20 = linear_slope_pct(closes[-20:])
    slope50 = linear_slope_pct(closes[-50:])
    ma20 = sum(closes[-20:]) / 20
    sd20 = stdev(closes[-20:])
    z = (close - ma20) / sd20 if sd20 > 0 else 0.0
    high_80 = max(highs[-80:])
    low_80 = min(lows[-80:])
    pos = (close - low_80) / max(1e-9, high_80 - low_80)
    return {
        "close": close,
        "ema21": e21[-1],
        "ema50": e50[-1],
        "ema200": e200[-1],
        "rsi": rs[-1] or 50.0,
        "macd_hist": hist[-1],
        "macd_hist_prev": hist[-2] if len(hist) > 1 else 0.0,
        "atr": atr_now,
        "atr_pct": atr_now / close * 100.0,
        "vol_ratio": vol_ratio,
        "slope20": slope20,
        "slope50": slope50,
        "zscore": z,
        "range_pos": pos,
        "support": min(lows[-30:]),
        "resistance": max(highs[-30:]),
    }


def side_score(tf: dict[str, Any], side: str) -> tuple[float, list[str]]:
    score = 50.0
    reasons: list[str] = []
    sign = 1 if side == "LONG" else -1
    close = tf["close"]
    trend_fast = 1 if close > tf["ema21"] > tf["ema50"] else -1 if close < tf["ema21"] < tf["ema50"] else 0
    trend_slow = 1 if close > tf["ema200"] else -1 if close < tf["ema200"] else 0
    score += sign * trend_fast * 13
    score += sign * trend_slow * 8
    if sign * trend_fast > 0:
        reasons.append("EMA тренд совпадает")
    if sign * trend_slow > 0:
        reasons.append("старшая EMA на стороне")

    r = tf["rsi"]
    if side == "LONG":
        if 48 <= r <= 68:
            score += 8; reasons.append(f"RSI {r:.0f} без перегрева")
        elif r > 76:
            score -= 8; reasons.append("RSI перегрев")
        elif r < 38:
            score -= 4
    else:
        if 32 <= r <= 52:
            score += 8; reasons.append(f"RSI {r:.0f} без перепроданности")
        elif r < 24:
            score -= 8; reasons.append("RSI перепроданность")
        elif r > 62:
            score -= 4

    macd_mom = 1 if tf["macd_hist"] > tf["macd_hist_prev"] else -1
    macd_side = 1 if tf["macd_hist"] > 0 else -1
    score += sign * macd_mom * 5 + sign * macd_side * 4
    if sign * macd_mom > 0:
        reasons.append("MACD momentum совпадает")

    score += sign * clamp(tf["slope20"], -2.0, 2.0) * 4
    score += sign * clamp(tf["slope50"], -4.0, 4.0) * 2
    if sign * tf["slope20"] > 0:
        reasons.append(f"наклон 20 свечей {tf['slope20']:+.2f}%")

    if tf["vol_ratio"] >= 1.08:
        score += 4
        reasons.append(f"объём x{tf['vol_ratio']:.2f}")

    # mean-reversion против позднего входа
    z = tf["zscore"]
    if side == "LONG" and z > 2.2:
        score -= 7; reasons.append("цена далеко выше BB")
    if side == "SHORT" and z < -2.2:
        score -= 7; reasons.append("цена далеко ниже BB")
    return clamp(score, 0, 100), reasons


def feature_vector(base: dict[str, Any], confirms: list[dict[str, Any]], side: str) -> list[float]:
    sign = 1 if side == "LONG" else -1
    conf_trend = 0.0
    for c in confirms:
        conf_trend += 1 if c["close"] > c["ema50"] else -1
    conf_trend /= max(1, len(confirms))
    return [
        clamp(sign * (base["close"] / base["ema21"] - 1) * 20, -2, 2),
        clamp(sign * (base["ema21"] / base["ema50"] - 1) * 30, -2, 2),
        clamp(sign * base["slope20"] / 2, -2, 2),
        clamp(sign * base["slope50"] / 4, -2, 2),
        clamp((base["vol_ratio"] - 1.0), -1, 2),
        clamp(sign * base["macd_hist"] / max(base["atr"], 1e-9) * 10, -2, 2),
        clamp((50 - abs(base["rsi"] - 50)) / 25, -1, 1),
        clamp(base["atr_pct"] / 2, 0, 2),
        clamp(sign * conf_trend, -1, 1),
        clamp(-abs(base["zscore"]) / 3, -1, 0),
    ]


async def build_signal_for_coin(ex: Any, settings: dict[str, Any], coin: str) -> Optional[Signal]:
    mode = settings["strategy_mode"]
    profile = MODE_PROFILES[mode]
    symbol = await market_symbol(ex, coin)
    base_candles = await fetch_candles(ex, symbol, profile["base_tf"], profile["limit_base"])
    base = analyze_timeframe(base_candles)
    if not (profile["min_atr_pct"] <= base["atr_pct"] <= profile["max_atr_pct"]):
        return None
    confirms = []
    for tf in profile["confirm_tfs"]:
        c = await fetch_candles(ex, symbol, tf, profile["limit_confirm"])
        confirms.append(analyze_timeframe(c))
    funding = await fetch_funding_pct(ex, symbol)

    best: Optional[Signal] = None
    for side in ("LONG", "SHORT"):
        rule, reasons = side_score(base, side)
        # Мульти-ТФ подтверждение.
        confirm_boost = 0.0
        for idx, conf in enumerate(confirms):
            conf_score, conf_reasons = side_score(conf, side)
            if conf_score >= 58:
                confirm_boost += 6 if idx == 0 else 8
                reasons.append(f"{profile['confirm_tfs'][idx]} подтверждает")
            elif conf_score < 45:
                confirm_boost -= 7 if idx == 0 else 10
        rule = clamp(rule + confirm_boost, 0, 100)

        # funding как мягкий контр-сигнал: дорого держать сторону -> небольшой штраф.
        if side == "LONG" and funding > 0.02:
            rule -= min(5, funding * 55); reasons.append(f"funding дорогой LONG {funding:+.4f}%")
        if side == "SHORT" and funding < -0.02:
            rule -= min(5, abs(funding) * 55); reasons.append(f"funding дорогой SHORT {funding:+.4f}%")

        features = feature_vector(base, confirms, side)
        neural = MODEL.predict(mode, coin, side, features)
        if int(MODEL.profile(mode, coin, side, len(features)).get("updates", 0)) < 8:
            # До накопления статистики не даём пустой модели ломать правила.
            neural = 50 + (rule - 50) * 0.25
        probability = rule * 0.72 + neural * 0.28 if settings.get("use_neural_filter") else rule
        if settings.get("use_neural_filter") and neural < float(settings.get("min_neural_probability", 52)) and rule < 84:
            probability -= 7
            reasons.append(f"AI фильтр осторожен {neural:.0f}%")

        entry = base["close"]
        stop_distance = base["atr"] * profile["atr_sl"]
        if side == "LONG":
            stop = min(entry - stop_distance, base["support"] - base["atr"] * 0.15)
            risk = max(entry - stop, entry * 0.0025)
            tp1, tp2, tp3 = entry + risk * profile["tp1_rr"], entry + risk * profile["tp2_rr"], entry + risk * profile["tp3_rr"]
        else:
            stop = max(entry + stop_distance, base["resistance"] + base["atr"] * 0.15)
            risk = max(stop - entry, entry * 0.0025)
            tp1, tp2, tp3 = entry - risk * profile["tp1_rr"], entry - risk * profile["tp2_rr"], entry - risk * profile["tp3_rr"]
        rr1 = abs(tp1 - entry) / max(abs(entry - stop), 1e-9)
        sig = Signal(
            coin=coin, market_symbol=symbol, side=side, probability=probability, rule_score=rule, neural_probability=neural,
            entry=entry, stop=stop, tp1=tp1, tp2=tp2, tp3=tp3, atr_value=base["atr"], atr_pct=base["atr_pct"], rr1=rr1,
            features=features, reasons=reasons[:8], mode=mode, timeframe=profile["base_tf"], funding_pct=funding,
        )
        if best is None or sig.probability > best.probability:
            best = sig
    threshold = settings["min_probability_scalp"] if mode == "scalp" else settings["min_probability_swing"]
    return best if best and best.probability >= threshold else None

# ---------------- trades ----------------

@dataclass
class Trade:
    id: str
    coin: str
    market_symbol: str
    side: str
    mode: str
    opened_at: float
    entry: float
    stop: float
    tp1: float
    tp2: float
    tp3: float
    atr_value: float
    qty: float
    notional: float
    risk_usdt: float
    probability: float
    neural_probability: float
    features: list[float]
    status: str = "open"
    trade_mode: str = "paper"
    exchange_order_id: Optional[str] = None
    reached_tp1: bool = False
    max_favorable_price: float = 0.0
    close_price: Optional[float] = None
    closed_at: Optional[float] = None
    pnl_usdt: float = 0.0
    pnl_pct: float = 0.0
    close_reason: str = ""


def trade_to_dict(t: Trade) -> dict[str, Any]:
    return asdict(t)


def trade_from_dict(d: dict[str, Any]) -> Trade:
    return Trade(**d)


def risk_position(signal: Signal, settings: dict[str, Any]) -> tuple[float, float, float]:
    equity = float(settings.get("account_equity_usdt", 100.0))
    risk_usdt = equity * float(settings.get("risk_per_trade_pct", 0.35)) / 100.0
    risk_per_unit = abs(signal.entry - signal.stop)
    qty = risk_usdt / max(risk_per_unit, 1e-9)
    notional = qty * signal.entry
    max_notional = equity * int(settings.get("leverage", 2)) * 0.95
    if notional > max_notional:
        qty = max_notional / signal.entry
        notional = max_notional
    return qty, notional, risk_usdt


def can_open_new_trade(signal: Signal, settings: dict[str, Any], state: dict[str, Any]) -> tuple[bool, str]:
    open_trades = [t for t in state.get("open_trades", []) if t.get("status") == "open"]
    if any(t.get("coin") == signal.coin for t in open_trades):
        return False, f"по {signal.coin} уже есть открытая сделка"
    if len(open_trades) >= int(settings.get("max_open_trades", 2)):
        return False, "достигнут максимум открытых сделок"
    daily = state.setdefault("daily", {}).setdefault(today_key(), {"pnl": 0.0, "trades": []})
    if float(daily.get("pnl", 0.0)) <= -float(settings.get("account_equity_usdt", 100)) * float(settings.get("max_daily_loss_pct", 2.0)) / 100.0:
        return False, "дневной лимит убытка достигнут"
    now = time.time()
    if signal.mode == "scalp":
        hour_trades = [x for x in daily.get("trades", []) if now - float(x.get("ts", 0)) < 3600]
        if len(hour_trades) >= int(settings.get("max_trades_per_hour_scalp", 10)):
            return False, "лимит scalp сделок за час"
    else:
        day_trades = [x for x in daily.get("trades", []) if x.get("mode") == "swing"]
        if len(day_trades) >= int(settings.get("max_trades_per_day_swing", 2)):
            return False, "лимит swing сделок за сутки"
    key = f"{signal.mode}:{signal.coin}:{signal.side}"
    last = float(state.get("last_signal_ts", {}).get(key, 0))
    cooldown = (settings["cooldown_scalp_min"] if signal.mode == "scalp" else settings["cooldown_swing_min"]) * 60
    if now - last < cooldown:
        return False, "cooldown"
    return True, "ok"


async def open_trade(signal: Signal, settings: dict[str, Any], state: dict[str, Any]) -> Optional[Trade]:
    qty, notional, risk_usdt = risk_position(signal, settings)
    if qty <= 0 or notional <= 0:
        return None
    trade = Trade(
        id=str(int(time.time() * 1000))[-10:], coin=signal.coin, market_symbol=signal.market_symbol,
        side=signal.side, mode=signal.mode, opened_at=time.time(), entry=signal.entry, stop=signal.stop,
        tp1=signal.tp1, tp2=signal.tp2, tp3=signal.tp3, atr_value=signal.atr_value, qty=qty, notional=notional, risk_usdt=risk_usdt,
        probability=signal.probability, neural_probability=signal.neural_probability, features=signal.features,
        trade_mode=settings["trade_mode"], max_favorable_price=signal.entry,
    )
    if settings["trade_mode"] == "live":
        if settings.get("live_confirm_required") and not state.get("live_armed"):
            return None
        ex = make_exchange(settings)
        try:
            try:
                await ex.set_margin_mode("isolated", signal.market_symbol)
            except Exception:
                pass
            try:
                await ex.set_leverage(int(settings.get("leverage", 2)), signal.market_symbol)
            except Exception:
                pass
            side = "buy" if signal.side == "LONG" else "sell"
            order = await ex.create_order(signal.market_symbol, "market", side, qty, None, {})
            trade.exchange_order_id = str(order.get("id") or "")
            if settings.get("protective_orders"):
                await place_protection_best_effort(ex, signal, qty)
        finally:
            await close_exchange(ex)
    state.setdefault("open_trades", []).append(trade_to_dict(trade))
    state.setdefault("last_signal_ts", {})[f"{signal.mode}:{signal.coin}:{signal.side}"] = time.time()
    state.setdefault("daily", {}).setdefault(today_key(), {"pnl": 0.0, "trades": []}).setdefault("trades", []).append({"ts": time.time(), "mode": signal.mode, "coin": signal.coin})
    save_state(state)
    return trade


async def place_protection_best_effort(ex: Any, signal: Signal, qty: float) -> None:
    # У разных бирж синтаксис условных ордеров отличается. Пробуем унифицированные параметры CCXT.
    close_side = "sell" if signal.side == "LONG" else "buy"
    for price, label in [(signal.stop, "stopLossPrice"), (signal.tp1, "takeProfitPrice")]:
        for params in (
            {"reduceOnly": True, label: price},
            {"reduceOnly": True, "triggerPrice": price},
        ):
            try:
                await ex.create_order(signal.market_symbol, "market", close_side, qty, None, params)
                break
            except Exception:
                continue


def signal_text(signal: Signal, autotrade_note: str = "") -> str:
    return (
        f"<b>{'⚡' if signal.mode == 'scalp' else '🧲'} {signal.coin} {signal.side} signal</b>\n"
        f"Режим: <b>{html.escape(signal.mode)}</b>, ТФ: <b>{html.escape(signal.timeframe)}</b>\n"
        f"Вероятность: <b>{signal.probability:.0f}%</b> | правила {signal.rule_score:.0f}% | AI {signal.neural_probability:.0f}%\n"
        f"Entry: <b>{fmt_price(signal.entry)}</b>\n"
        f"SL: <b>{fmt_price(signal.stop)}</b>\n"
        f"TP1: <b>{fmt_price(signal.tp1)}</b> · TP2: <b>{fmt_price(signal.tp2)}</b> · TP3: <b>{fmt_price(signal.tp3)}</b>\n"
        f"ATR: <b>{signal.atr_pct:.2f}%</b>, RR TP1: <b>{signal.rr1:.2f}</b>, funding: <b>{signal.funding_pct:+.4f}%</b>\n"
        f"Причины: {html.escape('; '.join(signal.reasons) or 'нет')}\n"
        f"{html.escape(autotrade_note)}\n\n"
        "⚠️ Не финсовет. LIVE режим опасен: сначала гоняй PAPER и /backtest."
    )


def trade_opened_text(trade: Trade) -> str:
    return (
        f"✅ <b>Сделка открыта</b> #{trade.id}\n"
        f"{trade.coin} {trade.side} · {trade.mode} · {trade.trade_mode}\n"
        f"Entry {fmt_price(trade.entry)} | SL {fmt_price(trade.stop)} | TP1 {fmt_price(trade.tp1)}\n"
        f"Qty {trade.qty:.6g}, notional ${trade.notional:.2f}, риск ≈ ${trade.risk_usdt:.2f}"
    )


async def close_trade_local(trade: Trade, price: float, reason: str, settings: dict[str, Any], state: dict[str, Any]) -> Trade:
    sign = 1 if trade.side == "LONG" else -1
    gross = (price - trade.entry) * sign * trade.qty
    fee = trade.notional * 0.0012  # rough round-trip taker + slippage reserve
    pnl = gross - fee
    trade.close_price = price
    trade.closed_at = time.time()
    trade.pnl_usdt = pnl
    trade.pnl_pct = pnl / max(trade.notional / max(1, int(settings.get("leverage", 1))), 1e-9) * 100.0
    trade.close_reason = reason
    trade.status = "closed"
    daily = state.setdefault("daily", {}).setdefault(today_key(), {"pnl": 0.0, "trades": []})
    daily["pnl"] = float(daily.get("pnl", 0.0)) + pnl
    # обучаемся по факту закрытия
    MODEL.update(trade.mode, trade.coin, trade.side, trade.features, 1 if pnl > 0 else 0)
    with TRADE_LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(trade_to_dict(trade), ensure_ascii=False) + "\n")
    # заменить в state
    new_open = []
    for d in state.get("open_trades", []):
        if d.get("id") == trade.id:
            new_open.append(trade_to_dict(trade))
        else:
            new_open.append(d)
    state["open_trades"] = [t for t in new_open if t.get("status") == "open"]
    save_state(state)
    return trade


def close_text(trade: Trade) -> str:
    emoji = "🟢" if trade.pnl_usdt > 0 else "🔴"
    return (
        f"{emoji} <b>Сделка закрыта</b> #{trade.id}\n"
        f"{trade.coin} {trade.side} · причина: <b>{html.escape(trade.close_reason)}</b>\n"
        f"Entry {fmt_price(trade.entry)} → Close {fmt_price(trade.close_price or 0)}\n"
        f"PnL: <b>{trade.pnl_usdt:+.2f} USDT</b> ({trade.pnl_pct:+.2f}%)\n"
        f"AI обновлён: {html.escape(MODEL.stats_text())}"
    )


async def monitor_trades_once(settings: dict[str, Any], state: dict[str, Any]) -> list[Trade]:
    closed: list[Trade] = []
    open_dicts = [t for t in state.get("open_trades", []) if t.get("status") == "open"]
    if not open_dicts:
        return closed
    ex = make_exchange(settings)
    try:
        for d in list(open_dicts):
            trade = trade_from_dict(d)
            price = await fetch_last_price(ex, trade.market_symbol)
            profile = MODE_PROFILES[trade.mode]
            sign = 1 if trade.side == "LONG" else -1
            trade.max_favorable_price = max(trade.max_favorable_price, price) if trade.side == "LONG" else min(trade.max_favorable_price or price, price)
            reason = None
            if (trade.side == "LONG" and price <= trade.stop) or (trade.side == "SHORT" and price >= trade.stop):
                reason = "SL"
            elif (trade.side == "LONG" and price >= trade.tp3) or (trade.side == "SHORT" and price <= trade.tp3):
                reason = "TP3"
            elif (trade.side == "LONG" and price >= trade.tp2) or (trade.side == "SHORT" and price <= trade.tp2):
                reason = "TP2"
            elif (trade.side == "LONG" and price >= trade.tp1) or (trade.side == "SHORT" and price <= trade.tp1):
                trade.reached_tp1 = True
                # после TP1 переводим стоп к безубытку с маленьким плюсом
                if trade.side == "LONG":
                    trade.stop = max(trade.stop, trade.entry * 1.0005)
                else:
                    trade.stop = min(trade.stop, trade.entry * 0.9995)
            if trade.reached_tp1:
                trail_distance = max(trade.atr_value * float(profile.get("trail_after_tp1_atr", 0.8)), abs(trade.entry - trade.stop) * 0.25)
                if trade.side == "LONG":
                    trade.stop = max(trade.stop, price - trail_distance)
                else:
                    trade.stop = min(trade.stop, price + trail_distance)
            # time stop
            if reason is None and time.time() - trade.opened_at > profile["max_hold_minutes"] * 60:
                reason = "time-stop"
            if reason:
                # live close best effort
                if trade.trade_mode == "live":
                    try:
                        close_side = "sell" if trade.side == "LONG" else "buy"
                        await ex.create_order(trade.market_symbol, "market", close_side, trade.qty, None, {"reduceOnly": True})
                    except Exception:
                        logging.exception("LIVE close order failed")
                closed_trade = await close_trade_local(trade, price, reason, settings, state)
                closed.append(closed_trade)
            else:
                # persist updated stop/tp1 flag
                for item in state.get("open_trades", []):
                    if item.get("id") == trade.id:
                        item.update(trade_to_dict(trade))
                save_state(state)
    finally:
        await close_exchange(ex)
    return closed

# ---------------- backtest ----------------

def simulate_backtest(candles: list[dict[str, float]], mode: str) -> dict[str, Any]:
    profile = MODE_PROFILES[mode]
    min_len = 220 if mode == "scalp" else 260
    trades = []
    equity = 1000.0
    peak = equity
    max_dd = 0.0
    cooldown_until = 0
    for i in range(min_len, len(candles) - 20):
        if i < cooldown_until:
            continue
        window = candles[:i]
        try:
            base = analyze_timeframe(window)
        except Exception:
            continue
        if not (profile["min_atr_pct"] <= base["atr_pct"] <= profile["max_atr_pct"]):
            continue
        best_side = None
        best_score = 0.0
        for side in ("LONG", "SHORT"):
            sc, _ = side_score(base, side)
            if sc > best_score:
                best_side, best_score = side, sc
        threshold = 74 if mode == "scalp" else 78
        if best_score < threshold:
            continue
        entry = base["close"]
        stop_dist = base["atr"] * profile["atr_sl"]
        if best_side == "LONG":
            stop = entry - stop_dist
            risk = entry - stop
            tp = entry + risk * profile["tp1_rr"]
        else:
            stop = entry + stop_dist
            risk = stop - entry
            tp = entry - risk * profile["tp1_rr"]
        outcome = None
        exit_price = None
        for j in range(i + 1, min(len(candles), i + 1 + (20 if mode == "scalp" else 72))):
            c = candles[j]
            if best_side == "LONG":
                if c["low"] <= stop:
                    outcome, exit_price = "loss", stop; break
                if c["high"] >= tp:
                    outcome, exit_price = "win", tp; break
            else:
                if c["high"] >= stop:
                    outcome, exit_price = "loss", stop; break
                if c["low"] <= tp:
                    outcome, exit_price = "win", tp; break
        if outcome is None:
            exit_price = candles[min(len(candles)-1, i + (20 if mode == "scalp" else 72))]["close"]
        sign = 1 if best_side == "LONG" else -1
        risk_usdt = equity * 0.0035
        qty = risk_usdt / risk
        pnl = (exit_price - entry) * sign * qty - entry * qty * 0.0012
        equity += pnl
        peak = max(peak, equity)
        max_dd = max(max_dd, (peak - equity) / peak * 100)
        trades.append({"pnl": pnl, "side": best_side, "score": best_score})
        cooldown_until = i + (3 if mode == "scalp" else 12)
    wins = sum(1 for t in trades if t["pnl"] > 0)
    losses = len(trades) - wins
    total_pnl = sum(t["pnl"] for t in trades)
    gross_win = sum(t["pnl"] for t in trades if t["pnl"] > 0)
    gross_loss = abs(sum(t["pnl"] for t in trades if t["pnl"] < 0))
    return {
        "trades": len(trades), "wins": wins, "losses": losses,
        "winrate": wins / max(1, len(trades)) * 100,
        "pnl": total_pnl, "pnl_pct": (equity - 1000) / 1000 * 100,
        "max_dd": max_dd,
        "profit_factor": gross_win / max(gross_loss, 1e-9),
    }

# ---------------- telegram UI ----------------

def settings_keyboard(settings: dict[str, Any]) -> InlineKeyboardMarkup:
    mode = settings["strategy_mode"]
    trade_mode = settings["trade_mode"]
    autotrade = "ON" if settings.get("autotrade_enabled") else "OFF"
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=f"⚡ Scalp {'✅' if mode=='scalp' else ''}", callback_data="set:mode:scalp"), InlineKeyboardButton(text=f"🧲 Swing {'✅' if mode=='swing' else ''}", callback_data="set:mode:swing")],
        [InlineKeyboardButton(text=f"🛑 OFF {'✅' if trade_mode=='off' else ''}", callback_data="set:trade_mode:off"), InlineKeyboardButton(text=f"🧪 PAPER {'✅' if trade_mode=='paper' else ''}", callback_data="set:trade_mode:paper"), InlineKeyboardButton(text=f"🔴 LIVE {'✅' if trade_mode=='live' else ''}", callback_data="set:trade_mode:live")],
        [InlineKeyboardButton(text=f"🤖 Автовход {autotrade}", callback_data="toggle:autotrade"), InlineKeyboardButton(text=f"AI {'ON' if settings.get('use_neural_filter') else 'OFF'}", callback_data="toggle:ai")],
        [InlineKeyboardButton(text="🔎 Скан", callback_data="run:scan"), InlineKeyboardButton(text="📈 Бэктест", callback_data="run:backtest")],
        [InlineKeyboardButton(text="🔴 ARM LIVE", callback_data="set:arm_live"), InlineKeyboardButton(text="🧯 DISARM LIVE", callback_data="set:disarm_live")],
    ])


def status_text(settings: dict[str, Any], state: dict[str, Any]) -> str:
    daily = state.setdefault("daily", {}).setdefault(today_key(), {"pnl": 0.0, "trades": []})
    live_armed = "ARMED" if state.get("live_armed") else "disarmed"
    open_trades = [t for t in state.get("open_trades", []) if t.get("status") == "open"]
    return (
        f"<b>{html.escape(BOT_VERSION)}</b>\n\n"
        f"Биржа: <b>{html.escape(settings['exchange_id'])}</b>\n"
        f"Режим стратегии: <b>{html.escape(settings['strategy_mode'])}</b>\n"
        f"Торговля: <b>{html.escape(settings['trade_mode'])}</b>, автовход: <b>{'ON' if settings.get('autotrade_enabled') else 'OFF'}</b>\n"
        f"LIVE защита: <b>{live_armed}</b>\n"
        f"Риск/сделка: <b>{settings['risk_per_trade_pct']:.2f}%</b>, плечо x<b>{settings['leverage']}</b>\n"
        f"Дневной PnL: <b>{float(daily.get('pnl',0)):+.2f} USDT</b>, сделок сегодня: <b>{len(daily.get('trades', []))}</b>\n"
        f"Открытых сделок: <b>{len(open_trades)}</b> / {settings['max_open_trades']}\n"
        f"AI: <b>{'ON' if settings.get('use_neural_filter') else 'OFF'}</b> — {html.escape(MODEL.stats_text())}\n\n"
        "Профили:\n"
        "⚡ scalp: 5m + 15m/1h, до 10 сделок/час, быстрые TP.\n"
        "🧲 swing: 1h + 4h/1d, 1-2 сделки/сутки, дальние TP."
    )


async def notify_all(text: str) -> None:
    if bot is None:
        return
    state = load_state()
    for chat_id in list(state.get("subscribers", [])):
        try:
            await bot.send_message(int(chat_id), text, reply_markup=main_keyboard)
        except Exception:
            logging.debug("notify failed %s", chat_id, exc_info=True)


async def run_scan(send_to_chat: Optional[int] = None) -> list[Signal]:
    settings = load_settings()
    state = load_state()
    signals: list[Signal] = []
    ex = make_exchange(settings)
    try:
        for coin in SYMBOLS:
            try:
                sig = await build_signal_for_coin(ex, settings, coin)
                if sig:
                    signals.append(sig)
            except Exception as exc:
                logging.exception("scan failed %s", coin)
                if send_to_chat and bot:
                    await bot.send_message(send_to_chat, f"⚠️ Ошибка скана {coin}: <code>{html.escape(str(exc))}</code>")
    finally:
        await close_exchange(ex)
    signals.sort(key=lambda s: s.probability, reverse=True)

    for sig in signals:
        can_open, reason = can_open_new_trade(sig, settings, state)
        note = ""
        if settings.get("autotrade_enabled") and settings["trade_mode"] in {"paper", "live"} and can_open:
            trade = await open_trade(sig, settings, state)
            if trade:
                note = f"Автовход: открыт #{trade.id} ({trade.trade_mode})."
                if send_to_chat and bot:
                    await bot.send_message(send_to_chat, signal_text(sig, note), reply_markup=main_keyboard)
                    await bot.send_message(send_to_chat, trade_opened_text(trade), reply_markup=main_keyboard)
                else:
                    await notify_all(signal_text(sig, note))
                    await notify_all(trade_opened_text(trade))
            else:
                note = "Автовход не открыт: LIVE не подтверждён/ошибка размера."
        else:
            note = f"Автовход: не открыт ({reason if not can_open else 'автовход OFF/режим OFF'})."
            if send_to_chat and bot:
                await bot.send_message(send_to_chat, signal_text(sig, note), reply_markup=main_keyboard)
            elif settings.get("signals_enabled"):
                await notify_all(signal_text(sig, note))
    if not signals and send_to_chat and bot:
        await bot.send_message(send_to_chat, "Сигнала выше порога сейчас нет.", reply_markup=main_keyboard)
    return signals


async def run_backtest_text() -> str:
    settings = load_settings()
    mode = settings["strategy_mode"]
    profile = MODE_PROFILES[mode]
    lines = [f"<b>📈 Бэктест {html.escape(mode)}</b>", "Упрощённая проверка по свежим свечам биржи. Не гарантия будущей прибыли.\n"]
    ex = make_exchange(settings)
    try:
        for coin in SYMBOLS:
            sym = await market_symbol(ex, coin)
            candles = await fetch_candles(ex, sym, profile["base_tf"], 1000)
            res = simulate_backtest(candles, mode)
            lines.append(
                f"<b>{coin}</b>: сделок {res['trades']}, WR {res['winrate']:.1f}%, "
                f"PnL {res['pnl']:+.2f} USDT ({res['pnl_pct']:+.2f}%), "
                f"PF {res['profit_factor']:.2f}, maxDD {res['max_dd']:.2f}%"
            )
    finally:
        await close_exchange(ex)
    return "\n".join(lines)

# ---------------- handlers ----------------

@dp.message(CommandStart())
async def cmd_start(message: Message) -> None:
    state = load_state()
    subs = set(int(x) for x in state.get("subscribers", []))
    subs.add(message.chat.id)
    state["subscribers"] = sorted(subs)
    save_state(state)
    await message.answer(
        "Готов. Это ETH/BTC бот для сигналов и авто-торговли. По умолчанию безопасный PAPER режим.\n\n"
        "Команды: /status /settings /scan /backtest /api /api_set /mode /trade_mode /risk /leverage /arm_live /disarm_live",
        reply_markup=main_keyboard,
    )

@dp.message(Command("status"))
async def cmd_status(message: Message) -> None:
    await message.answer(status_text(load_settings(), load_state()), reply_markup=settings_keyboard(load_settings()))

@dp.message(Command("settings"))
async def cmd_settings(message: Message) -> None:
    if not is_admin(message):
        return await message.answer("Только админ.")
    await message.answer(status_text(load_settings(), load_state()), reply_markup=settings_keyboard(load_settings()))

@dp.message(Command("scan"))
async def cmd_scan(message: Message) -> None:
    if not is_admin(message):
        return await message.answer("Только админ.")
    progress = await message.answer("🔎 Сканирую BTC/ETH...")
    await run_scan(message.chat.id)
    try:
        await progress.edit_text("✅ Скан готов")
    except Exception:
        pass

@dp.message(Command("backtest"))
async def cmd_backtest(message: Message) -> None:
    if not is_admin(message):
        return await message.answer("Только админ.")
    progress = await message.answer("📈 Загружаю свечи и гоняю бэктест...")
    try:
        text = await run_backtest_text()
        await progress.edit_text(text)
    except Exception as exc:
        logging.exception("backtest failed")
        await progress.edit_text(f"⚠️ Ошибка бэктеста: <code>{html.escape(str(exc))}</code>")

@dp.message(Command("mode"))
async def cmd_mode(message: Message, command: CommandObject) -> None:
    if not is_admin(message):
        return await message.answer("Только админ.")
    value = (command.args or "").strip().lower()
    if value not in MODE_PROFILES:
        return await message.answer("Используй: /mode scalp или /mode swing")
    settings = load_settings(); settings["strategy_mode"] = value; save_settings(settings)
    await message.answer(f"Режим стратегии: <b>{html.escape(value)}</b>", reply_markup=settings_keyboard(settings))

@dp.message(Command("trade_mode"))
async def cmd_trade_mode(message: Message, command: CommandObject) -> None:
    if not is_admin(message):
        return await message.answer("Только админ.")
    value = (command.args or "").strip().lower()
    if value not in {"off", "paper", "live"}:
        return await message.answer("Используй: /trade_mode off|paper|live")
    settings = load_settings(); settings["trade_mode"] = value; save_settings(settings)
    await message.answer(f"Торговый режим: <b>{html.escape(value)}</b>", reply_markup=settings_keyboard(settings))

@dp.message(Command("risk"))
async def cmd_risk(message: Message, command: CommandObject) -> None:
    if not is_admin(message):
        return await message.answer("Только админ.")
    try:
        value = clamp(float(command.args or ""), 0.05, 2.0)
    except Exception:
        return await message.answer("Пример: /risk 0.35")
    settings = load_settings(); settings["risk_per_trade_pct"] = value; save_settings(settings)
    await message.answer(f"Риск на сделку: <b>{value:.2f}%</b>")

@dp.message(Command("leverage"))
async def cmd_leverage(message: Message, command: CommandObject) -> None:
    if not is_admin(message):
        return await message.answer("Только админ.")
    try:
        value = int(clamp(int(command.args or ""), 1, 10))
    except Exception:
        return await message.answer("Пример: /leverage 2")
    settings = load_settings(); settings["leverage"] = value; save_settings(settings)
    await message.answer(f"Плечо: <b>x{value}</b>")

@dp.message(Command("api"))
async def cmd_api(message: Message) -> None:
    if not is_admin(message):
        return await message.answer("Только админ.")
    settings = load_settings()
    keys = load_api_keys().get(settings["exchange_id"], {})
    env_ok = bool(os.getenv("EXCHANGE_API_KEY") and os.getenv("EXCHANGE_API_SECRET"))
    file_ok = bool(keys.get("apiKey") and keys.get("secret"))
    await message.answer(
        f"<b>API настройки</b>\n"
        f"Биржа: <b>{html.escape(settings['exchange_id'])}</b>\n"
        f"Ключи в ENV: <b>{'есть' if env_ok else 'нет'}</b>\n"
        f"Ключи в файле: <b>{'есть' if file_ok else 'нет'}</b>\n\n"
        "Безопаснее задать EXCHANGE_API_KEY / EXCHANGE_API_SECRET в Railway Variables.\n"
        "Через чат: <code>/api_set mexc KEY SECRET</code>\n"
        "Для OKX/некоторых бирж с паролем: <code>/api_set bybit KEY SECRET PASSWORD</code>\n"
        "Очистить: <code>/api_clear</code>"
    )

@dp.message(Command("api_set"))
async def cmd_api_set(message: Message, command: CommandObject) -> None:
    if not is_admin(message):
        return await message.answer("Только админ.")
    parts = (command.args or "").split()
    if len(parts) < 3:
        return await message.answer("Формат: /api_set mexc KEY SECRET [PASSWORD]")
    exchange_id = parts[0].lower()
    if exchange_id not in SUPPORTED_EXCHANGES:
        return await message.answer(f"Биржи: {', '.join(sorted(SUPPORTED_EXCHANGES))}")
    data = load_api_keys()
    data[exchange_id] = {"apiKey": parts[1], "secret": parts[2], "password": parts[3] if len(parts) > 3 else ""}
    save_api_keys(data)
    settings = load_settings(); settings["exchange_id"] = exchange_id; save_settings(settings)
    try:
        await message.delete()
    except Exception:
        pass
    await message.answer("✅ API ключи сохранены. Сообщение с ключами попробовал удалить. LIVE включай только после PAPER и /backtest.")

@dp.message(Command("api_clear"))
async def cmd_api_clear(message: Message) -> None:
    if not is_admin(message):
        return await message.answer("Только админ.")
    settings = load_settings(); data = load_api_keys(); data.pop(settings["exchange_id"], None); save_api_keys(data)
    await message.answer("API ключи текущей биржи очищены.")

@dp.message(Command("arm_live"))
async def cmd_arm_live(message: Message) -> None:
    if not is_admin(message):
        return await message.answer("Только админ.")
    state = load_state(); state["live_armed"] = True; save_state(state)
    await message.answer("🔴 LIVE ARMED. Реальные сделки разрешены, если /trade_mode live и автовход ON.")

@dp.message(Command("disarm_live"))
async def cmd_disarm_live(message: Message) -> None:
    if not is_admin(message):
        return await message.answer("Только админ.")
    state = load_state(); state["live_armed"] = False; save_state(state)
    await message.answer("🧯 LIVE disarmed. Реальные сделки заблокированы.")

@dp.callback_query(F.data.startswith("set:") | F.data.startswith("toggle:") | F.data.startswith("run:"))
async def callbacks(callback: CallbackQuery) -> None:
    if callback.from_user is None or callback.from_user.id not in ADMIN_IDS:
        return await callback.answer("Только админ", show_alert=True)
    settings = load_settings(); state = load_state(); data = callback.data or ""
    if data == "set:mode:scalp":
        settings["strategy_mode"] = "scalp"; save_settings(settings); await callback.answer("Scalp")
    elif data == "set:mode:swing":
        settings["strategy_mode"] = "swing"; save_settings(settings); await callback.answer("Swing")
    elif data.startswith("set:trade_mode:"):
        settings["trade_mode"] = data.split(":")[-1]; save_settings(settings); await callback.answer(settings["trade_mode"])
    elif data == "toggle:autotrade":
        settings["autotrade_enabled"] = not settings.get("autotrade_enabled"); save_settings(settings); await callback.answer("autotrade toggled")
    elif data == "toggle:ai":
        settings["use_neural_filter"] = not settings.get("use_neural_filter"); save_settings(settings); await callback.answer("AI toggled")
    elif data == "set:arm_live":
        state["live_armed"] = True; save_state(state); await callback.answer("LIVE ARMED", show_alert=True)
    elif data == "set:disarm_live":
        state["live_armed"] = False; save_state(state); await callback.answer("LIVE disarmed")
    elif data == "run:scan":
        await callback.answer("Скан")
        if callback.message:
            await run_scan(callback.message.chat.id)
    elif data == "run:backtest":
        await callback.answer("Бэктест")
        if callback.message:
            text = await run_backtest_text(); await callback.message.answer(text)
    if callback.message and data not in {"run:scan", "run:backtest"}:
        await callback.message.edit_text(status_text(load_settings(), load_state()), reply_markup=settings_keyboard(load_settings()))

@dp.message(F.text == "📊 Статус")
async def btn_status(message: Message) -> None: await cmd_status(message)
@dp.message(F.text == "🔎 Скан")
async def btn_scan(message: Message) -> None: await cmd_scan(message)
@dp.message(F.text == "⚡ Скальп")
async def btn_scalp(message: Message) -> None:
    settings=load_settings(); settings["strategy_mode"]="scalp"; save_settings(settings); await message.answer("⚡ Scalp включён")
@dp.message(F.text == "🧲 Свинг")
async def btn_swing(message: Message) -> None:
    settings=load_settings(); settings["strategy_mode"]="swing"; save_settings(settings); await message.answer("🧲 Swing включён")
@dp.message(F.text == "🧪 PAPER")
async def btn_paper(message: Message) -> None:
    settings=load_settings(); settings["trade_mode"]="paper"; save_settings(settings); await message.answer("🧪 PAPER режим")
@dp.message(F.text == "🛑 OFF")
async def btn_off(message: Message) -> None:
    settings=load_settings(); settings["trade_mode"]="off"; settings["autotrade_enabled"]=False; save_settings(settings); await message.answer("🛑 Торговля OFF")
@dp.message(F.text == "🤖 AI/обучение")
async def btn_ai(message: Message) -> None: await message.answer(f"🤖 {html.escape(MODEL.stats_text())}")
@dp.message(F.text == "📈 Бэктест")
async def btn_bt(message: Message) -> None: await cmd_backtest(message)
@dp.message(F.text == "🔑 API")
async def btn_api(message: Message) -> None: await cmd_api(message)
@dp.message(F.text == "⚙️ Настройки")
async def btn_set(message: Message) -> None: await cmd_settings(message)

# ---------------- workers ----------------

async def trading_loop() -> None:
    await asyncio.sleep(5)
    while True:
        try:
            settings = load_settings(); state = load_state()
            closed = await monitor_trades_once(settings, state)
            for t in closed:
                await notify_all(close_text(t))
            if settings.get("signals_enabled"):
                await run_scan(None)
            await asyncio.sleep(int(settings.get("loop_interval_sec", 45)))
        except asyncio.CancelledError:
            raise
        except Exception:
            logging.exception("trading_loop failed")
            await asyncio.sleep(20)

async def main() -> None:
    global bot
    if not BOT_TOKEN:
        raise RuntimeError("BOT_TOKEN / TELEGRAM_BOT_TOKEN не задан")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    settings = load_settings(); save_settings(settings)
    state = load_state(); save_state(state)
    bot = Bot(BOT_TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    await bot.delete_webhook(drop_pending_updates=True)
    task = asyncio.create_task(trading_loop())
    try:
        await dp.start_polling(bot)
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        await bot.session.close()

if __name__ == "__main__":
    asyncio.run(main())
