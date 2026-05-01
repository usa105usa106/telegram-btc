import time
from datetime import timedelta

# Глобальная переменная для отслеживания времени запуска бота
BOT_START_TIME = time.time()

def send_ping(chat_id: int) -> None:
    """Улучшенный Ping с uptime"""
    started = time.perf_counter()
    
    try:
        bot.get_me()  # проверяем отзывчивость Bot API
        ping_ms = int((time.perf_counter() - started) * 1000)
    except Exception:
        ping_ms = 999  # если API недоступен

    # Время работы бота
    uptime_seconds = int(time.time() - BOT_START_TIME)
    uptime_str = str(timedelta(seconds=uptime_seconds))

    text = (
        f"🏓 <b>Ping</b>: {ping_ms} ms\n"
        f"⏱ <b>Uptime</b>: {uptime_str}\n"
        f"🔢 <b>Версия бота</b>: {BOT_VERSION}\n"
        f"📊 <b>Проверено в сессии</b>: {checked_counter(chat_id):,}"
    )

    bot.send_message(chat_id, text, reply_markup=main_keyboard(chat_id))