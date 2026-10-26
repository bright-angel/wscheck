"""时间处理：数据库统一存 UTC naive，展示按会话时区（默认北京时间）。"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

TIMEZONES = [
    ("Asia/Shanghai", "北京时间 (UTC+8)"),
    ("Asia/Singapore", "新加坡 (UTC+8)"),
    ("Asia/Tokyo", "东京 (UTC+9)"),
    ("UTC", "UTC"),
    ("Europe/London", "伦敦"),
    ("Europe/Berlin", "柏林"),
    ("America/New_York", "纽约"),
    ("America/Los_Angeles", "洛杉矶"),
    ("Australia/Sydney", "悉尼"),
]

DATETIME_FMT = "%Y-%m-%d %H:%M:%S"
DATE_FMT = "%Y-%m-%d %H:%M"


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def resolve_tz(name: str | None):
    try:
        return ZoneInfo(name or "Asia/Shanghai")
    except (ZoneInfoNotFoundError, ValueError):
        return timezone(timedelta(hours=8))


def to_local(value: datetime | None, tz_name: str | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc).astimezone(resolve_tz(tz_name))


def fmt_dt(value: datetime | None, tz_name: str | None = None, fmt: str = DATETIME_FMT) -> str:
    local = to_local(value, tz_name)
    return local.strftime(fmt) if local else "-"


def fmt_span(pair) -> str:
    """接收 (开始, 结束) 序列，结束为空时按当前时间计算耗时。"""
    start, end = (list(pair) + [None, None])[:2]
    if not start:
        return "-"
    delta = (end or utcnow()) - start
    seconds = int(delta.total_seconds())
    if seconds < 0:
        return "-"
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m{seconds % 60:02d}s"
    return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m"


def init_app(app):
    from flask import g

    @app.context_processor
    def inject_timezone():
        g.tz = session_tz()
        return {"current_tz": g.tz, "timezone_options": TIMEZONES}

    app.jinja_env.globals["local_now"] = lambda: fmt_dt(utcnow(), session_tz())
    app.jinja_env.filters["dt"] = lambda v, fmt=DATETIME_FMT: fmt_dt(v, session_tz(), fmt)
    app.jinja_env.filters["date"] = lambda v: fmt_dt(v, session_tz(), DATE_FMT)
    app.jinja_env.filters["duration"] = fmt_span
    app.jinja_env.filters["now"] = lambda: fmt_dt(utcnow(), session_tz())


def session_tz() -> str:
    from flask import current_app, has_request_context, session

    if has_request_context() and session.get("tz"):
        return session["tz"]
    return current_app.config["TIMEZONE"]
