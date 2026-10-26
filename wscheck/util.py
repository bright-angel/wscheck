from __future__ import annotations


def int_value(value, default: int = 0, minimum: int | None = None,
              maximum: int | None = None) -> int:
    """整数参数解析：非法值退回默认值，再按需夹到给定区间。"""
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    if minimum is not None:
        number = max(minimum, number)
    if maximum is not None:
        number = min(maximum, number)
    return number
