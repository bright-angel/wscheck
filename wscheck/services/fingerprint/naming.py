"""应用名归一化。

POC 的 appName 与指纹规则的 app_name 都允许用英文逗号声明多个名称，
比较时逐个拆开、统一小写并去掉标点后再判断是否指同一产品。
"""

from __future__ import annotations

import re


def canonical_app(name: str) -> str:
    return re.sub(r"[^0-9a-z\u4e00-\u9fff]+", "", (name or "").lower())


def split_app_names(value) -> list[str]:
    """把 "GitLab, Jenkins" 拆成 ["GitLab", "Jenkins"]；列表/元组形式也接受。"""
    if isinstance(value, (list, tuple, set)):
        parts = [str(item) for item in value]
    else:
        parts = str(value or "").split(",")
    return [part.strip() for part in parts if part.strip()]


def app_keys(value) -> set[str]:
    return {key for key in (canonical_app(part) for part in split_app_names(value)) if key}


def related_keys(left: str, right: str) -> bool:
    if not left or not right:
        return False
    if left == right:
        return True
    # 短名字（如 "oa"）按包含判断会把无关产品也算命中，只在双方都有足够长度时放宽
    return len(left) >= 4 and len(right) >= 4 and (left in right or right in left)


def related_app(left, right) -> bool:
    """两个应用名（都可以是逗号分隔的多个）是否至少有一项指同一产品。"""
    return any(related_keys(a, b) for a in app_keys(left) for b in app_keys(right))
