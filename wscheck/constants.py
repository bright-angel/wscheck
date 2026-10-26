from __future__ import annotations

DEFAULT_PORTS = {"http": 80, "https": 443}
# 不指定 agent 时 pocsuite3 会在每个请求里 Faker() 生成随机 UA，其 provider 目录扫描在
# 多线程 + 杀软实时防护下会阻塞几十秒，批量执行时整批都卡在第一个请求上
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)
DEFAULT_BODY_LIMIT = 256 * 1024

# 扫描参数默认值：配置对象与任务表单共用，避免两处各写一份后逐渐漂移
SCAN_DEFAULTS = {
    "concurrency": 10,
    "task_timeout": 600,
    "probe_timeout": 5,
    "poc_timeout": 10,
    "verify_timeout": 5,
    "batch_size": 50,
    "allow_internal": False,
    "skip_static": True,
    "negative_verify": True,
}
