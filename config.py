import os

from wscheck.constants import DEFAULT_BODY_LIMIT, DEFAULT_USER_AGENT, SCAN_DEFAULTS

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")

# 信号字段权重：指纹表达式中每个命中的条件按字段权重累加
SIGNAL_WEIGHTS = {
    "title": 30,
    "body": 20,
    "header": 10,
    "server": 10,
    "cert": 20,
    "port": 5,
    "status": 5,
    "app": 30,
    "product": 30,
    "favicon": 25,
}

STATIC_SUFFIXES = (
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg", ".ico",
    ".css", ".js", ".mjs", ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".map", ".mp4", ".mp3", ".avi", ".mov", ".zip", ".rar", ".7z",
    ".tar", ".gz", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
)


class Config:
    SECRET_KEY = os.getenv("WSCHECK_SECRET", "wscheck-dev-secret-change-me")
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "WSCHECK_DB", "sqlite:///" + os.path.join(DATA_DIR, "wscheck.db")
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = 8 * 1024 * 1024

    TIMEZONE = os.getenv("WSCHECK_TZ", "Asia/Shanghai")
    POC_DIR = os.getenv("WSCHECK_POC_DIR", os.path.join(BASE_DIR, "pocs"))
    # POC 仓库同步的清单与备份：清单记录上次由本工具写入的文件，备份用于覆盖失败时回滚
    POC_SYNC_STATE = os.getenv("WSCHECK_POC_SYNC_STATE", os.path.join(DATA_DIR, "poc_sync_state.json"))
    POC_SYNC_BACKUP_DIR = os.getenv("WSCHECK_POC_BACKUP_DIR", os.path.join(DATA_DIR, "poc_sync_backup"))
    RULES_DIR = os.getenv("WSCHECK_RULES_DIR", os.path.join(BASE_DIR, "rules"))
    # 指纹规则仓库同步的清单与备份，与 POC 仓库分开，互不影响
    RULES_SYNC_STATE = os.getenv("WSCHECK_RULES_SYNC_STATE", os.path.join(DATA_DIR, "rules_sync_state.json"))
    RULES_SYNC_BACKUP_DIR = os.getenv("WSCHECK_RULES_BACKUP_DIR", os.path.join(DATA_DIR, "rules_sync_backup"))
    RULES_SEED_STATE = os.path.join(DATA_DIR, "rules_seed_state.json")
    # 主动敏感目录探测字典：应用名 -> 路径列表（放在 rules/dicts 下，避免被当作指纹规则导入）
    DIR_DICT_PATH = os.getenv("WSCHECK_DIR_DICT", os.path.join(BASE_DIR, "rules", "dicts", "dir.yaml"))
    # 单目标最多请求多少个字典路径，防止换成大字典后把任务拖死；0 表示不限制
    DIR_SCAN_MAX_PATHS = int(os.getenv("WSCHECK_DIR_MAX_PATHS", "0"))
    REPORT_DIR = os.path.join(DATA_DIR, "reports")
    EXPORT_DIR = os.path.join(DATA_DIR, "exports")

    SIGNAL_WEIGHTS = SIGNAL_WEIGHTS
    SCAN_DEFAULTS = SCAN_DEFAULTS
    STATIC_SUFFIXES = STATIC_SUFFIXES
    USER_AGENT = DEFAULT_USER_AGENT
    BODY_LIMIT = DEFAULT_BODY_LIMIT
    # 弱口令爆破、依赖 ceye/fofa 等外部平台的 POC 默认不进扫描：
    # 前者对单个目标能发出上万次请求并把任务挂住，后者没有 token 只会超时
    POC_ALLOW_HEAVY = os.getenv("WSCHECK_POC_ALLOW_HEAVY", "0") == "1"
