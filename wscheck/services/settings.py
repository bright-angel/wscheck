"""全局设置：把 pocsuite3 SDK 的运行选项（代理、OOB、请求头…）做成可持久化的界面配置。

值存 SQLite 的 settings 表，读取时与字段默认值合并；pocsuite3 只认 init_options 里出现过的键，
所以这里统一负责"空值不传"，避免把 conf 覆盖成空字符串。
"""

from __future__ import annotations

import re
import secrets
import socket
from dataclasses import dataclass, field
from urllib.parse import quote, urlsplit

import requests

from ..extensions import db
from ..models import Setting
from ..timeutil import utcnow
from . import webfetch

MAX_TEXT_VALUE = 4000
MAX_POC_DEFAULTS = 20
DEFAULT_PROXY_TIMEOUT = 10
CEYE_API = "http://api.ceye.io/v1"

# pocsuite3 自己占用的选项名：POC 默认参数不能用这些键，否则会被当成 SDK 全局选项处理
RESERVED_POC_OPTIONS = {
    "url", "url_file", "ports", "poc", "poc_keyword", "mode", "cookie", "host", "referer",
    "agent", "proxy", "proxy_cred", "timeout", "retry", "delay", "headers", "quiet",
    "threads", "batch", "plugins", "output_path", "verbose", "api", "ceye_token",
    "oob_server", "oob_token", "connect_back_host", "connect_back_port", "session-reuse",
}


@dataclass(frozen=True, slots=True)
class Field:
    key: str
    label: str
    kind: str = "text"  # text / password / number / checkbox / textarea
    help: str = ""
    placeholder: str = ""
    default: str = ""
    minimum: int = 0
    maximum: int = 0

    @property
    def is_secret(self) -> bool:
        return self.kind == "password"


@dataclass(frozen=True, slots=True)
class Group:
    key: str
    title: str
    icon: str
    note: str
    fields: tuple[Field, ...] = field(default_factory=tuple)


PROXY_FIELD = Group(
    key="proxy",
    title="网络与代理",
    icon="bi-diagram-3",
    note="代理对 POC 执行、指纹采集、对照校验三条链路都生效。"
         "SOCKS 代理由 pocsuite3 直接替换进程级 socket，本进程其他请求也会一起走代理；"
         "HTTP 代理只影响 requests 的转发。",
    fields=(
        Field("proxy", "代理地址", placeholder="http://127.0.0.1:7890 或 socks5://127.0.0.1:1080",
              help="支持 http / https / socks4 / socks5 / socks5h，格式 scheme://地址:端口；留空表示直连。"),
        Field("proxy_cred", "代理认证", kind="password", placeholder="用户名:密码",
              help="仅在代理要求认证时填写，保存后不会回显。"),
    ),
)

OOB_FIELD = Group(
    key="oob",
    title="OOB 与回连",
    icon="bi-broadcast",
    note="dnslog 类 POC 需要一个可解析的 OOB 域名才能判定命中。配置后 POC 列表里标记"
         "「依赖 OOB 平台」的脚本会自动进入扫描范围；未配置时它们仍会被跳过，"
         "否则 pocsuite3 会卡在交互式输入上。",
    fields=(
        Field("oob_server", "interactsh 域名", placeholder="oast.me",
              help="自建或公共 interactsh 服务域名，POC 用 httpOOb()/Interactsh() 取回调子域。"),
        Field("oob_token", "interactsh Token", kind="password", help="自建服务要求鉴权时填写。"),
        Field("ceye_token", "CEye Token", kind="password",
              help="POC 调用 CEye() 时使用；留空则相关 POC 会被跳过。"),
        Field("connect_back_host", "回连地址",
              placeholder="目标的出网地址，默认留空由 POC 自行决定",
              help="填充 POC 参数里的 {0}/{1} 占位（fastjson、JNDI、反连 shell 一类）。"),
        Field("connect_back_port", "回连端口", kind="number", default="6666",
              minimum=1, maximum=65535, help="与回连地址配套，pocsuite3 默认 6666。"),
    ),
)

FOFA_FIELD = Group(
    key="fofa",
    title="FOFA 目标导入",
    icon="bi-search",
    note="配置 API Key 后，新建任务页可以按 FOFA 查询语句导入扫描目标（结果仍会经过输入层的内网拦截）。"
         "Key 只保存在本地 SQLite，页面不回显；每次导入会消耗 FOFA 账号的查询额度。",
    fields=(
        Field("fofa_key", "FOFA API Key", kind="password",
              placeholder="在 fofa.info 个人中心获取",
              help="仅用于任务创建时的目标导入，不会传给 POC 引擎。"),
    ),
)

POC_REPO_FIELD = Group(
    key="poc_repo",
    title="POC 仓库同步",
    icon="bi-github",
    note="POC 不再随本项目分发，由指定 GitHub 仓库同步到本机 POC 目录。"
         "同步时按文件覆盖，并删除上游已经删掉的 POC；手工放进 POC 目录的其他文件不会被删除。"
         "私有仓库需要填写有 Contents 读取权限的 GitHub Token，Token 只保存在本地 SQLite，页面与日志不回显。",
    fields=(
        Field("poc_repo_url", "仓库地址",
              placeholder="https://github.com/bright-angel/pocsuite3-poc",
              help="填写仓库根地址，目前支持 github.com 的公开或私有仓库。"),
        Field("poc_repo_ref", "分支 / Tag / Commit", placeholder="留空使用仓库默认分支",
              help="例如 main、v1.0.0 或提交 SHA；同步会记录解析到的提交，便于确认版本。"),
        Field("poc_repo_subdir", "POC 子目录", placeholder="pocs（留空表示仓库根目录）",
              help="仓库中存放 POC 的目录；填写后只同步该目录下的文件。"),
        Field("github_token", "GitHub Token", kind="password",
              placeholder="ghp_… 或 github_pat_…",
              help="私有仓库必填；公开仓库填写可提高 API 限额。只需仓库 Contents 读取权限。"),
        Field("poc_auto_sync", "启动时自动同步", kind="checkbox",
              help="勾选后每次启动服务先拉取仓库并重建索引；仓库不可达时记录警告并继续使用本地文件。"),
    ),
)

RULES_REPO_FIELD = Group(
    key="rules_repo",
    title="指纹规则仓库同步",
    icon="bi-shield-check",
    note="指纹规则也可以由指定 GitHub 仓库维护：同步时把仓库里的 YAML 规则文件写入 rules/ 目录，"
         "再按规则 ID 导入数据库。内置规则继续保留；仓库里同 ID 的规则会覆盖名称、表达式与阈值，"
         "页面上手工设置的启用/停用状态保持不变。私有仓库需要填写有 Contents 读取权限的 GitHub Token。",
    fields=(
        Field("rules_repo_url", "规则仓库地址",
              placeholder="https://github.com/<owner>/<repo>",
              help="填写仓库根地址，目前支持 github.com 的公开或私有仓库。"),
        Field("rules_repo_ref", "分支 / Tag / Commit", placeholder="留空使用仓库默认分支",
              help="例如 main、v1.0.0 或提交 SHA；同步会记录解析到的提交，便于确认版本。"),
        Field("rules_repo_subdir", "规则子目录", placeholder="rules（留空表示仓库根目录）",
              help="仓库中存放 YAML 规则的目录；填写后只同步该目录下的文件。"),
        Field("rules_github_token", "GitHub Token", kind="password",
              placeholder="ghp_… 或 github_pat_…",
              help="私有规则仓库必填；公开仓库填写可提高 API 限额。只需仓库 Contents 读取权限。"),
        Field("rules_auto_sync", "启动时自动同步", kind="checkbox",
              help="勾选后每次启动服务先拉取规则仓库；仓库不可达时记录警告并继续使用本地规则。"),
    ),
)

REQUEST_FIELD = Group(
    key="request",
    title="请求与执行",
    icon="bi-arrow-repeat",
    note="这里改的是所有 POC 发出请求的公共形态；单个任务的并发、超时仍在任务表单里设置。"
         "pocsuite3 对 POC 请求固定关闭证书校验（patch 里写死 verify=False），SDK 没有开关，"
         "所以本工具不提供该选项；命令行版的 --delay 在 2.1.0 里是未实现的占位参数，同样没有开放。",
    fields=(
        Field("agent", "User-Agent", placeholder="留空使用 config.py 里的默认 UA"),
        Field("referer", "Referer", placeholder="http://target/portal",
              help="部分 POC 要求来源页才返回业务响应；写进 pocsuite3 的公共请求头，POC 已自带时不覆盖。"),
        Field("host", "Host 头", placeholder="目标 Host 头",
              help="用于按 Host 分桶的虚拟主机，或需要以内部域名访问的目标；只改请求头，不改连接地址。"),
        Field("cookie", "Cookie", placeholder="a=1; b=2",
              help="需要登录态的目标可以在此带上 Cookie，POC 请求会原样携带。"),
        Field("headers", "附加请求头", kind="textarea", placeholder="X-Token: abc\nAuthorization: Bearer xxx",
              help="每行一个 Header: 值，已存在的请求头不会被覆盖。"),
        Field("retry", "连接超时重试", kind="number", default="0", minimum=0, maximum=10,
              help="pocsuite3 只在连接超时这类错误上重试，取值 0-10。"),
        Field("session_reuse", "复用 HTTP 会话（keep-alive）", kind="checkbox",
              help="启用 pocsuite3 的 session 队列，同一批目标复用连接，减少握手开销。"),
        Field("session_reuse_num", "会话池大小", kind="number", default="20", minimum=1, maximum=64,
              help="复用会话时预建的 session 数量，建议不小于任务并发数。"),
        Field("poc_debug", "记录 POC 引擎调试日志", kind="checkbox",
              help="默认只把引擎错误写进任务日志；勾选后连「加载了哪个 POC、每个目标跑的是哪条」"
                   "一起记录，单个批次可能上千行，只在排查为什么扫不出结果时开启。"),
    ),
)

POC_OPTION_FIELD = Group(
    key="poc",
    title="POC 默认参数",
    icon="bi-braces",
    note="部分 POC 声明了必填参数（require=True），不填就会被 pocsuite3 直接判为执行失败。"
         "在这里按 name=value 给出全局默认值，扫描与交互执行都会套用；"
         "POC 自己声明了同名参数时才会生效，不会被用到的参数不影响任何脚本。",
    fields=(
        Field("poc_defaults", "参数默认值", kind="textarea",
              placeholder="cmd=id\npath=/etc/passwd",
              help=f"每行一个 name=value，最多 {MAX_POC_DEFAULTS} 行；"
                   "参数名不能与 pocsuite3 自带选项重名。"),
    ),
)

GROUPS = (PROXY_FIELD, OOB_FIELD, FOFA_FIELD, POC_REPO_FIELD, RULES_REPO_FIELD,
          REQUEST_FIELD, POC_OPTION_FIELD)
FIELDS = tuple(f for group in GROUPS for f in group.fields)
DEFAULTS = {item.key: item.default for item in FIELDS}


def _snapshot() -> dict[str, str]:
    """一次查询读出全部设置；需要多个键的调用方不要再逐个 get。"""
    stored = {row.key: row.value for row in db.session.query(Setting).all()}
    merged = {key: (stored.get(key) or default) for key, default in DEFAULTS.items()}
    for key, value in stored.items():  # 兼容已废弃的键，避免直接丢失
        merged.setdefault(key, value)
    return merged


def values() -> dict[str, str]:
    """当前设置（含未保存过的字段默认值）。"""
    return _snapshot()


def get(key: str) -> str:
    row = db.session.get(Setting, key)
    if row is not None and row.value:
        return row.value
    return DEFAULTS.get(key, "")


def save(form) -> list[str]:
    """校验并保存；只要有一个字段不合法就一项都不写，避免半截提交把配置改花。
    密码类字段留空表示保持原值，勾选清除才置空。"""
    errors: list[str] = []
    staged: list[tuple[str, str]] = []
    for item in FIELDS:
        if item.kind == "checkbox":
            stored = "1" if form.get(item.key) else ""
        else:
            value = (form.get(item.key) or "").strip()
            if item.is_secret and not value and not form.get(f"{item.key}_clear"):
                continue
            if item.key in ("poc_repo_subdir", "rules_repo_subdir"):
                value = value.replace("\\", "/").strip("/")
            stored = value[:MAX_TEXT_VALUE]
        error = _validate(item, stored, form)
        if error:
            errors.append(error)
            continue
        staged.append((item.key, stored))
    if errors:
        return errors
    # 代理被清空时认证信息一并清掉，否则残留的 user:pass 会被下一个代理地址使用
    if not (form.get("proxy") or "").strip():
        staged = [(key, value) for key, value in staged if key != "proxy_cred"]
        staged.append(("proxy_cred", ""))
    # 仓库地址清空后 Token 没有用途，一并清掉，避免敏感值长期留在库里
    if not (form.get("poc_repo_url") or "").strip():
        staged = [(key, value) for key, value in staged if key != "github_token"]
        staged.append(("github_token", ""))
    if not (form.get("rules_repo_url") or "").strip():
        staged = [(key, value) for key, value in staged if key != "rules_github_token"]
        staged.append(("rules_github_token", ""))
    _write(staged)
    return errors


def _validate(item: Field, value: str, form) -> str:
    if not value:
        return ""
    if item.key == "proxy":
        return _validate_proxy(value, form.get("proxy_cred") or get("proxy_cred"))
    if item.key == "proxy_cred" and ":" not in value:
        return "代理认证格式应为 用户名:密码"
    if item.kind == "number":
        return _validate_number(item, value)
    if item.key == "poc_defaults":
        return _validate_poc_defaults(value)
    if item.key in ("poc_repo_url", "poc_repo_ref", "poc_repo_subdir",
                    "rules_repo_url", "rules_repo_ref", "rules_repo_subdir"):
        return _validate_repo_field(item, value)
    if item.key == "headers":
        for line in value.splitlines():
            if line.strip() and ":" not in line:
                return f"附加请求头 {line[:40]} 缺少冒号"
    return ""


def _validate_proxy(value: str, cred: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return "代理地址格式无效，正确形式如 http://127.0.0.1:7890"
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https", "socks4", "socks5", "socks5h"):
        return "代理地址需要 http/https/socks4/socks5/socks5h 开头的 scheme"
    if not parsed.hostname:
        return "代理地址缺少主机名，正确形式如 http://127.0.0.1:7890"
    if not port:
        return "代理地址缺少端口，正确形式如 http://127.0.0.1:7890"
    if cred and ":" not in cred:
        return "代理认证格式应为 用户名:密码"
    return ""


def _validate_number(item: Field, value: str) -> str:
    try:
        number = int(value)
    except ValueError:
        return f"{item.label} 必须是整数"
    if not item.minimum <= number <= item.maximum:
        return f"{item.label} 取值范围 {item.minimum}-{item.maximum}"
    return ""


def _validate_poc_defaults(value: str) -> str:
    lines = [line for line in value.splitlines() if line.strip()]
    if len(lines) > MAX_POC_DEFAULTS:
        return f"POC 默认参数最多 {MAX_POC_DEFAULTS} 行"
    for line in lines:
        name, sep, _ = line.partition("=")
        name = name.strip()
        if not sep:
            return f"POC 默认参数 {line[:40]} 缺少等号"
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,31}", name):
            return f"POC 参数名 {name} 不合法"
        if name.lower() in RESERVED_POC_OPTIONS:
            return f"POC 参数名 {name} 与 pocsuite3 自带选项冲突，请改用脚本内的其他参数"
    return ""


def _validate_repo_field(item: Field, value: str) -> str:
    from . import repo_sync

    try:
        if item.key.endswith("_url"):
            repo_sync.parse_repo_url(value)
        elif item.key.endswith("_ref"):
            repo_sync.normalize_ref(value)
        else:
            repo_sync.normalize_subdir(value)
    except repo_sync.SyncError as error:
        return str(error)
    return ""


def _write(staged: list[tuple[str, str]]) -> None:
    """所有字段一次性提交，避免保存中途失败留下半套配置。"""
    if not staged:
        return
    keys = [key for key, _ in staged]
    existing = {row.key: row for row in db.session.query(Setting)
                .filter(Setting.key.in_(keys)).all()}
    now = utcnow()
    for key, value in staged:
        row = existing.get(key)
        if row is None:
            row = Setting(key=key)
            db.session.add(row)
        row.value = value
        row.updated_at = now
    db.session.commit()


def _proxy_label(value: str) -> str:
    """用于提示与日志的代理地址：只保留 scheme://host:port，绝不带认证信息。"""
    parsed = urlsplit(value)
    host = parsed.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    try:
        port = f":{parsed.port}" if parsed.port else ""
    except ValueError:
        port = ""
    return f"{parsed.scheme}://{host}{port}" if host else "代理"


def proxy_display(value: str = "") -> str:
    """页面展示用的代理地址：只保留 scheme://host:port，绝不带出认证信息。"""
    value = (value or get("proxy")).strip()
    return _proxy_label(value) if value else ""


def proxy_url(proxy: str = "", cred: str = "") -> str:
    """requests 形态的代理 URL（认证信息拼进 URL）；pocsuite3 用 proxy + proxy_cred 两个键。"""
    value = (proxy or get("proxy")).strip()
    if not value:
        return ""
    cred = cred or get("proxy_cred")
    if not cred:
        return value
    username, sep, password = cred.partition(":")
    auth = quote(username, safe="")
    if sep:
        auth += ":" + quote(password, safe="")
    parsed = urlsplit(value)
    host = parsed.netloc.rsplit("@", 1)[-1]
    return f"{parsed.scheme}://{auth}@{host}"


def http_proxies(proxy: str = "", cred: str = "") -> dict[str, str]:
    url = proxy_url(proxy, cred)
    return {"http": url, "https": url} if url else {}


def oob_ready() -> bool:
    """是否具备跑 dnslog 类 POC 的条件。"""
    snap = _snapshot()
    return bool(snap.get("oob_server") or snap.get("ceye_token"))


def poc_options() -> dict:
    """构造 pocsuite3 init_options 需要的额外键，空值一律不传。"""
    snap = _snapshot()
    options = {}
    for key in ("proxy", "proxy_cred", "oob_server", "oob_token", "ceye_token",
                "connect_back_host", "cookie", "headers", "referer", "host"):
        value = snap.get(key, "")
        if value:
            options[key] = value
    if snap.get("connect_back_port"):
        options["connect_back_port"] = snap["connect_back_port"]
    if snap.get("retry") not in ("", "0"):
        options["retry"] = int(snap["retry"])
    if snap.get("session_reuse"):
        options["requests_session_reuse"] = True
        options["requests_session_reuse_num"] = int(snap.get("session_reuse_num") or 20)
    options.update(parse_poc_defaults(snap.get("poc_defaults", "")))
    return options


def debug_logs() -> bool:
    """是否把 pocsuite3 引擎的 INFO 日志一并写进任务日志。"""
    return bool(get("poc_debug"))


def parse_poc_defaults(value: str | None = None) -> dict[str, str]:
    result = {}
    for line in (get("poc_defaults") if value is None else value).splitlines():
        name, sep, item = line.partition("=")
        if sep and name.strip():
            result[name.strip()] = item.strip()
    return result


def user_agent() -> str:
    from flask import current_app

    return get("agent") or current_app.config.get("USER_AGENT", "")


def summary(snap: dict[str, str] | None = None) -> str:
    """给任务日志用的一行摘要，绝不带出 token、密码等敏感值。"""
    snap = snap or _snapshot()
    parts = []
    if snap.get("proxy"):
        parts.append(f"代理 {_proxy_label(snap['proxy'])}")
    if snap.get("oob_server"):
        parts.append(f"OOB {snap['oob_server']}")
    if snap.get("ceye_token"):
        parts.append("CEye 已配置")
    if snap.get("fofa_key"):
        parts.append("FOFA 已配置（目标导入）")
    if snap.get("poc_repo_url"):
        ref = f"@{snap['poc_repo_ref']}" if snap.get("poc_repo_ref") else ""
        parts.append(f"POC 仓库 {snap['poc_repo_url']}{ref}")
    if snap.get("github_token"):
        parts.append("GitHub Token 已配置")
    if snap.get("poc_auto_sync"):
        parts.append("启动时同步 POC 仓库")
    if snap.get("rules_repo_url"):
        ref = f"@{snap['rules_repo_ref']}" if snap.get("rules_repo_ref") else ""
        parts.append(f"指纹规则仓库 {snap['rules_repo_url']}{ref}")
    if snap.get("rules_github_token"):
        parts.append("规则仓库 Token 已配置")
    if snap.get("rules_auto_sync"):
        parts.append("启动时同步规则仓库")
    if snap.get("connect_back_host"):
        parts.append(f"回连 {snap['connect_back_host']}:{snap.get('connect_back_port') or 6666}")
    if snap.get("cookie"):
        parts.append("公共 Cookie")
    if snap.get("referer"):
        parts.append(f"Referer {snap['referer']}")
    if snap.get("host"):
        parts.append(f"Host {snap['host']}")
    if snap.get("headers"):
        parts.append(f"附加请求头 {len(snap['headers'].splitlines())} 条")
    if snap.get("session_reuse"):
        parts.append(f"会话复用 {snap.get('session_reuse_num')}")
    if snap.get("poc_debug"):
        parts.append("引擎调试日志")
    defaults = parse_poc_defaults(snap.get("poc_defaults", ""))
    if defaults:
        parts.append("POC 默认参数 " + "、".join(defaults))
    return "、".join(parts)


def _from_form(form, key: str) -> str:
    """自测按表单当前填写的值走，留空回落到已保存的值——密码框刷新后总是空的。"""
    if form is not None:
        value = (form.get(key) or "").strip()
        if value:
            return value
    return get(key)


def test_proxy(url: str = "", form=None) -> tuple[bool, str]:
    """先测代理端口能否连通，给了地址再测通过代理取一次。"""
    value = _from_form(form, "proxy")
    proxies = http_proxies(value, _from_form(form, "proxy_cred"))
    if not value:
        return False, "未配置代理地址"
    parsed = urlsplit(value)
    label = _proxy_label(value)
    try:
        host, port = parsed.hostname, parsed.port
    except ValueError:
        return False, f"代理地址 {label} 格式不正确"
    if not host or not port:
        return False, f"代理地址 {label} 缺少主机名或端口"
    try:
        with socket.create_connection((host, port), timeout=DEFAULT_PROXY_TIMEOUT):
            pass
    except OSError as error:
        return False, f"代理 {label} 连不上：{type(error).__name__}: {error}"
    if not url:
        return True, f"代理 {label} 端口可连通"
    if not _looks_http(url):
        return False, "测试地址需要 http:// 或 https:// 开头"
    try:
        response = webfetch.get(url, timeout=DEFAULT_PROXY_TIMEOUT, proxies=proxies,
                                limit=64 * 1024)
    except (requests.RequestException, ValueError) as error:
        return False, f"经代理请求 {url} 失败：{type(error).__name__}"
    return True, f"经代理请求 {url} 返回 {response.status_code}，读取 {len(response.content)} 字节"


def test_fofa(form=None) -> tuple[bool, str]:
    """校验 FOFA Key；延迟导入 fofa，避免 settings ↔ fofa 的循环依赖。"""
    from . import fofa

    return fofa.verify(
        _from_form(form, "fofa_key"),
        http_proxies(_from_form(form, "proxy"), _from_form(form, "proxy_cred")),
    )


def test_poc_repo(form=None) -> tuple[bool, str]:
    """校验仓库地址与 Token 能否访问，只调用 API，不下载、不覆盖本地 POC。"""
    from .poc import sync

    cfg = sync.RepositoryConfig(
        repo_url=_from_form(form, "poc_repo_url"),
        ref=_from_form(form, "poc_repo_ref"),
        subdir=_from_form(form, "poc_repo_subdir"),
        token=_from_form(form, "github_token"),
    )
    return sync.check_repository(
        cfg, http_proxies(_from_form(form, "proxy"), _from_form(form, "proxy_cred"))
    )


def test_rules_repo(form=None) -> tuple[bool, str]:
    """校验规则仓库地址与 Token 能否访问，只调用 API，不下载、不覆盖本地规则。"""
    from . import repo_sync

    cfg = repo_sync.RepositoryConfig(
        repo_url=_from_form(form, "rules_repo_url"),
        ref=_from_form(form, "rules_repo_ref"),
        subdir=_from_form(form, "rules_repo_subdir"),
        token=_from_form(form, "rules_github_token"),
    )
    return repo_sync.check_repository(
        cfg, http_proxies(_from_form(form, "proxy"), _from_form(form, "proxy_cred"))
    )


def test_oob(form=None) -> tuple[bool, str]:
    """检查 OOB 域名能否解析、能否注册；CEye 则验证 token 是否可用。"""
    messages = []
    ok = False
    proxies = http_proxies(_from_form(form, "proxy"), _from_form(form, "proxy_cred"))
    server = _from_form(form, "oob_server")
    if server:
        ok, message = _test_interactsh(server, proxies)
        messages.append(message)
    token = _from_form(form, "ceye_token")
    if token:
        ceye_ok, message = _test_ceye(token, proxies)
        messages.append(message)
        ok = ok or ceye_ok
    if not messages:
        return False, "未配置 oob_server 或 ceye token"
    return ok, "；".join(messages)


def _test_interactsh(server: str, proxies: dict) -> tuple[bool, str]:
    sample = f"{secrets.token_hex(4)}.{server}"
    try:
        socket.getaddrinfo(sample, None)
    except OSError:
        return False, f"{server} 未提供泛解析（{sample} 无法解析），POC 拿不到回调子域"
    try:
        with requests.Session() as http:
            response = webfetch.request(
                http, "POST", f"http://{server}/register",
                headers={"Content-Type": "application/json"},
                json={"public-key": "", "secret-key": "wscheck", "correlation-id": sample[:20]},
                proxies=proxies, timeout=DEFAULT_PROXY_TIMEOUT)
            status = response.status_code
            text = response.text
    except requests.RequestException as error:
        return False, f"{server} 可解析但 /register 请求失败：{type(error).__name__}"
    if status == 401:
        return False, f"{server} 要求鉴权，请填写 interactsh Token"
    if "success" not in text:
        return True, f"{server} 可解析，/register 返回 {status}（非标准响应，仍可使用）"
    return True, f"{server} 可用，回调示例子域 {sample}"


def _test_ceye(token: str, proxies: dict) -> tuple[bool, str]:
    try:
        with requests.Session() as http:
            # 不走 requests.get：POC 执行期间它会被 pocsuite3 的 hook 接管，带上 POC 的代理
            response = webfetch.request(
                http, "GET", f"{CEYE_API}/identify",
                headers={"Authorization": token, "User-Agent": "curl/7.80.0"},
                proxies=proxies, timeout=DEFAULT_PROXY_TIMEOUT)
            status = response.status_code
            try:
                payload = response.json()
            except ValueError:
                payload = None
    except requests.RequestException as error:
        return False, f"api.ceye.io 请求失败：{type(error).__name__}"
    if status != 200:
        return False, f"CEye 返回 {status}，token 可能无效"
    if not isinstance(payload, dict):
        return False, "CEye 返回 200 但内容不是 JSON，无法验证 token（请求可能被代理或网关拦截）"
    data = payload.get("data")
    identify = data.get("identify", "") if isinstance(data, dict) else ""
    return True, f"CEye token 有效，接入域 {identify}" if identify else "CEye token 有效"


def _looks_http(url: str) -> bool:
    return urlsplit(url).scheme in ("http", "https")
