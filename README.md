# WSCHECK · Web 安全检测工具

指纹驱动的快速 Web 安全检测工具：FOFA 风格指纹规则 + pocsuite3 POC 生态 + 任务化扫描 + 结果治理，
全部功能通过 Web 控制台完成（简体中文界面，时间按所选时区展示，默认北京时间）。

> 仅供获得授权的安全测试与研究使用。扫描、指纹表达式测试与负向对照校验都会真实访问目标。

## 技术栈

Flask 3.1 + Blueprint · Bootstrap 5.3 · SQLAlchemy 2.0（Flask-SQLAlchemy）· SQLite · pocsuite3 2.1 SDK

## 安装与运行

```bash
uv sync                      # 或 pip install -r requirements.txt
uv run python run.py --host 127.0.0.1 --port 8080
```

浏览器打开 <http://127.0.0.1:8080> 。首次启动会自动：

1. 建表（`data/wscheck.db`，可用 `WSCHECK_DB` 覆盖）；
2. 导入 `rules/` 目录下所有 YAML 指纹规则（按文件记录在 `data/rules_seed_state.json`，
   已导入过的文件不会重复写入，删除的规则不会被"复活"，之后以数据库为准；也可由设置里的
   指纹规则仓库同步维护）；
3. 静态解析 POC 目录建立索引（不执行 POC 代码）；POC 由「设置 → POC 仓库同步」指定的
   GitHub 仓库提供，同步完成后自动重建索引；
4. 把上次进程遗留的未完成任务标记为失败。

首次启动后，在「设置 → POC 仓库同步」填写仓库地址（私有仓库再填 GitHub Token），
保存后到 POC 页点击「从仓库同步」；勾选"启动时自动同步"可以让服务每次启动先拉取仓库。
指纹规则同理，可在「设置 → 指纹规则仓库同步」配置另一个仓库，并在指纹规则页点击「从规则仓库同步」。

环境变量：`WSCHECK_DB`、`WSCHECK_SECRET`、`WSCHECK_TZ`、`WSCHECK_POC_DIR`、`WSCHECK_RULES_DIR`、
`WSCHECK_DIR_DICT`（主动目录探测字典，默认 `rules/dicts/dir.yaml`）、`WSCHECK_DIR_MAX_PATHS`
（单目标最多探测多少条字典路径，`0` 表示不限制）、`WSCHECK_POC_SYNC_STATE`（POC 同步清单路径）、
`WSCHECK_POC_BACKUP_DIR`（POC 同步前备份目录）、`WSCHECK_RULES_SYNC_STATE`（规则同步清单路径）、
`WSCHECK_RULES_BACKUP_DIR`（规则同步前备份目录，均默认在 `data/` 下）。

### Docker Compose

仓库自带 `Dockerfile` 与 `docker-compose.yml`，无需安装 Python：

```bash
docker compose up -d --build
```

浏览器打开 <http://127.0.0.1:8080> 。默认端口映射只监听本机，需要局域网访问时用
`WSCHECK_BIND=0.0.0.0 docker compose up -d`。`./data`（SQLite、报告、同步清单与备份）、
`./pocs`、`./rules` 都挂载到宿主机目录，重建容器不会丢数据，同步下来的 POC 与指纹规则
也可以直接在宿主机上查看和编辑。

常用变量（可写进 `.env` 或命令行前置；仓库提供 `.env.example`，复制为 `.env` 后修改即可）：

| 变量 | 默认值 | 说明 |
| ---- | ------ | ---- |
| `WSCHECK_SECRET` | 开发用默认值 | Flask 会话密钥，部署时务必改成随机值 |
| `WSCHECK_BIND` / `WSCHECK_PORT` | `127.0.0.1` / `8080` | 监听地址与宿主机端口 |
| `WSCHECK_TZ` | `Asia/Shanghai` | 页面时区 |
| `WSCHECK_DIR_MAX_PATHS` | `0` | 单目标目录探测路径上限，`0` 表示不限制 |
| `WSCHECK_POC_ALLOW_HEAVY` | `0` | 设为 `1` 时把爆破、依赖 OOB 的 POC 放回自动扫描 |

容器内是单进程运行（任务状态与 POC 引擎锁都在进程内），不要用 `--scale` 起多个副本。
扫描目标里的 `127.0.0.1` 指向容器自身；要扫宿主机上的演练站点，使用
`http://host.docker.internal:8999`（compose 已配置映射），并按需勾选"允许内网目标"。

## 使用流程

| 步骤 | 页面 | 说明 |
| ---- | ---- | ---- |
| 1 | 指纹 | 维护 FOFA 风格规则（可手工维护，也可从 GitHub 仓库同步），`/fingerprints/test` 可用真实目标验证表达式与得分 |
| 2 | POC | 到设置里配置 GitHub 仓库后同步/重建索引，查看索引结果（可按"引擎不加载"筛选）、启停单个 POC；详情页展示元数据、可填参数、参考链接与脚本片段 |
| 3 | 任务 → 新建 | 输入 URL / IP / CIDR / 域名（也可用 FOFA 查询导入），选择扫描模式、并发、超时、指纹与 POC 范围后开始 |
| 4 | 任务详情 | 进度实时轮询，结果 / 资产 / 日志三个页签（均分页），资产页展示指纹与目录命中，可取消、重试、导出 |
| 5 | 结果 | 复核（确认有效 / 标记误报 / 重置）、批量处理与批量导出、按等级/时间排序、人工补充结果 |
| 6 | 报告 | 勾选多个任务合并生成 HTML / Markdown / JSON / CSV 并下载 |

扫描流水线：输入规范化 → 指纹采集与求值 →（全指纹 / 指纹漏洞）主动目录探测 → 按模式筛选 POC
→ pocsuite3 执行 → 负向对照校验 → 落库。

### 报告内容

四种格式的导出与合并报告都包含"任务概览 → 指纹识别 → 检测结果"三部分。指纹识别章节按任务
列出采集到的资产：URL、状态码、页面标题、应用指纹及得分、组件、目录命中（路径与状态码）、
Server 与采集异常，内容与任务详情「资产」页签一致。JSON 报告在 `assets` 数组给出同样的数据，
`summary` 里附带 `assets`、`fingerprinted`、`dir_hits`、`probe_errors` 计数，schema 为
`wscheck.report/v3`；CSV 在结果表之后以"指纹识别结果"标题追加独立区块；单个任务导出与
勾选结果导出同样适用（勾选导出会带上相关任务的全部资产）。

### 从 FOFA 导入目标

在「设置 → FOFA 目标导入」保存 API Key 后，新建任务页的目标列表下方会出现导入框：
填写 FOFA 查询语句（如 `app="Nacos" && country="CN"`）和数量（单次最多 100 条），
点击“导入目标”即可把结果追加到上方列表并自动去重。导入只请求官方 `fofa.info` API，
沿用全局代理设置；返回的 URL 仍会经过输入层解析，内网地址同样要显式勾选“允许内网目标”。
每次查询消耗账号额度；设置页的“测试 FOFA Key”使用 `info/my`，不消耗搜索次数。

## 扫描模式

新建任务时四选一，默认"指纹漏洞扫描"：

| 模式 | 指纹采集 | 主动目录探测 | POC |
| ---- | -------- | ------------ | --- |
| 指纹扫描 | ✓ | ✗ | ✗ |
| 全指纹扫描 | ✓ | ✓ | ✗ |
| 指纹漏洞扫描 | ✓ | ✓ | 有指纹的目标按 `appName` 匹配；未识别到指纹的目标回落全量（仍跳过爆破、依赖 OOB 与引擎不加载的脚本） |
| 专项扫描 | ✓ | ✗ | 只跑手工勾选的；一个都不勾则按指纹匹配 |

"全指纹扫描"会在普通指纹之外，按字典主动请求常见的敏感路径（Nacos、Druid、Swagger、Actuator、
Tomcat Manager、报错页等）。字典是 `应用名 -> [路径…]`，默认读取 `rules/dicts/dir.yaml`
（32 个应用 / 74 条路径），换成自己的字典时用 `WSCHECK_DIR_DICT` 指定路径即可，下次任务生效。

命中判定（尽量压掉反向代理的伪 200）：

* 每个目标先请求一个随机不存在的路径作为软 404 基线；请求路径带后缀时按后缀各取一份基线
  （有些站点任意 `.html` 都回首页），根路径则对照首页。状态码相同且正文一致（忽略路径回显与空白）
  视为同一种"找不到"页面，不计命中。
* 响应里识别出的指纹与字典应用是同一个产品（归一化名称相等或包含）时直接算命中，这是强证据；
  否则只有 200 / 401 / 403 且不落进软 404 才算命中——401/403 说明路径存在但需要认证。
* 单个应用命中第一条有效路径即停止；单目标墙钟上限 `max(30, 8 × 单次超时)`，
  可在 `WSCHECK_DIR_MAX_PATHS` 限制请求数，取消请求在每条路径之间检查。
* 软 404 基线、404 / 500 报错页本身也会送进指纹引擎（正文窗口 32 KB）：框架的调试/错误页常在
  页面后半段才露出标识，例如 ThinkPHP 的"系统发生错误"页里 `ThinkPHP` 字样在 6 KB 之后，
  只截前 4 KB 就会漏掉。识别结果会补进资产的 `fingerprint` / `app_names`，即使一条目录都没命中，
  也能参与"指纹对应 POC"的筛选。
* 目录命中的应用会并入资产的 `app_names`，因此能参与"指纹对应 POC"的筛选，并在任务详情
  的资产页单独列出；探测请求与指纹采集共用代理设置。

任务重试沿用原任务的 `config_json`；旧任务里只有 `poc_scope` 的配置会自动映射
（`all` → 指纹漏洞，其余 → 专项扫描），不会因为字段改名而失败。

## 指纹语法

字段 `title body header server cert port status app product favicon`，运算符 `=`（包含）、
`!=`（不包含）、`==`（完全相等）、`~=`（正则，非法正则永不命中），逻辑 `&& || ! ()`，字符串用引号包裹。

* 别名：`banner`、`content_type` → `header`，`icon_hash` → `favicon`，`status_code` → `status`。
* `~=` 的值里 `\s`、`\d` 等正则转义会原样保留，只有 `\"`、`\'`、`\\` 会被还原。
* 字段未采集到（空信号）时 `!=` 判定为不命中，避免"没有数据"造成大面积误命中。
* 匹配统一按小写进行，不区分大小写。

得分 = 所有命中条件的字段权重之和（`title=30 body=20 cert=20 app=30 product=30 favicon=25
header=10 server=10 port=5 status=5`，见 `config.py`），命中判定要求布尔表达式为真 **且** 得分 ≥ 阈值。
与 `demo.md` 的"短路计分"不同，这里所有条件都参与累加，规则阈值需按可达分值设定；
阈值 `0` 即退化为纯布尔命中（迁移规则采用这种写法）。

## webfinger 规则迁移

`rules/webfinger.yaml` 由 `tools/migrate_webfinger.py` 从外部 `webfinger.yaml`
（`AppName: [表达式, …]`，7160 个应用 / 8118 条表达式）转换生成，请勿手工编辑：

```bash
python tools/migrate_webfinger.py --src C:/path/to/webfinger.yaml --out rules/webfinger.yaml
```

| 处理 | 数量 | 说明 |
| ---- | ---- | ---- |
| 保留表达式 | 7963 | 字段别名归一化后按 AST 重新序列化 ，`||` 合并为一条规则 |
| 生成规则 | 7025 | 一个应用一条规则，`threshold: 0`，`app_name` 把 `-`/`_` 归一为空格 |
| 丢弃表达式 | 153 | `protocol`(136)、`path`(11)、`icon_mdhash`(4)、`type`(1)、`body_hash`(1) 属于探测阶段字段，无对应响应信号 |
| 语法错误 | 2 | 源表达式本身残缺（缺操作数、非法字符）， 已跳过 |
| 整体跳过的应用 | 135 | 全部表达式都被丢弃或报错 |

与内置 19 条规则重名的 id 会加 `-wf` 后缀（如 `jenkins-wf`），保证导入互不覆盖。
更新规则库时重新执行脚本、删除 `data/rules_seed_state.json` 中对应条目并重启服务即可重新导入；
若规则已迁到 GitHub 仓库维护，直接用指纹规则页的「从规则仓库同步」覆盖更新即可。

7044 条规则下的实测：引擎构建（解析全部 AST）约 0.3 s，单目标识别 8 KB 响应体约 0.05 s、
256 KB 约 0.5 s；信号按目标统一小写一次，比较值与正则在引擎内缓存，第二遍求值仅重跑
使用 `app`/`product` 字段的组合规则。新建任务页的规则 / POC 勾选改为搜索式选择器
（`/tasks/picker`），避免渲染七千余个复选框。

POC 自动筛选按归一化名称（去大小写、去分隔符，保留中文）比对指纹 `app_name` 与 POC `appName`，
例如指纹 `Spring Boot` 可命中 `appName=SpringBoot` 的 POC。指纹扫描 / 全指纹扫描不执行 POC；
指纹漏洞模式对未识别到指纹的目标回落到全量 POC（同样跳过爆破、依赖 OOB 与引擎不加载的脚本），
专项模式只认手工勾选，未勾选时才按指纹匹配。

## 指纹规则仓库同步

指纹规则既可以在页面上手工维护、由 `rules/` 里的 YAML 初始化，也可以由「设置 → 指纹规则仓库同步」
指定的 GitHub 仓库统一维护。填写仓库根地址后，在指纹规则页点击「从规则仓库同步」即可：
通过与 POC 同步相同的 GitHub REST API 下载 zipball（不执行任何脚本，也不调用 git 命令），
把仓库（或子目录）下的 `.yaml` / `.yml` 写入 `rules/` 并导入数据库。

| 配置 | 说明 |
| ---- | ---- |
| 仓库地址 | 目前支持 github.com 的公开或私有仓库，填仓库根地址，不要带 `/tree/` 等路径；与 POC 仓库互相独立 |
| 分支 / Tag / Commit | 留空使用仓库默认分支；同步会记录实际解析到的提交，便于确认规则版本 |
| 规则子目录 | 规则不在仓库根目录时填写（如 `rules`），只同步该目录下的文件 |
| GitHub Token | 私有仓库必填，需要 Contents 读取权限；与 POC 仓库的 Token 分开保存，页面、日志与自测结果都不回显 |
| 启动时自动同步 | 勾选后每次启动先拉取规则仓库；仓库不可达时记录警告并继续使用本地规则 |

同步行为：

* 规则按 `id` 做 upsert：新增的直接写入，已有的更新名称、表达式、阈值、`app_name` 与备注；
  **启用 / 停用状态保留用户在页面上的选择**，不会被仓库内容覆盖。
* 只有"上次由同步写入、现在仓库和本地规则文件里都不存在"的规则才会被删除；
  内置规则与手工新建的规则不受影响。
* YAML 格式与 `rules/*.yaml` 一致：列表每一项至少包含 `id` 与 `expr`，可选 `name`、`threshold`
  （默认 30）、`app_name`、`note`、`enabled`；缺字段或格式错误的条目会跳过并在页面提示数量。
* 文件清单写入 `data/rules_sync_state.json`（含已同步的规则 id），覆盖或删除前把旧文件备份到
  `data/rules_sync_backup/<时间戳>/`（保留最近 3 次），写盘失败会尝试回滚；同步完成后立即重建
  表达式 AST 缓存，无需重启服务。
* 与 POC 同步共用一把同步锁，同一时间只允许一个仓库同步；文件大小 / 文件数上限、解压路径校验、
  同名文件大小写冲突与杀软隔离文件的跳过策略都与 POC 同步一致。
* 规则仓库自动同步在导入内置规则之后执行；仓库里的同 id 规则会覆盖内置内容，但不会改动其启用状态。

## POC 仓库同步

POC 不再随项目分发，统一由「设置 → POC 仓库同步」指定的 GitHub 仓库提供。填写仓库根地址
（例如 `https://github.com/bright-angel/pocsuite3-poc`）后，在 POC 页点击「从仓库同步」即可：
通过 GitHub REST API 下载该分支的 zipball，静态解析后重建索引（不执行 POC 代码，不调用 git 命令）。

| 配置 | 说明 |
| ---- | ---- |
| 仓库地址 | 目前支持 github.com 的公开或私有仓库，填仓库根地址，不要带 `/tree/` 等路径 |
| 分支 / Tag / Commit | 留空使用仓库默认分支；同步会记录实际解析到的提交，便于确认版本 |
| POC 子目录 | POC 不在仓库根目录时填写（如 `pocs`），只同步该目录下的文件 |
| GitHub Token | 私有仓库必填，需要 Contents 读取权限；公开仓库可选，用于提高 API 限额 |
| 启动时自动同步 | 勾选后每次启动先拉取仓库；仓库不可达时记录警告并继续使用本地文件 |

同步行为：

* 文件清单写入 `data/poc_sync_state.json`。下次同步只删除"上次由本工具写入、上游已删除"的文件，
  手工放进 POC 目录的其他文件不会被删除。
* 覆盖或删除前把旧文件备份到 `data/poc_sync_backup/<时间戳>/`（保留最近 3 次），
  写盘失败会尝试回滚；同步完成后自动重建 `poc_registry` 索引，POC 的启用/停用状态按 `poc_id` 保留。
* 私有仓库的 Token 只保存在本地 SQLite，页面、任务日志和自测结果都不回显；同步失败信息里也不会带出 Token。
* 下载有大小与文件数上限（单文件超过 8 MB 的资源会跳过），解压时拒绝绝对路径、`..` 和符号链接；
  同仓库内仅大小写不同的文件名在 Windows 上会被拒绝同步。
* POC 引擎正在执行任务时拒绝同步，等任务结束后再试，避免替换正在读取的脚本。
* 个别 POC 在写入前后被本机安全软件（如火绒、Defender）按恶意文件隔离时，同步会跳过这些文件并在页面
  给出警告，其余文件照常写入；若全部被隔离则同步失败并提示。遇到这种情况把 POC 目录加入杀毒软件信任
  后重新同步即可。

外部 POC 里包含 RCE、文件上传、路径穿越等**具有实际利用行为**的脚本，只可指向明确授权的目标；
需要保守扫描时，在任务表单里用"手动选择"只勾选只读类 POC，或在 POC 页停用相应脚本。
POC 一律通过 pocsuite3 的受控 SDK 执行（不解析、不 `eval` POC 之外的代码），
同一进程内由全局锁串行运行。

### 全量扫描为什么不卡死

pocsuite3 一次 `start()` 会把整批 POC 导入并 join 到全部跑完，第三方 POC 里有几种会永久不返回，
"选择全部 POC"就再也结束不了。本项目做了五层处理：

| 问题 | 表现 | 处理 |
| ---- | ---- | ---- |
| `install_requires` 写了非法模块名 | `register.check_requires()` 直接 `raise SystemExit`，它是 BaseException，任务线程被静默杀死、进度永久停在 55 | 批次捕获 `BaseException`；整批异常时降级为逐个执行，定位到具体 POC 后其余照常完成 |
| 弱口令爆破类 POC | FTP/SSH/Telnet/MySQL/Redis… 读 pocsuite3 自带字典，单目标上万次请求，一个批次能挂十几分钟 | 索引时按 `paths.*_PASS` / `*_USER` / `get_word_list` 标记 `bruteforce`，默认不进扫描 |
| 依赖 ceye / fofa / shodan 等外部平台 | 没有 token 时 `CEye()` 走 `while True: getpass.getpass()` 等终端输入，后台线程永远读不到 | 索引时标记 `needs_oob`，默认不进扫描；进程内把 `getpass`/`input` 替换成立即抛错，防止其他写法的 POC 挂住 |
| 随机 User-Agent | 未指定 `agent` 时每个请求都 `Faker()` 构造，多线程 + 杀软实时防护下首次要几十秒 | 固定使用配置里的 `USER_AGENT` 传给 pocsuite3 |
| 引擎根本不加载的脚本 | `_set_pocs_modules()` 对正文里没有 `register_poc` / `matchers:` 的文件直接 `continue`，既不报错也不执行；同目录下重名的文件按 `pocs_<文件名>` 注册，只会加载第一个——列进批次就是白等一轮超时 | 索引时套用 SDK 的同一判据标记 `loadable=0` 并写明原因，POC 页可筛选"引擎不加载"，批次选 POC 时跳过并在任务日志留一行，结果页的交互执行直接拒绝并给出原因 |

此外：POC 列表按 25 个一批切分（原来只按目标切分，1 个目标 × 数百个 POC 就是无法取消的单批），
每批之间检查取消与 `task_timeout`，进度在 55%→95% 之间按批次推进；
每批还有墙钟上限（`max(90, POC 数 × POC 超时)`），超时即放弃该批并停止后续批次——
Python 无法强杀线程，卡住的 POC 会继续占用 POC 引擎，此时后续执行最多等 `LOCK_WAIT_SECONDS`（120 秒）
就报"引擎被占用"，重启服务可彻底释放。

想把这些耗时 POC 放回扫描，把配置 `POC_ALLOW_HEAVY` 设为 1（或环境变量 `WSCHECK_POC_ALLOW_HEAVY=1`）；
单个 POC 也可以在 POC 页手工停用/启用，任务表单里"手动选择"的 POC 不受上面的默认跳过影响
（但仍会跳过"引擎不加载"的脚本，那是执行不了的东西，选它只会白等一次超时）。
实测：本机演练站点 + 自动筛选范围内单目标全量扫描约 1-2 分钟完成；"手动选择"全选可加载 POC 时
因包含爆破类会放慢一个量级，个别 POC 卡住会在批次墙钟上限处中断，
任务以 partial 结束并在日志里写明"有 POC 不会返回且无法强杀，已停止后续批次"。

## 全局设置（代理 / OOB / FOFA / POC 仓库 / 规则仓库 / 请求参数）

导航「设置」页写入 SQLite `settings` 表，扫描任务与结果页交互执行都会读取；留空的字段
不会传给 pocsuite3，避免把它的默认值覆盖成空串。密码/Token 类字段留空表示保持原值，
勾选"清除"才会置空，页面与任务日志都不回显明文。

| 分组 | 字段 | 作用 |
| ---- | ---- | ---- |
| 代理 | `proxy`、`proxy_cred` | 形如 `http://127.0.0.1:8080`，协议限 http/https/socks4/socks5/socks5h；凭据 `user:password` 单独填 |
| OOB 与回连 | `oob_server`、`oob_token`、`ceye_token`、`connect_back_host`、`connect_back_port` | dnslog 类 POC 的外带验证平台；不填时这类 POC 会被跳过，填了自动放行 |
| FOFA 目标导入 | `fofa_key` | FOFA API Key，仅用于新建任务时按查询语句导入目标；不会传给 POC 引擎，页面与任务日志不回显 |
| POC 仓库同步 | `poc_repo_url`、`poc_repo_ref`、`poc_repo_subdir`、`github_token`、`poc_auto_sync` | 从 GitHub 仓库拉取 POC 到本机目录；私有仓库 Token 仅存本地、页面不回显；`poc_auto_sync` 控制启动时自动同步 |
| 指纹规则仓库同步 | `rules_repo_url`、`rules_repo_ref`、`rules_repo_subdir`、`rules_github_token`、`rules_auto_sync` | 从另一个 GitHub 仓库拉取 YAML 指纹规则并导入数据库；Token 与 POC 仓库分开保存、页面不回显；`rules_auto_sync` 控制启动时自动同步 |
| 请求参数 | `agent`、`referer`、`host`、`cookie`、`headers`、`retry`、`session_reuse`、`session_reuse_num`、`poc_debug` | 全局 UA、来源页、Host 头（虚拟主机分桶，只改头不改连接地址）、公共 Cookie、附加请求头（每行一条 `Name: value`）、重试次数、连接会话复用、引擎调试日志 |
| POC 默认参数 | `poc_defaults` | 每行一条 `name=value`，作为所有 POC 自定义选项的兜底默认值（交互执行时用户输入优先） |

生效范围：

* POC 批量执行与单发交互执行 —— 全部经 `init_options()` 交给 pocsuite3，不自行拼接请求。
* 指纹采集（含 favicon）、对照校验、指纹表达式测试 —— 走 `requests` 的 `proxies`，与 POC 保持同一出口。

已知边界：

* pocsuite3 在 `init()` 里会改写进程级全局——`requests.api.request`、`Session.request`、
  `socket.socket`（配 SOCKS 代理时换成 `socks.socksocket`）、`socket.setdefaulttimeout`、
  `ssl._create_default_https_context`，而且执行完不还原。本项目导入 pocsuite3 之前先记录原值，
  每批（含单发交互执行）结束在 `_reset_engine_state()` 里逐项复原，并清空 `cmd_line_options` 与
  `kb.results/targets/registered_pocs`（`DIY_OPTIONS` 在每次执行前清空）。复原之前（批次执行期间、
  或被墙钟上限放弃的挂住线程尚未结束时），非 POC 请求由 `services/webfetch.py` 在导入时抓住的原始
  `Session.request` 发出，不经过 pocsuite3 的 hook——那个 hook 的 timeout 只接受数值（
  `(connect, read)` 会直接 `TypeError`），还会套上 POC 的代理并固定 `verify=False`；
  代理等选项本身仍按 `proxies` 显式传给非 POC 请求。
  唯一补不回来的情况：被墙钟上限放弃的那个挂住线程（Python 无法强杀）可能在复原之后再次改写它们，
  此时表现就是"引擎被占用"，重启服务可彻底释放。
* pocsuite3 对 POC 请求固定 `verify=False`（写死在 `session_request` 的默认参数里，SDK 没有开关），
  所以本工具不提供"校验目标证书"选项；指纹里的 TLS 证书采集走原始 socket，不经过代理也不受影响。
* 2.1.0 没有 `--random-agent`，只有 `--user-agent`；不指定 UA 时每个请求都会重新 `Faker()` 构造，
  本项目统一传配置里的固定 UA（见上文"全量扫描为什么不卡死"）。
* pocsuite3 2.1.0 的 `--delay` 在 controller 里还是 `# TODO`，没有实际限速，故未暴露该选项。
* 「记录 POC 引擎调试日志」只是将 pocsuite3 内部 logger 的级别从 WARNING 提到 INFO 并收集到任务日志，
  收集器挂在引擎自己的 logger 上、由任务线程统一落库，不会改变执行结果；默认只保留错误行。
* `POC 默认参数` 的键名会先校验（合法标识符、且不能占用 pocsuite3 自己管理的键），
  避免误把 `timeout`、`cookie` 之类写成 POC 参数导致执行期 `SystemExit`。

「设置」页的"连通性自测"按表单当前填写的值发起（密码框留空时回落到已保存的值），不需要先保存，
也不会写入设置；只使用 socket / requests，不导入 pocsuite3，因此不会触发交互式输入，
也不会因为 token 缺失而阻塞。代理自测可选填一个 URL 验证经代理取回内容，OOB 自测按
`oob_server`（interactsh `/register`）或 `ceye_token`（`api.ceye.io/v1`）分别探测，
FOFA 自测调用 `info/my` 校验 Key 与剩余额度（不消耗搜索次数）；POC 仓库与指纹规则仓库自测
各自校验仓库地址、分支与 Token 的读取权限，不会下载或写入文件。

## 结果页交互（attack / 命令控制台）

索引 POC 时会静态探测三类能力并入库（`poc_registry` 表），据此决定结果行展示哪种控件：

| 探测结果 | 判定方式 | 前端控件 |
| -------- | -------- | -------- |
| attack | POC 类里定义了 `_attack` | "攻击"按钮：按 POC 的 `_options` 声明生成参数表单，提交后以 attack 模式单发执行 |
| 命令控制台 | 定义了 `_attack` 且有名字为 `cmd`/`command`/`exec` 的选项 | "命令控制台"按钮：输入命令 → 写入该选项 → attack 模式执行，输出按时间累积成控制台样式 |
| 仅 shell | 只有 `_shell` 没有 `_attack` | 不提供交互，标注"仅 shell"：pocsuite3 的 shell 需要目标回连监听端口，浏览器侧无法交互 |

交互执行走 `runner.execute_once()`：`init_options + init` 后直接取注册好的 POC 实例、
`set_option` 注入参数、调用 `poc.execute(target, mode=...)`，同样不执行 POC 之外的代码，
与批量扫描共用 `RUN_LOCK`（因此可能与正在运行的任务互相排队）。
被标记为"引擎不加载"的 POC 在接口层直接拒绝（返回原因），前端按钮置灰并显示"pocsuite3 不会加载这个脚本"，
避免点下去只等到一句"未命中"。
每次执行都写入 `poc_actions`（参数、状态、输出、耗时）并在任务日志留一行，弹窗内可回看历史；
执行失败时会把引擎侧的报错（缺依赖、参数被占用、加载失败等）拼在错误信息后面，不再只有一句"POC 执行失败"。

> 这些按钮会按 POC 的利用逻辑真实访问目标（写文件、执行命令），仅可对获得授权的目标使用。

## 本地自测

```bash
python tools/mock_site.py                       # 默认 127.0.0.1:8999，仅本机监听
```

新建任务时输入 `http://127.0.0.1:8999` 并勾选"允许内网目标"，可跑通
指纹命中 → 目录探测 → POC 命中 → 对照校验（confirmed / suspected / 疑似误报）→ 复核 → 导出
的完整链路。演练站点预置了 `/nacos/`、`/druid/basic.json`、`/error`、`/actuator`、
`/manager/html`（401）、`/swagger-ui.html` 等路径，并让任意 `.php` / `.html` 返回首页或
Swagger 页——后者正是用来验证按后缀的软 404 基线不会把它们误判成命中。
演练时 POC 范围建议选"专项扫描"并只勾选只读类检测，避免对本地站点批量执行外部利用类 POC。
`http://127.0.0.1:8999/echo` 会回显请求头与来源地址，用来确认代理、公共 Cookie、附加请求头
是否真的到达了目标。

## 与设计文档（demo.md）的实现差异

| 设计文档 | 本项目 | 原因 |
| -------- | ------ | ---- |
| FastAPI + asyncio | Flask + 线程池 | 指定的技术栈 |
| Lark 文法解析 | 手写分词 + 递归下降 | 规则简单，减少依赖并便于给出精确报错 |
| 短路计分 | 全量累加计分 | 文档示例的阈值在短路语义下不可达 |
| `init_pocsuite/start_pocsuite/get_results` | `init_options + init + start` 读 `kb.results` | pocsuite3 2.1.0 的实际 SDK |
| Redis 队列 / 分布式 worker | 进程内后台线程 + SQLite | v1.0 非目标 |
| 少量规则、逐条求值 | 7044 条规则 + 缓存与两遍求值 | 迁移后的规则量级需要按目标预归一信号、复用编译结果 |
| 主动爬虫 | 未实现 | v1.0 非目标 |

POC 执行受进程级全局锁串行化（pocsuite3 的运行期状态是进程单例）；取消只在批次边界生效。
内网地址默认拒绝，需显式勾选"允许内网目标"，扫描、单发交互执行与指纹表达式测试共用这条红线；
静态资源后缀默认跳过 POC 检测。

## 常见问题

* **POC 页显示 pocsuite3 不可用**：本机杀软（火绒）会把 `pocsuite3/lib/core/common.py` 判定为
  `HEUR:Trojan/Python.ShellLoader.y` 并隔离，导致包导入失败。可从 wheel 中单独取出该文件放回
  `.venv/Lib/site-packages/pocsuite3/lib/core/`，并在杀软中排除该目录。
* **任务卡在 running**：进程被强杀时无法收尾，重启服务会自动标记为失败并可"重试"。
* **全量 POC 扫描卡死 / 跑不完**：见"全量扫描为什么不卡死"。排查顺序——
  日志里 `POC 批次 …进度 n/N` 是否还在动：不动就是某批里有 POC 不返回（爆破、等回连、要 token），
  超过墙钟上限后任务会以 partial 结束并写明原因；
  一直在动但很慢通常是目标或外网连接超时叠加，调小 `poc_timeout`、按需停用耗时 POC；
  如果日志里出现"引擎被占用"，说明上一批的线程还挂着，重启服务即可。
* **交互按钮点下去转圈**：与扫描共用 POC 引擎全局锁，任务在跑时会排队，最多等 120 秒后返回"引擎被占用"。
* **POC 页出现"引擎不加载"徽标**：这类脚本 pocsuite3 根本不会导入——正文里没有 `register_poc`
  也没有 `matchers:`（很多是从 Nuclei/其他格式转来的半成品，或者只定义了类没注册），
  同目录下与别的 POC 重名的文件也只会有第一个被注册（引擎按 `pocs_<文件名>` 建模块名）。
  以前选进批次就是白等一轮超时且没有任何报错，现在会在列表筛选、批次选 POC、任务表单和交互执行里都标出来，
  鼠标悬浮徽标可看具体原因；确实要用就自己补上 `register_poc(XXX())` 再重新索引。
* **POC 跑了但一条都不命中 / 想看引擎到底在说什么**：日志里只有"POC 执行失败"时，
  到「设置」勾选"记录 POC 引擎调试日志"重跑一次。默认已把引擎的 WARNING（缺依赖、
  `install_requires` 非法、参数名被占用、加载失败）收进任务日志并附在单发执行的错误后面，
  勾选后连引擎自己的 INFO（加载了哪个 POC、每个目标跑哪条）一起记录，单批可能上千行，排查完记得关掉。
* **改了代码不生效**：`run.py` 默认不带自动重载（`--debug` 才有），要重启进程；
  如果任务日志里的报错文案和当前代码对不上（例如已支持的 `status` 字段仍报"不支持的字段"），
  基本就是旧进程在跑。
* **"POC 执行失败"刷屏**：pocsuite3 未命中也会写一条 fail 记录，各 POC 文案不统一
  （`target is not vulnerable` / `not vulnerability` / `Internet nothing returned` …），
  这些按"未命中"处理，不计入异常；目标主动断开连接或超时（批量执行里很常见，
  很多 POC 会发畸形请求被服务栈直接 RST）记为 warning，日志里是"POC 请求被目标中断"，
  也不影响任务状态；只有真正的执行异常（导入失败、代码报错）才记 error 并把任务标记为 partial。
* **升级后缺列**：`db.create_all()` 只建新表不改旧表，启动时 `bootstrap._upgrade_columns()`
  会按 `POC_REGISTRY_COLUMNS` 给 `poc_registry` 补列——交互能力与耗时标记
  （`vul_id`/`vul_type`/`supports_attack`/`supports_shell`/`needs_oob`/`oob_kind`/`bruteforce`/`poc_options`）、
  引擎可加载性（`loadable`/`load_error`）与参考链接（`poc_refs`，SQLite 里 `references` 是关键字不能直接当列名），
  并按 `TARGET_ASSET_COLUMNS` 给 `target_assets` 补 `dir_hits`；随后重新索引即可填充，
  换 POC 仓库或目录后点"从仓库同步"会自动重建索引。
* **目录探测一条都不命中**：先看任务日志里"主动目录探测：N 个应用 / M 条路径"是否为 0——为 0
  说明字典路径不存在或 YAML 格式不对（表单顶部也会显示字典规模）；有请求但无命中时，
  确认目标是否对所有路径返回同一个 200 页面（会被基线判定为软 404），或把单次超时调大。
* **目录探测太慢**：默认每个目标最多 74 条路径，且被 `max(30, 8 × 单次超时)` 的墙钟上限兜住；
  目标多时按并发数并行。想更快可精简 `dir.yaml`，或用 `WSCHECK_DIR_MAX_PATHS` 限制单目标请求数。
* **删除任务后残留子表**：SQLite 默认不启用外键，`extensions.py` 已在连接事件里 `PRAGMA foreign_keys=ON`，
  结果、日志、资产、交互记录都会随任务级联删除。
* **时间显示**：右上角可切换时区，数据库统一存 UTC，展示时按所选时区转换。
