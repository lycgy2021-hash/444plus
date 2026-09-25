# gopoc

可扩展的 Go HTTP 漏洞检测框架：统一 HTTP 引擎、CVE 注册表、工作池、能力策略、分层证据判定（`detected`/`likely`/`confirmed` + 正交 `error`）、统一 Confirm 契约，以及 JSON / SQLite 报告。当前内置 checker：

| CVE | 产品 | 最高判定 | 验证方式 |
| --- | --- | --- | --- |
| CVE-2021-41773 | Apache HTTP Server 2.4.49 | confirmed | Canary 文件读取（active-canary，走 Confirm 契约） |
| CVE-2021-42013 | Apache HTTP Server 2.4.49/2.4.50 | confirmed | Canary 文件读取（active-canary，走 Confirm 契约） |
| CVE-2026-42238 | nginx-ui < 2.3.8 | confirmed | 未鉴权 `/api/restore` 安全探测（active-probe，走 Confirm 契约） |
| CVE-2026-42533 | nginx < 1.30.4 / 1.31.0–1.31.2 | detected | 被动版本区间 |
| CVE-2025-1974 | ingress-nginx（IngressNightmare） | likely | admission webhook 未鉴权可达（active-probe） |
| CVE-2024-55591 / CVE-2025-24472 | FortiOS/FortiProxy（FG-IR-24-535） | likely | 指纹 + 版本区间 + 管理面暴露 |
| CVE-2025-32756 | FortiVoice/Mail/NDR/Recorder/Camera（FG-IR-25-254） | likely | 指纹 + 版本区间 + 管理面暴露 |
| CVE-2025-49704/49706/53770/53771 | Microsoft SharePoint（ToolShell 家族） | likely | 指纹 + build/补丁级 + ToolPane.aspx 暴露 |
| CVE-2025-24813 | Apache Tomcat 9.0.0–9.0.98 / 10.1.0–10.1.34 / 11.0.0–11.0.2 | likely | 指纹 + 版本区间 + DefaultServlet 可写（OPTIONS，无损） |
| CVE-2023-21839 | Oracle WebLogic 10.3.6 / 12.1.3 / 12.2.1.3 / 12.2.1.4 / 14.1.1 | likely | 多协议：HTTP 指纹 + T3 握手（版本）+ T3/IIOP/SOAP 暴露面（协议级握手，非端口推断） |
| CVE-2026-60198/60199/60200/60202/60291/60292/60294 | Oracle WebLogic Core（CPU 2026-07，12.2.1.4 / 14.1.1 / 14.1.2 / 15.1.1） | likely | 复用多协议底座，按 HTTP / SOAP / T3-IIOP 分组，`likely` 需对应协议面真实暴露 |

| CVE-2026-21962 / CVE-2026-60364 | Oracle HTTP Server / WebLogic Proxy Plug-in（Apache/IIS，12.2.1.4 / 14.1.1 / 14.1.2） | likely | 前端类型(OHS/Apache/IIS)+ 代理插件专属证据 + WebLogic 路由确认；纯 Apache/IIS 不算 |
| CVE-2025-7775 | Citrix NetScaler ADC/Gateway（14.1 / 13.1 / 13.1-FIPS/NDcPP / 12.1-FIPS/NDcPP，12.1/13.0 EOL） | likely | NetScaler 专属指纹 + 分支化版本表 + Gateway/AAA 服务面暴露；纯 Citrix 页面不算 |

WebLogic 引入了**多协议探测**：除 HTTP 外，通过原始 TCP 做 T3/IIOP 协议级握手（`httpx.TCP` + `tcp_probe` 能力），T3 的 `HELO` 回包同时给出版本；协议暴露只在真实握手成立时判定，绝不因端口开放而误判（IIOP 无 GIOP 回包即视为未暴露）。

各 CVE 的版本范围来自对应官方公告（Apache httpd、nginx、nginx-ui、Kubernetes、Fortinet PSIRT）。**Fortinet 指纹为启发式，尚未在真实设备上验证（real-device validation pending）**；该产品线目前冻结，不再新增公告。Apache 版本范围仅针对上述两个 CVE（2.4.50 修复不完整，2.4.51 修复后者）。

**编译与运行**

需要 Go 1.25 或更新版本。SQLite 使用纯 Go 驱动，不需要 GCC、CGO 或系统 SQLite 动态库。

```powershell
go build -o bin/gopoc.exe ./cmd/gopoc
./bin/gopoc.exe list
./bin/gopoc.exe scan -u http://127.0.0.1:8080 -id CVE-2021-41773
./bin/gopoc.exe scan --targets examples/targets.txt --product apache --severity critical --json scan.json --sqlite scans.db
```

在当前受限 Windows 工作区，可以使用下面的脚本，把构建、模块与临时缓存都放在 `.cache/`：

```powershell
./scripts/dev.cmd check
./scripts/dev.cmd build
```

`scan` 默认运行全部匹配的 checker。`--target` / `-u` 可以重复；`--cve` / `--id` / `-id` 支持重复与逗号分隔。目标文件每行一个完整 URL，支持空行、`#` 注释和 UTF-8 BOM。目标会规范化、去重，不从网页发现额外目标。保留输入 URL 的路径，拒绝凭据、查询参数和片段。

**单 IP 模式与输出**

只给一个 IP 也能评估：`gopoc scan 10.0.0.8 --discover` 先做低噪声资产识别（少量 HTTP GET + 仅在提示 WebLogic 时一次 T3 握手），只运行识别到的产品对应的 checker（例如识别为 Tomcat 就只跑 Tomcat，不打 Fortinet/NetScaler/SharePoint/WebLogic）。同产品的多个 CVE 共用一次 assessment（缓存在单次扫描内）。

三种输出：默认打印**简洁人类报告**到 stdout（Target / Discovered / High-Risk Findings 按行动优先级分组 / Scan Quality；`not_found`、`unknown` 默认隐藏，仅在 Scan Quality 计数）；`--evidence`（`-v`）展开完整证据链；`--json`（`-o`）输出机器可读 JSON（`-` 为 stdout，此时人类报告转 stderr，管道得到纯 JSON；指定文件则写文件、人类报告仍在 stdout）。不指定 `--json` 时不输出 JSON。裸 IP/主机名默认按 `http://` 处理；`--json` 指定新文件时不覆盖已有文件；SQLite 追加历史扫描。退出码：`0` 完成，`1` 参数/初始化/报告错误，`130` 中断或总超时。检测到漏洞、单目标连接失败或策略拦截通过报告表达，不改变正常完成的退出码。

**判定与证据**

证据分三层递进：`detected`（版本/指纹符合）→ `likely`（危险端点/配置/异常行为可达）→ `confirmed`（漏洞特有行为成立 + 阴性对照不成立）。

| Verdict | 含义 |
| --- | --- |
| `confirmed` | 漏洞特有行为成立：CVE 对应的利用请求命中，且阴性对照请求不命中、响应差异符合漏洞特征。例如穿越路径返回精确 Canary、两个对照请求均不返回 |
| `likely` | 危险端点、配置或异常行为可达，但未做出行为级证明。例如 ingress-nginx admission webhook 未鉴权可应答 AdmissionReview |
| `detected` | 仅 `Server`/指纹命中受影响版本范围，未观察到任何危险行为；配置、回补补丁与可利用性均未验证 |
| `not_found` | 检测有效完成，证据明确不支持漏洞（Banner 声明的版本不在该 CVE 影响范围） |
| `unknown` | 检测正常完成，但证据不足/无法判断（版本缺失或冲突、目标非该产品、策略拦截） |
| `error` | 检测过程本身未正常完成：请求失败、取消、插件 panic、配置无效，或违反 confirmed 契约（`confirmation_missing`） |

`error` 与证据层级正交——它描述「这次检测没跑成」，不是对目标的漏洞判断，因此单独统计。CLI 摘要给出 `Scanned / Completed / Errors`，用户不必从一堆 `unknown` 里猜到底是「证据不足」还是「网络挂了」。`--evidence`（或 `-v`）在 stderr 打印每条 finding 的人类可读证据块（confirmed 展开 positive/negative/diff/repeat 与逐步匹配；detected 明确标注「behavioral evidence unavailable」）。

`confirmed` 由统一的 **Confirm 契约**（[checks/detect/confirm.go](checks/detect/confirm.go)）产出，checker 不能自行构造：默认策略要求阳性利用探测重复命中 2 次、至少 1 个阴性对照为干净对照（可达、状态可用、不呈现漏洞特征）、且阳性与阴性响应存在可解释差异。引擎对每个 `confirmed` 结果强制校验其 `evidence.confirmation` 通过，否则打回 `unknown` + `reason: confirmation_missing`——因此没有 checker 能靠一句状态码或版本号伪造 `confirmed`。版本/指纹证据只能贡献 `detected`，不能作为 Confirm 的阳性主体。报告中的 `evidence.confirmation` 是机器可读的证据对象（每个 positive/negative 探测的 status、matched、matcher、detail，以及 positive/negative 通过计数、diff、repeat）。单看状态码、Banner 或版本号不足以 `confirmed`。`detected` 明确区分「版本命中」与「漏洞可利用」，避免把版本扫描当成漏洞确认。`not_found` 不是“没有漏洞”的证明。Banner 可以被隐藏或改写，且反向代理可能只暴露前端版本。`confidence` 是规则置信等级（0–100），与 verdict 层级正交，不是经过统计校准的概率。失败的主动验证保留被动结论并写明原因。

报告包含目标、CVE、时间、耗时、原因、状态码、选定的 `Server` / `Content-Type`、响应体 SHA-256、读取字节数、截断标记，以及每一步的证据。响应体和 Cookie 不写入报告。发生截断时，哈希只对应已读取并保留的部分；Canary 截断不会确认漏洞。策略拦截使用 `unknown` + `reason: policy_blocked`，不扩展判定枚举。

**Active Canary**

默认 `passive` 只进行正常 GET 和 Banner 分析；这里的“被动”仍会产生 HTTP 请求。主动模式需显式选择 `--mode active-canary` 并配置 `active.enabled: true`。配置文件本身不会把默认模式切换为主动模式。

在测试服务器预先放置内容唯一的普通文本文件，例如 `/tmp/gopoc-canary.txt`，放在 DocumentRoot 和 Alias 指向目录之外。文件内容应与 `expected` 精确一致，允许结尾带一个 LF 或 CRLF。框架不会创建或修改远端文件。

编辑 [examples/canary.yaml](examples/canary.yaml)：

```yaml
allowlist:
  - 127.0.0.1
active:
  enabled: true
  canary:
    alias_path: /canary-alias/
    traversal_depth: 4
    file_path: /tmp/gopoc-canary.txt
    expected: GOPOC-CANARY-7f732a64b98947ed
```

`alias_path` 对应服务器实际配置的 Alias URL 前缀；`traversal_depth` 是从 Alias 指向的文件系统目录回到根目录的层数，范围 1–16。`file_path` 是服务器上的绝对文件路径。本版主动插件按 Unix 路径构造，配置应用到本次所有目标，测试前应保证它们采用相同的 Canary 布局。

```powershell
./bin/gopoc.exe scan -u http://127.0.0.1:8080 --mode active-canary --config examples/canary.yaml --cve CVE-2021-41773,CVE-2021-42013
```

每个主动 checker 最多发出三个额外 GET：直接 URL 对照、带随机不存在文件名的穿越对照、实际 Canary 请求。前两个请求不能返回预期内容，也不能超时、截断、返回 5xx 或重定向。实际 Canary 请求必须返回 `200` 和完整预期内容。主动请求不跟随任何重定向。确认的是文件读取行为，不能从该结果推断命令执行能力。

**HTTP 与作用域配置**

完整示例在 [examples/passive.yaml](examples/passive.yaml)。命令行参数覆盖 YAML 中的对应字段；未知 YAML 字段和多个 YAML 文档会报错。

| 参数 | 默认值 | 行为 |
| --- | --- | --- |
| `--timeout` | `5s` | 单次请求的 DNS、连接、TLS、响应头与响应体总超时 |
| `--scan-timeout` | `0` | 整次扫描期限；包含排队、限速等待 |
| `--max-body` | `1048576` | 解压后响应体上限 |
| `--concurrency` | `20` | worker 数量和全局同时请求上限 |
| `--per-host` | `2` | 每个主机名的同时请求上限，跨端口共享 |
| `--rate` | `2` | 全局每秒请求数；`0` 关闭限速 |
| `--redirects` | `3` | 指纹请求允许的同源跳转次数；`0` 不跟随 |
| `--proxy` | 无 | 显式 HTTP(S) / SOCKS5 代理，不自动继承环境代理 |
| `--dns` | 系统解析器 | 可指定 `host:port` |
| `--insecure` | `false` | 显式跳过 TLS 证书校验 |
| `--allow` | 无 | 重复添加精确主机名、IP、CIDR 或完整 origin |

同源按规范化的协议、主机、有效端口同时相等判断，HTTP 到 HTTPS 也不自动跟随。含凭据、查询或片段的重定向不会跟随。每个实际发起的扫描 GET（含重定向和 Canary 对照）都经过同一限速器。同一目标的两个 checker 共用本次扫描的指纹结果。

未提供 allowlist 时，输入目标列表定义扫描范围。提供 allowlist 后，只有匹配的输入目标可以请求，越界目标保留拦截记录。主机名规则精确匹配，不自动匹配子域；主机名规则允许该主机的所有端口，origin 规则限定协议和端口。CIDR 只匹配输入 URL 的 IP 字面量，不把任意域名解析到 CIDR 后放行；主机名规则不执行 DNS 地址固定。代理和系统解析行为也不等价于网络隔离。

默认能力是 `passive | http_get`；主动模式额外允许 `canary_read`。`state_change`、`command_execution` 和未定义能力均被引擎拒绝。能力策略约束按接口协作的可信插件；编译进进程的 Go 代码本身拥有进程权限，因此不是针对不可信插件的隔离沙箱。

**扩展 checker**

```text
cmd/gopoc/          CLI 和依赖组装
checks/apache/     两个独立 CVE checker 和公共检测逻辑
checks/builtin.go  内置插件注册入口
internal/model/    Target、Finding、Evidence、Checker、Capability
internal/httpx/    统一请求、指纹缓存、限速、并发、重定向
internal/policy/   能力和目标 allowlist
internal/engine/   工作池、策略门禁、取消和插件异常处理
internal/registry/ 注册、去重、ID / 产品 / 严重性过滤
internal/config/   严格 YAML 读取
internal/report/   JSON 和 SQLite
internal/testutil/ 原始请求测试夹具
```

新插件实现 [model.Checker](internal/model/model.go)，通过构造函数接收 `httpx.Probe`，所有请求使用注入的客户端。实现应支持并发调用并遵守 `context.Context`，最后在 `checks/builtin.go` 注册。新增 checker 不需要修改扫描器核心。当前按注册表元数据筛选插件；HTML/TLS 产品识别、外部规则文件加载和动态插件加载尚未实现。

SQLite 的 `scans` 保存每次运行及完整 JSON，`findings` 提供 `run_id`、`cve`、`target`、`verdict` 和 `confidence` 索引查询字段。一次扫描在同一事务内写入；重复 run ID 或写入失败时回滚。Ctrl+C / 总超时会保留已有结果，并为未完成任务生成 `unknown`，然后保存带 `cancelled: true` 的报告。

```sql
SELECT cve, target, verdict, confidence
FROM findings
WHERE verdict IN ('confirmed', 'likely');
```

**验证**

```powershell
go test ./...
go vet ./...
go build ./cmd/gopoc
```

测试使用本地 HTTP/TLS 服务及原始 TCP 请求夹具，覆盖版本矩阵、指纹复用、原始编码与代理传输、Canary 对照、正文截断、证书验证、限速、并发、策略门禁、取消、JSON 和 SQLite 事务。它们验证框架与协议行为；当前环境未发现 Docker 命令，尚未运行真实 Apache 2.4.49 / 2.4.50 / 2.4.51 版本矩阵。
