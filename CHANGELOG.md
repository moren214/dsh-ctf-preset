# 变更记录

## 0.51.0

- **审计回归与可复现构建**：新增 `test/audit-regressions.test.js` 锁定本轮修复的六处缺陷（PCAP 按 UTC 时间过滤、GGUF 字符串数组模板注入、Safetensors `__metadata__` 模板注入、Ghidra `image_base`/相对地址契约、`ctf_sandbox` 的 `result_id` 链路、提交账本坏行容错）；CI 增加 Python worker 编译检查与真实容器隔离冒烟；`docker/Dockerfile` 的基础镜像改为按 digest 固定，`bkcrack`/`ffuf`/`pwninit`/`gef` 与 `Dockerfile.heavy` 的 `ghidra`/`jadx`/`apktool` 均校验 SHA-256。
- **提交账本可观测性**：`check_flag`/`submit_flag` 现在回报 `corrupted_receipts` 计数，坏行不再静默消失；实例账本解析失败时退化为空表而不是让 `ctf_instance`/`ctf_arena`/`submit_flag` 一起失败。


- **P0 安全与模型扫描修复**：要求隔离的沙箱任务在 `backend: "auto"` 下不再静默回退到共享宿主权限的 WSL2；动态靶机授权按会话/工作区隔离、限时并支持删除撤销；`ctf_arena detail` 不再从自由文本描述授权 URL；GDB stdin 路径改用 POSIX 安全引用；Pickle、GGUF 与 PyTorch ZIP 扫描截断会报告 `incomplete` 且至少为中风险，并补充危险 Torch 加载入口识别。
- **P0 平台凭据边界**：`ctf_arena fetch_files` 的同源附件下载复用 CTFd/GZCTF 适配器认证；跳转到其他来源时仍不携带平台凭据。
- **P1 图谱租约与分页**：未认领的 Intent 不能直接结案；`board` 的 `ruled_out` 现与 Facts/Intents 共用 offset 并在 `paging` 中报告总量和后续页状态。
- **P1 Python 配置热重载**：`resolvePython()` 每次先检查配置文件版本；更改 `pythonPath` 后会重新探测解释器，不再返回旧缓存。
- **P1 ELF 防护识别**：`__stack_chk_fail_local` 计入 canary 证据；FORTIFY 只由未定义的标准 `__*_chk` 动态导入触发，避免把自定义函数误报为保护。
- **P1 平台跳转**：允许通过逐跳来源授权的同源 API 跳转；跨来源跳转仍被阻断，POST 等请求体不会被自动重放。
- **P1 跨平台与反编译诊断**：Linux 沙箱执行前规范化 `.sh` 的 CRLF；Ghidra/r2 非零退出或空函数结果会显式报错或标出回退；平台自动探测不再吞掉认证、网络和取消异常。
- **P1 只读与续接错误契约**：只读会话仍可查看实时榜单（`recorded: false`）；`ctf_progress` 只读拒绝和过期 revision 分别报告 `permission` / `conflict`，handoff 同时保留旧值与只读告警；补齐 `FS_STALE_VERSION`、`FS_NOT_OBSERVED` 与 `EBUSY` 的冲突分类。
- **P1 取证与密码学回归**：覆盖 PNG CRC 损坏告警、EXIF UserComment、无节头 ELF、RSA 明文长度、广义 LCG CRT、PCAP 缓冲区与畸形节头、浏览器隧道超时及 Ghidra/r2 边界。
- **P1 动态网络与大抓包保护**：支持经结构化靶机信息授权 IPv6 TCP 地址；动态授权表达到上限时不再驱逐仍有效端点；TCP 乱序缓存增加 16 MiB 全局字节预算并复制小片段，超限状态显式可见。
- **P1 附件部分成功契约**：`ctf_arena fetch_files` 超过单次 8 个附件时返回 `partial`、总数、遗漏数及 `fetch_attachment` 补充路径。
- **P1 ONNX 扫描完整性**：ONNX GraphProto 节点尚未遍历时，扫描结果明确标为 `incomplete` 且风险至少为中；外部路径特征扫描覆盖完整输入。真实大模型边界用例验证超过 2 MiB 的载荷仍会被检查。
- **P1 未覆盖模块与容器运行加固**：新增真实磁盘/字节与 Python worker 用例覆盖此前 10 个函数覆盖率为 0% 的 JS 模块；Docker 容器改以 UID 10001 运行，RAM 与 swap 限额相同，Python 工具装入共享系统包的 venv 以避免覆盖 apt 管理的 NumPy/fpylll；构建支持 apt、pip、GitHub 与 RubyGems 镜像参数，`r2ghidra` 安装失败会让镜像构建失败。
- **P1 动态 flag 新鲜度**：`ctf_arena` 的容器 create/extend/delete 写入共享实例账本；`ctf_arena(submit)` 与 `submit_flag` 忽略调用方自报的 `refreshed_at`，只接受账本中 30 分钟内且未删除的实例记录。
- **跨平台契约说明**：同步 README 与 SKILL 的沙箱回退行为和题面动态授权边界。未新增运行时依赖、配置字段或文件，因此 `package.json` 的 `files` 清单无需变更。

## 0.50.0

- **Schema 瘦身、图谱分页与 Writeup 导出（包 A）**：
  - `ctf_progress` 去除冗长 `oneOf`/`not` 嵌套，Schema 体积缩减 ~61%（7.5 KB → 2.9 KB），运行时按 `action` 的字段校验完全保持不变。
  - `ctf_graph` 的 `board` 新增 `status_filter`（`all|active|open|claimed|done|dead|overdue`）、`limit`/`offset` 分页与 `summary_only` 极简汇总；新增只读 `action: "export_writeup"` 一键导出按题/全图谱 Markdown 题解草稿。
  - `ctf_arena` 原生支持 GZCTF `Cookie: GZCTF_Token=` 自动认证（由 `platform-request` 识别 `=` 后缀不插空格）、`container_action: "extend"` 容器续期，以及 `sync_graph` 同分题目按解出人数（`solves`）降序动态排优。
- **Web 浏览器进阶、容器安全加固与 APK 沙箱桥接（包 B）**：
  - `browser_session` 启用 `Page` 事件监听，自动捕获并放行 `alert`/`confirm`/`prompt`（防止 XSS 触发弹窗卡死会话），新增 `dialogs`、`evaluate`、`set_cookie`（受 `authorize` 来源约束）、`set_headers` 与 `upload_file`（受工作区路径约束）。
  - `ctf_sandbox` 容器运行默认加固 `--cap-drop=ALL` 与 `--security-opt=no-new-privileges:true`，`status`/`pwn_triage` 及 `exec(read_only_work: true)` 自动以只读 `/work:ro` 挂载工作区；`docker/Dockerfile` 锁定 `radare2`/`GEF`/`bkcrack`/`ffuf`/`pwninit` 版本，并增补 `tesseract-ocr`、`john`、`sqlmap`、`pyinstxtractor-ng`、`bkcrack`、`ffuf`、`pwninit`；`mobile_apk(action: "decompile")` 在宿主机缺少 `jadx`/`apktool` 时自动桥接至 `ctf_sandbox`（优先 `heavy` 镜像）。
- **AI 模型/Pickle 静态安全体检、密码学模板与覆盖率跃升（包 C）**：
  - `inspect_media` 新增 `kind: "model"`（纯 Python 标准库零执行静态扫描），支持 **Pickle**（`pickletools` 模拟栈跟踪 `STACK_GLOBAL`/memo 混淆、识别危险模块/调用及尾随数据）、**PyTorch ZIP**（扫描 `.pkl` 与 TorchScript `.py`）、**Safetensors**（`__metadata__`/张量表/尾随隐写字节）、**GGUF**（KV 元数据与可疑模板）和 **ONNX**（自定义域与外部路径穿越），完整继承 `source_result_id` 零拷贝链路；同步将 `media-reader.js` 改为脚本文件路径调用，彻底消除 Windows 下 `-c` 命令行 32 KiB 长度限制。
  - `crypto_solver` 新增 3 个零占位可运行脚手架：`ecc_weak`（纯标准库 Pohlig-Hellman + 异常曲线 Smart 攻击）、`padding_oracle`（AES-CBC 解密 + CBC-R 伪造）与 `hash_ext`（纯标准库 SHA-256 长度扩展）。
  - 新增 `test/web-and-core-coverage.test.js` 并扩充回归用例至 **149 项**，消除 `net-session`、`elf`、`pwn-payload`、`browser-gateway`、`browser-session`、`audio-metadata` 等核心模块 0% 覆盖盲区，全局覆盖率突破 **70%+**。

## 0.49.1

- **`ctf_graph` 结案 Fencing 保护**：`finish_intent` 拒绝重复结案已处终态（`done`/`dead`）的 Intent（返回 `status: "closed"`），并拒绝非当前持有者越权结案已被其他代理认领的 Intent（返回 `status: "conflict"`），防止超时接管后的滞后子代理覆盖新进度。
- **`ctf_sandbox` 反编译性能与缓存优化**：`decompile` 将 `radare2`/`rizin` 的伪 C（`pdg`/`pdc`）与反汇编/交叉引用（`pdf`/`axt`）合并为单次 `-A` 分析进程；Ghidra Headless 按二进制 SHA-256 持久化缓存已分析项目至 `.ctf-cache/ghidra/`，二次查询走 `-process -noanalysis -readOnly` 复用缓存并标明 `cached_project`。
- **`ctf_doctor` 热重载口径与技能同步自检**：`ctf_doctor` 区分进程实际注册层级（`tool_tier`）与配置文件层级（`configured_tool_tier`），新增 `tool_tier_sync` 与 `skill_sync`（自动归一化换行对比包内与工作区/全局 `SKILL.md` 的 SHA-256）自检项。
- **错误分类与文档对齐**：统一核心与扩展工具的只读权限拒绝错误为 `permission`，补充 `EEXIST -> conflict` 映射；在 `README.md` 与 `SKILL.md` 中完整标明扩展审计层工具边界，修复快速开始示例依赖默认关闭工具的问题。

## 0.49.0

- **工具分层与 Schema 精简**：新增 `enableExtendedAudit` 开关（默认 `false`），默认仅注册 27 个高频核心工具，Schema 体积较全量精简 34%+；设为 `true` 时完整恢复全部 45 个工具（100% 向后兼容）。
- **跨平台 Linux 安全沙箱与双层镜像自动路由（`ctf_sandbox`）**：
  - 新增 `ctf_sandbox`（`status` / `exec` / `decompile` / `pwn_triage`），自动探测并优先调用 Docker（默认 `--network=none` 离线隔离），Docker 不可用时自动回退至本机 WSL2 发行版（`wsl.exe --cd --exec` 原生支持中文路径与零 shell 展开），内置 30 秒探测缓存；强隔离运行未知程序可显式传 `backend: "docker"` 禁止降级。
  - 提供双层镜像定义：`docker/Dockerfile`（`dsh-ctf-sandbox:latest`，含 32 位运行库、GEF、`qemu-user`/`gdb-multiarch`、`radare2`+`r2ghidra`、`pwntools`/`z3`/`fpylll`/`ROPgadget`/`ropper`/`seccomp-tools`/`one_gadget`/`volatility3`/`wabt`/`sleuthkit`/`cpio`/`pillow`/`numpy`/`scipy`/`scapy`/`xdis` 等）与 `docker/Dockerfile.heavy`（`dsh-ctf-sandbox:heavy`，增量叠加 Ghidra Headless、`angr`、`jadx`/`apktool` 及可选 `WITH_SAGE=1`）。
  - 新增 `profile: "auto" | "base" | "heavy"` 自动档位路由（支持 `sandboxHeavyImage` 配置）：默认 `auto` 自动识别命令、`.sage`/`.apk` 任务与 `.py` 脚本导入头部，按需自动切入 `heavy` 镜像并扩容容器内存至 `4g`；`decompile` 传 `profile: "heavy"` 优先调用 Ghidra Headless 并自动放宽超时至 120 秒，亦支持 `r2`/`rizin`/`objdump`/无节 ELF PT_LOAD/`gdb` 逐级兜底。
- **跨题共享图谱与多代理并行编排（`ctf_graph`）**：
  - 在 `.ctf-graph/` 维护分层 Fact-Intent DAG（`graph.json` + `graph.saved.json` 恢复副本 + 自动投影 `BOARD.md`），采用 CAS 乐观锁支持并发互斥认领。
  - 支持 `board`（按题汇总 `challenges`、已排除路线 `ruled_out` 与超时提醒）、`expand`、`add_fact`（`dedupe_key` 幂等去重）、`add_intent`、`claim_intent`（含 `next: true` 与 `steal_overdue: true` 超时接管）、`finish_intent` 以及 `dispatch_plan`（自动避开进行中题目并生成子代理任务提示与超时回收清单）。
  - `BOARD.md` 自动生成 `## Overview` 按题总览表、事实来源标注与 `Active & Open` / `Completed & Ruled Out` 分区。
- **赛题平台原生适配器（`ctf_arena`）**：
  - 原生适配 **CTFd v1**（自动默认 `Token` 认证）、**GZCTF**（`platformGameId`、分组题单、容器启删自动授权、判题归一化）与通用平台（`platformType: "auto" | "ctfd" | "gzctf" | "generic"`）。
  - 支持 `status` / `games` / `challenges` / `detail` / `sync_graph`（幂等导入 `.ctf-graph/` 按分值排序）/ `fetch_files` / `container` / `submit`。
- **Pwn / Rev / Crypto / Web 核心实战增强**：
  - `crypto_solver` 新增零依赖纯 Node.js `action: "solve"`（`jwt_inspect`、`jwt_crack`、`flask_session`、`lcg_recover`、`mt19937_recover`）；4 个 Python 脚手架模板均补全为可直接编译运行代码；`check` 在宿主机缺库时自动附带 `sandbox_fallback` 提示。
  - `rev_query` 扩展至 **ELF32 / ELF64**（x86、x86-64、ARM、AArch64、RISC-V）与 **PE32 / PE32+**，新增无需 Capstone 的 `operation: "triage"`（识别 UPX/PyInstaller/Go/Rust/.NET/GCC/Clang/MSVC 及常见密码常量）。
  - `gdb_driver` 放宽安全只读偏移表达式与缩写、支持 `args` 传参，并在 Windows 下检测 Linux ELF 时自动桥接 Docker/WSL2 运行 Linux `gdb`。
  - `http_request` 保留赛题响应头（仅脱敏平台令牌）、支持自定义 `Host`、`cookie_jar` 与 `multipart` 上传；`network-boundary` 支持通配端口、端口范围、子域通配、CIDR 与 `ctf_instance`/`ctf_arena` 返回靶机的动态授权；`workbench-config` 支持热重载。
  - `ctf_doctor` 联动展示 `sandbox_summary`、`sandbox:docker_base` / `sandbox:docker_heavy` 就绪状态与镜像构建命令提示，并修正 Windows 原生 `libarchive` 探测及 `compact: false` 生效范围。

## 0.48.0

- `rev_query` 新增函数级 `cfg`：按函数符号或虚拟地址遍历 x86-64 ELF 的可达基本块，输出条件分支、跳转、直接/间接调用及 RIP 相对数据引用。
- 分析可设基本块与指令上限；间接跳转标为未解析，并说明混淆、跳转表和代码内数据可能导致的静态分析缺口。
- 同步更新工具参数、README、包内与当前 CTF 技能说明。

## 0.47.0

- Pwn 增加受限的 GDB 批量调试，可设断点、运行/单步、检查寄存器、栈和回溯，并用工作区输入文件复现题目输入。
- 新增 `pwn_payload`，根据泄漏与符号偏移计算 libc/PIE 基址，并按给定地址组装有界的 x86-64 ret2libc payload。
- 同步 GDB 可用命令、执行边界和输入限制说明。

## 0.46.0

- Web 浏览器会话增加受限的点击、表单填充、下拉选择、按键发送和动态元素等待，支持处理依赖客户端脚本的题目页面。
- 可读取当前授权来源的 localStorage/sessionStorage；页面写操作遵循可写会话策略。
- 同步浏览器工具参数、边界和当前 CTF 技能说明。

## 0.45.0

- Misc 增加重复密钥 XOR 分析、bzip2/XZ 解压，以及 ASCII85/Z85 编解码。
- Crypto 增加由已知 RSA 私钥指数恢复因数，以及 ECDSA nonce 重用候选恢复与公钥参数核验。
- 同步压缩附件限制、计算参数和当前 DSH 技能说明。

## 0.44.0

- `calculate_offline` 的 `encode`/`decode` 新增 basE91，支持与现有字节编码及后续计算串联。
- 补充 Misc 编码用法和当前技能说明。

## 0.43.0

- Misc 新增 zlib 自动识别和 raw Deflate 显式提示；解压成员或 TAR 可继续交给附件工具检查。
- Crypto 新增 RSA `batch_gcd` 共享因子检查，广播攻击最多接受 8 组模数。
- 更新当前 CTF 技能用法与兼容矩阵。

## 0.42.0

- `calculate_offline` 新增无符号大整数与字节互转，可指定字节序、Hex/Base64/Base64URL 编码和输出字节长度。
- 支持引用附件读取结果，在同一批次串联转换、模逆和同余核验；报告原始字节长度、最大公因数或余数，便于复查。

## 0.41.0

- `calculate_offline` 新增已知参数和种子的 LCG 序列复算。
- 确定性复算可按候选核对中间步骤，报告首个不符或待验证的检查点。
- 确定性计算超时可保留完成步骤，同一会话可携原参数从未完成步骤续算。

## 0.40.0

- 图像、PDF、二维码、归档成员与音频提取结果可通过 `result_id` 直接传给下一项本地分析；派生字节保留哈希和来源链。
- PNG 新增按整字节续接的连续 LSB 位流；PDF 支持页面 PNG 渲染和嵌入附件读取；新增 SQLite 只读查询及 DOCX/XLSX/PPTX/ODF 文本读取。
- `stego_audio` 支持 24 位 PCM、声道与时间段选择；`pcap_stream` 支持 IPv4/协议/端口/UTC 过滤，并将大于 64 MiB 的 PCAP/PCAPNG 分块流式处理至 1 GiB。

## 0.39.0

- `inspect_attachment` 可接 `scan_binary` 的结果编号，确认普通单卷 ZIP 候选的边界、目录和首个成员头。
- 离线编码、解码、格式转换和哈希可按结果编号复读完整文件片段或归档成员，并报告原件和数据哈希。
- `ctf_progress` 保存预测与实际观测，可按原工具参数找回验证并复核原件是否变化。

## 0.38.0

- 新增 `scan_binary`，按块定位格式签名和已知字节，返回原件偏移、命中 SHA-256 与续查位置。
- `inspect_attachment` 和 `read_archive_member` 支持指定内嵌 ZIP 的原件区间。目录查询和成员复核使用同一区间。

## 0.37.1

- 补充平台请求、二进制分段读取、归档成员读取、循环模式与 ZIP 扩展工具的成功和失败路径测试；兼容性测试覆盖无提示注入接口时由 SKILL 回退。
- 覆盖率门槛提高为全局行覆盖 40%、函数覆盖 35%，并对九个核心模块分别设行、分支和函数下限。
- 工作区路径校验失败现在返回 `path` 类型错误，便于工具给出正确修复提示。

## 0.37.0

- 工具结果默认使用紧凑 JSON，`compact: false` 可恢复缩进；`ctf_progress` schema 按 action 限定字段。
- 平台 HTTP 请求集中处理来源校验、令牌脱敏和重定向策略；跨工具错误统一按 `kind` 生成提示。
- `ctf_doctor` 区分必需与可选能力，并报告宿主接口；无续接提示接口时依赖包内 SKILL。时间盒告警返回结构化 `warnings[]`，并保留兼容文本。状态追加在版本冲突时最多重试 3 次，最新有效记录保存到 `.ctf/status.saved.json`。
- PCAPNG 统计报告筛选范围，`pcap_stream` 明确整份捕获范围并结构化标记部分解析。
- 增加模块语法/本地导入检查、工具契约单测、Node 22 覆盖率门槛及 Windows/Linux CI。图标颜色改用主题变量，清理重复根目录 locale。

## 0.36.0

- HTTP 支持同主机升级 HTTPS，逐跳核验目标。正文中断时保留状态、响应头和已读字节，URL 登录信息按安全规则处理。
- Flask 支持隐式 HEAD/OPTIONS、路径百分号解码和斜杠匹配。提交预检的自定义正则独立执行，回执写入按字段筛选。
- 多行 Base64、二进制 URL / 表单 / HTML 字节编码可往返。长计算结果支持翻页和完整值衔接。因子不符合 RSA 参数条件时拒绝输出明文。
- ZIP 可校验误标的未加密成员并保留更长的名称。取证补充 EXIF、16 位 PNG、APNG 帧、图像元数据、WAV 时频谱和 PCAPNG 时间边界。
- 统一配置优先级和异步自检。实例先建后删，榜单只记本队摘要。浏览器遵守操作超时并清理配置目录，可复核的扩展输出进入结果缓存。大附件可显式放宽下载上限。

## 0.35.0

- `check_flag` 和 `submit_check` 默认只读，传 `record: true` 时保存预检回执。
- 过期的证据编号可用原件路径、字节范围和 SHA-256 复算。范围越界或哈希变化标为证据不足。
- 支持 BSD 回环抓包，记录 TCP 流首尾捕获位置，提取带时间的 UDP DNS 查询名与 TXT 应答样本。
- 允许读取只有一个全零结束块的 TAR，返回警告与尾随位置。
- Flask 静态路由报告附适用的响应钩子，可与返回事件核对。动态响应处理保留待复核标记。

## 0.34.0

- 先核对正式提交回执再判定提交结果。预检回执与正式提交分开。实例轮换按删除和创建分别报告。
- HTTP、TCP、浏览器和附件下载检查已配置的范围。附件下载逐跳验证公网地址，支持取消和分块记录。
- 扩展工具校验工作区路径和必填参数。GDB 提供固定静态检查，已知 ZIP 口令可读单个成员。
- 抓包支持 Linux SLL/SLL2、坏包隔离、有界 IPv4 分片和连接世代。TAR 报告尾随区域，Flask 识别常见隐式状态并筛除明显过期的事件。
- 题目证据可按工作区留存，旧值标为已记录。笔记状态有恢复副本，更新交接和题解时保留手改内容。

## 0.33.0

- 续接：`notes.md` 改为"结论/命令/排除/待办"四段人读格式，机器状态（revision、session、instance、工具值）移到 `.ctf/state.json`；旧版内联 JSON 块仍可读，`save` 后自动迁移；`load` 在会话或实例变化时给出提示，`repair` 重建 state 与 notes 并备份。
- 赛制操作：新增 `check_flag`（原 `submit_check` 保留）、`submit_flag`（本地校验通过后按平台配置提交并分类 accepted/rejected/duplicate）、`ctf_instance`（status/list/create/rotate/delete）、`fetch_attachment`（http(s) 附件下载并登记 manifest）、`ctf_status board`（榜单/分数写入心跳记录）。
- 工程：`ctf_doctor` 增加 Python 3.11+ 与 libarchive/capstone/pymupdf/pillow/opencv/numpy 探测，缺失时给出 `pip install` 命令；新增 `test/` 下的 node:test 单元测试（path 解析、ZIP 目录、证据 SHA-256、progress save/load/repair）与 `npm test`。
- 提示词：persona 开头加入开工优先级（附件 → read_ctf_files，HTTP → http_request，TCP → net_session，证据 → result_id），并加入网络上下文桥接（赛题内网域名在实例 shell 里请求）、自动 load/save 节奏、外部内容防注入、安全边界与上下文纪律。
- 文档：README 新增快速开始、任务索引、故障排查、安全边界、迁移说明；SKILL.md 新增自动保存与续接、网络上下文桥接、节省上下文、安全边界四节。

## 0.32.0

- `verify_evidence` 支持 `{result_id}`：按记录中的 byte_offset/byte_length/range_sha256 复核片段，仍要求至少两个不同文件。
- 新增 `ctf_doctor`（依赖与续接文件自检）与 `competition_api`（配置化平台访问，未配置时返回 dependency）。
- 续接提示通过 systemPrompt 注入（order 900），提示新会话先读 notes/handoff/status/submissions。
- 工具选择表补全 pwn_cyclic、flask 证据类工具、doctor 与平台工具。

## 0.31.0

- 新增 `ctf_status`（15/30/60 分钟心跳提醒）与 `submit_check`（格式/长度/来源/动态新鲜度/重复校验 + 本地回执）。
- `ctf_progress` 增加 `hints` 字段与"提示吸收"段。
- SKILL.md 增加工具选择表、时间盒与心跳、提交纪律、提示吸收、并行调度、收尾清单。

## 0.30.0

- 附件导入目录改为 `.ctf-attachments/`，新增 `manifest.jsonl` 登记来源路径与导入时间；同名不同内容加 SHA-256 前缀。
- 工具错误新增 `missing` kind；`ctf_progress results` 可列出当前 result_id 清单；`read_ctf_files`/`http_request`/`net_session` 描述首行写明边界。

## 0.29.0

- 新增 7 个扩展工具：browser_session、gdb_driver、archive_crack、stego_audio、mobile_apk、cloud_metadata、crypto_solver；输出文件限制在题目工作区内。

## 0.28.1

- 附件绝对路径自动导入（`.ctf-imports/`，0.30.0 起改名）、结构化错误 `ok:false` + kind/hint、`ctf_progress insights` 判断来源、`handoff` 写入 `handoff.md`。

## 兼容矩阵

| 插件版本 | DSH 版本 | 说明 |
|---|---|---|
| 0.51.x | `>=0.2.2-rc.5 <0.3.0` | 当前版本。补审计回归用例、CI 容器冒烟与镜像 digest/SHA-256 锁定，提交账本坏行可见。 |
| 0.50.x | `>=0.2.2-rc.5 <0.3.0` | 旧版本。保持 Core Tier（27 核心 / 45 全量）；精简 `ctf_progress` schema、新增 `ctf_graph` 分页/`export_writeup`、`ctf_arena` GZCTF Cookie/续期/solves 排优、`browser_session` Web 进阶、Docker 加固与 `bkcrack`/`ffuf`/`sqlmap` 等兵器、`mobile_apk` 沙箱桥接、`inspect_media(kind: "model")` 及 3 个密码学脚手架。 |
| 0.49.x | `>=0.2.2-rc.5 <0.3.0` | 旧版本。默认 Core Tier（27 工具，`enableExtendedAudit: true` 恢复全部 45 工具）；新增 `ctf_sandbox`（双层镜像自动路由/WSL2 兜底）、`ctf_graph`、`ctf_arena` 与 `crypto_solver solve`。 |
| 0.48.x | `>=0.2.2-rc.5 <0.3.0` | 旧版本。函数级 Rev 控制流分析，以及 ZIP 候选检查、文件片段复读和压缩附件链路需要对应工具及宿主能力。 |
| 0.45.x–0.47.x | `>=0.2.2-rc.5 <0.3.0` | 旧版本；依具体功能需要相应工具及宿主能力。 |
| 0.44.x–0.39.x | `>=0.2.2-rc.5 <0.3.0` | 旧版本；ZIP 候选检查与文件片段复读需要 `ctx.fs.readByteRange`。 |
| 0.38.x | `>=0.2.2-rc.5 <0.3.0` | 扫描与 ZIP 区间查询需要 `ctx.fs.readByteRange`。 |
| 0.37.x | `>=0.2.2-rc.5 <0.3.0` | 要求 `ctx.fs` 与 `tools.register`；系统提示接口缺失时回退包内 SKILL |
| 0.33–0.36 | `>=0.2.2-rc.5 <0.3.0` | 旧版本；升级后工具输出默认改为紧凑 JSON |
| 更低 | 未验证 | 低于声明范围不支持；运行时 `ctf_doctor` 可报告宿主能力缺失 |

升级 DSH 前先跑 `npm test`；若 `engines.dsh` 上限不再满足，先在本机冒烟测试通过再改 `engines` 字段。
