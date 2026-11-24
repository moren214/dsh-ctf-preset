# `@local/dsh-ctf-preset` (v0.50.0) 红队级代码与实战审查报告

> **审查日期**：2026-11-24  
> **审查目标**：`D:\文档\deepseek-harness\default-workspace\ctf-preset` 及宿主配置 `C:\Users\10844\.dsh\`  
> **实测基线**（Windows 宿主，Node 实测）：
> - `node scripts/check-modules.mjs`：**81 个 JS 模块语法与本地导入通过**；
> - `node scripts/check-coverage.mjs`（放开回环网络后）：**149/149 测试通过（0 跳过）**，总体 JS 覆盖率 **70.19% lines / 63.07% branches / 70.67% funcs**（9 个核心模块达下限；但 **10 个 JS 模块函数覆盖率为 0%**，约 **150 KB Python worker 覆盖率 0% 追踪**）；
> - Schema 体积实测：**Core Tier 27 个工具 = 32,072 chars（~9,163 tokens）**；**Extended Tier 45 个工具 = 44,435 chars（~12,696 tokens）**；叠加 `SKILL.md`（29,358 bytes，经比对与 `C:\Users\10844\.dsh\skills\ctf\SKILL.md` 哈希一致）；
> - 宿主配置 `C:\Users\10844\.dsh\ctf-workbench.json` 指向本机 `Python314` 与 `base100Source`。

---

## 1. 总评与加权打分表

> 注：原审查清单标题写“8 大维度”，实际列出 7 个编号维度且权重之和恰为 **100%**，下表严格按 7 个权重维度计分（维度 2 下含 6 个子方向独立打分）。

| 维度 | 权重 | 得分 (/10) | 加权分 | 一句话红队定性 |
|---|---:|---:|---:|---|
| 1. DSH 集成与整体架构 | 15% | **7.2** | 1.080 | 零 npm 依赖与分层思路清晰，但存在 131 KB God Object、全局可变状态、CAS/多文件原子性短板与脆弱手写解析器 |
| 2. 分方向 CTF 解题实战能力 | 25% | **7.1** | 1.775 | 广度惊人、零拷贝链路扎实，但高频高难场景（Ghidra 查址、大 PCAP 内存、4096-bit RSA、无节头 ELF、Web 长连接、AI 模型绕过）存在硬伤 |
| 3. Agent 可用性与上下文工程 | 15% | **7.6** | 1.140 | Core Tier 瘦身与 `source_result_id` 零拷贝有效，但 Core Schema + `SKILL.md` 仍占 ~19k tokens，`ctf-progress` 报错失分类 |
| 4. 比赛全流程表现与多代理协同 | 15% | **7.0** | 1.050 | 闭环设计完整，但多代理 Fencing 可被复用槽位击穿、图谱 500 条硬上限无归档、平台 50 题无分页、自签 HTTPS 不可用 |
| 5. 工程质量、代码健壮性与测试可信度 | 10% | **6.7** | 0.670 | 149 绿灯存在严重“Mock 假象”：10 个 JS 模块 0% func 覆盖，真浏览器/真 Docker/真 Ghidra/真 Windows 锁竞争均未实测 |
| 6. 安全边界与对抗鲁棒性 | 10% | **6.4** | 0.640 | **最接近一票否决区**：WSL2 静默降级丢弃全部隔离、题面文本自动授权内网端口、GDB 双引号命令展开、Pickle/GGUF 体检可绕过 |
| 7. 配置管理、兼容性与跨平台部署 | 10% | **6.9** | 0.690 | `SKILL.md` 与 `tool_tier_sync` 自检贴心，但 `resolvePython` 绕过热重载、Windows 锁/CRLF 踩坑、Dockerfile 未锁版本且吞错 |
| **加权总分** | **100%** | — | **7.05 / 10** | **定位：可用但粗糙（7.0–7.9 区间下沿）——设计野心接近 8.5，实战细节与安全/并发硬伤将其拉回 7.0** |

### 是否存在“一票否决级”隐患？

**存在 2 项准一票否决（P0 阻断级）隐患**：
1. **静默隔离失效（安全边界）**：`ctf_sandbox` 默认 `backend: "auto"` 在 Docker 未启动/未构建时静默降级到 WSL2，**直接丢弃 `network: "none"`、`read_only_work: true`、cap-drop 与资源配额**，却只在执行**之后**才在返回 JSON 中标注 `network: "host_shared_wsl"`（`sandbox-runner.js:351-356, 947-963`）。
2. **题面文本诱导 SSRF 边界扩张（对抗鲁棒性）**：`ctf_arena(detail)` 直接把不可信赛题 `description` 中提取出的所有 URL 与 `host:port`（如 `http://127.0.0.1:2375`、`10.0.0.1:6379`）自动注入动态授权表，并用 64 条 FIFO 挤掉合法靶机（`ctf-arena.js:359-367`）。

---

## 2. 最值得肯定的 5 个真实硬核亮点

1. **零拷贝 `source_result_id` / `source_result_ids` 证据链**：归档成员 → PNG 连续位流（按 `next_bit_offset` 整字节续页）→ QR 码 / PDF 渲染页 / AI 模型静态体检全链路内存衔接，每跳校验输入与原件 SHA-256，无需 LLM 复制 Hex 或落地中间临时文件（`ctf-tools.js:550-571, 1715-1751`）。
2. **`crypto_solver` 脚手架不是摆设**：经源码核验，`extra-tools.js:780-950` 中的 `ecc_weak`（Pohlig-Hellman + BSGS + 射影坐标 Smart 异常曲线攻击）与 `lattice`（`fpylll` LLL/BKZ 线性同余小根求解）是**真正可编译、无占位符、带自检向量的实战算法**，而非空壳模板。
3. **`offline-calculation-runner.js` Worker 隔离与断点续算**：离线密码计算跑在独立 `worker_threads` 中，硬限制 `maxOldGenerationSizeMb: 64`、5 秒时间片、最多 2 并发 Worker，超时后通过 `WeakRef` 检查点（15 分钟 TTL）携带 `resume_id` 从 `next_step` 续算，且保证 `worker.terminate()`，有效防主进程 OOM/卡死。
4. **平台凭据零明文纪律与响应脱敏**：`platform-request.js` 强制从环境变量读取平台 Token，发请求前拒绝明文配置，且支持 `http_request` 保留赛题 `Set-Cookie`/`WWW-Authenticate` 仅脱敏平台 Token，兼顾 Web 解题与凭据保护（覆盖率 100% lines / 90.91% branches）。
5. **诚实的文档与自检工程习惯**：`ctf_doctor` 主动检测 `SKILL.md` 同步哈希、冷热配置漂移（`tool_tier_sync`）、原生 `libarchive` 而非 pip 假阳性，且有专门的契约测试校验 `package.json` `files`、`README.md` 与 `CHANGELOG.md` 一致性（`ctf-tools.js:935-991`）。

---

## 3. 最尖锐的 10 个核心缺陷 / 隐蔽 Bug / 实战痛点

| # | 严重等级 | 代码位置 | 问题机理 | 实战翻车场景 |
|---|---|---|---|---|
| 1 | **P0 严重** | `sandbox-runner.js:351-356, 947-963` | `backend: "auto"` 降级 WSL2 时静默忽略 `network: "none"` 与 `read_only_work: true`，无任何前置阻断 | 选手以为在断网只读沙箱里跑恶意 ELF/木马脚本，实际在 WSL2 中带着宿主机网络与 `/mnt/c` 读写权限直接裸奔 |
| 2 | **P0 严重** | `ctf-arena.js:359-367`, `network-boundary.js:216-235` | `fetchChallengeDetail` 将不可信题面 `description` 中所有 URL/`host:port` 无差别调用 `grantHttp`/`grantTcp`，未拦截回环/RFC1918 内网 | 对抗赛题面植入 Prompt Injection + `http://127.0.0.1:2375` 或 `10.0.0.1:6379`，直接打穿网络边界并挤出合法靶机授权 |
| 3 | **P0 严重** | `media-reader-worker.py:605, 650-751, 875, 913, 972` | Pickle 栈模拟忽略 `APPEND`/`SETITEM`/`PERSID` 导致 `STACK_GLOBAL` 栈失同步；`torch`/`numpy` 前缀全放行漏掉 `load_inline`/`torch.hub.load`；GGUF 在 64 KV / 1024 字节处截断后再检 SSTI；PyTorch ZIP 静默跳过第 9 个 `.pkl`/`.py` | AI-Sec 题在 Pickle 中插一条 `SETITEM` 或在 GGUF 第 65 个 KV / 1KB 注释后放 Jinja2 Payload，`inspect_media(model)` 返回 `risk_level: "low"`，误导选手/代理直接加载中招 |
| 4 | **P0 严重** | `extra-tools.js:184-186, 1403-1404` | `gdb_driver` 拼接 `run < "${stdinFile}"` 使用双引号，Linux 下 GDB 调用 `/bin/sh` 做重定向会展开 `$(...)`/反引号/`$VAR` | 解压恶意题包产生含 `$(id)` 的工作区文件名，调用 `gdb_driver` 传入 `stdin_file` 即触发任意命令执行 |
| 5 | **P1 高危** | `ctf-graph.js:9-10, 348-349, 585, 851` | (a) `dispatch_plan` 每轮硬编码 `worker-1/2/3`，无单调租约 token，旧代理醒来可撞名篡改任务；(b) Windows `EPERM`/`EBUSY` 锁冲突在 `current.version === document.version` 时**第 0 次即直接抛错不重试**；(c) 500 条 Facts/Intents 硬上限且无清理/归档命令 | 48 小时 40+ 题国际赛，3–5 代理在 Windows 并发抢题时频繁假报错、旧代理复活覆写进度，赛程过半撞 500 条硬墙直接锁死整个图谱 |
| 6 | **P1 高危** | `browser-gateway.js:50-55`, `browser-session.js:317-321` | `CONNECT` 隧道把 `AbortSignal.timeout(30000)` 直接绑在 `net.createConnection` 上，Node 在连接建立后仍保留 signal，**30 秒强杀所有 HTTPS/WSS 长连接**；且 `CONNECT` 硬编码 `https://` 拦截 `ws://`；单次 `waitFor` 超时直接销毁整个浏览器进程与 Cookie | Web 题中任意 SSE/WebSocket/长轮询或耗时稍长的 XSS/盲注交互在 30 秒必断；一次等待元素超时清空全部登录态与抓包记录 |
| 7 | **P1 高危** | `pcap-stream.js:344, 356, 775-785, 873-883` | 64 MiB+ 流式读取用 1 MiB `Buffer.allocUnsafe` 并直接把 `subarray` 视图存入流/分片队列，**每个小包钉死整块 1 MiB 父 Buffer**；PCAPNG 流式路径未校验 SHB `blockSize >= 28` 直接抛未捕获 `RangeError` | 500 MB 流量取证题看似流式读取，实际数百 MB 内存无法释放引发 OOM；畸形 16 字节 SHB 直接崩掉整个工具 |
| 8 | **P1 高危** | `sandbox-runner.js:492, 498-499, 518` | Ghidra `list` 返回补零地址（`0x00401000`），但查函数时 `lstrip('0')` 去零导致**拿着 `list` 返回的地址查反编译必然匹配失败**；且 `run_headless` 硬编码 `timeout=90`，无视 `HEAVY_DECOMPILE_TIMEOUT_MS=120s` 和用户 180s 设置 | 逆向题切 `profile: "heavy"` 列完函数表再按返回地址反编译，稳定报找不到函数；大二进制 90 秒被提前腰斩且静默吞掉 stderr |
| 9 | **P1 高危** | `offline-calculation.js:1029-1036, 1323`, `crypto-toolbox.js:344, 407` | 4096-bit RSA 求解结果因 `factors + d + plaintext` 超出 4096 字符上限，**静默删除 `plaintext`/`plaintext_hex`**；`rsaKnownD` 误拒 `e*d-1 > 4096 bit`；`recoverLcg` 失败时仍覆写 `candidate`，且 `gcd > 64` 跳过导致 2^32/2^64 模数频繁漏解 | 辛苦算出 4096-bit RSA 私钥，工具把明文直接静默删掉；标准 2048-bit 已知 `d` 题被当成超限拒绝 |
| 10 | **P1 高危** | `platform-request.js:72-78`, `ctf-arena.js:21, 338`, `submission.js:23, 28, 130-135` | `platformRequest` 无法配置自签 HTTPS（无 `allow_insecure`）、禁跳转且给无包体 `GET`/`DELETE` 硬塞 `Content-Type: application/json`；`ctf_arena` 题单死卡 50 题无分页；`submission.js` 把 401/429/500 的 `{"success":false}` 误判为 Flag 错误，网络异常写入 `unknown` 回执后反而锁死重复提交 | 线下断网内网自签 HTTPS 赛场全线瘫痪；大场超过 50 题后半场题拉不到；平台限流 429 后被系统判死刑且阻止重提 |

---

## 4. 7 大维度逐项深度评审

### 维度 1：DSH 集成与整体架构（7.2 / 10，权重 15%）
- **生命周期与资源清理**：`apply()` 用 `ctx.effect` 清理了 `calculation`、`managers`（TCP）和 `base100`，但：
  - `cookieJars`（`ctf-tools.js:1825-1840`）无容量上限、无 `effect` 清理，且 `execution.agent.session` 未做空值保护（与第 236 行 `agent?.session` 风格不一致）。
  - `net-session.js:400-448, 636-645` 中正在建连（`authorize`/`openSocket`）的 socket 未登记进 `sessions`，`dispose()` 无法中止它们，且空闲清理是被动触发的（不调 `execute()` 就不关 socket）。
  - `browser-session.js:147-170` 关闭浏览器时的 `wait()` 定时器未 `unref()`，且只有 `SIGTERM` 无 `SIGKILL` 兜底，Windows 锁住临时 profile 目录时易留僵尸进程与残留目录。
  - `ctf-tools.js:99` 的 `instanceTransitions = new Set()` 为**模块级隐式全局状态**，跨 `apply(ctx)` 实例互相干扰。
- **工具分层（Core 27 vs Extended 45）**：
  - 合理之处：将低频/旧审计工具（`verify_*`、`trace_flask_route`、`cloud_metadata`、`competition_api`）移出默认层，Schema 从 44.4 KB 压到 32.1 KB。
  - 错配之处：**高频实战工具 `pwn_cyclic`、`pwn_payload`、`mobile_apk`、`read_log_range` 被藏进冷启动扩展层**（无法热重载开启），而 4.37 KB Schema 的 `calculate_offline` 和 2.95 KB 的 `ctf_progress` 常驻核心层。
- **God Object 与耦合度**：`ctf-tools.js`（2,320 行 / 131.7 KB）、`extra-tools.js`（1,762 行 / 90.7 KB）、`offline-calculation.js`（93.2 KB）均严重膨胀。
- **状态机与持久化原子性**：
  - `ctf-graph.js:335-354` 与 `ctf-status.js:57-71`：无退避/抖动的紧循环 CAS，且 Windows `EPERM`/`EBUSY` 会立即中止重试；`graphFiles.write` / `statusFiles.write` 漏发 `ctx.emit('fs/observed', ...)`（`ctf-tools.js:708, 768`），导致宿主文件版本缓存脏读。
  - `ctf-progress.js:803-817, 853-868`：`save`/`repair` 顺序写 4 个文件无跨文件锁，`notes.md` 写失败时已提交的 `state.json` 不回滚，产生撕裂态。
- **零外部 npm 依赖的代价**：手写解析器在边界场景全面承压——ZIP64 SFX 硬编码 `adjustment: 0`（`zip-directory.js:83-97`）、PCAPNG SHB 越界读（`pcap-stream.js:873-883`）、PNG CRC 报错直接全盘中止（`image-metadata.js:114-116`）、CDP 导航 `readyState` 竞态与重定向 `requestId` 淘汰丢事件（`browser-session.js:51-56, 334-339`）。

---

### 维度 2：分方向 CTF 解题实战能力（7.1 / 10，权重 25%）

#### 2.1 Web（7.2 / 10）
- **强在哪**：`http_request` 支持自定义 `Host`（VHost/Host 注入）、多 `cookie_jar`、`multipart` 文件上传、保留赛题 `Set-Cookie`/`WWW-Authenticate`；`browser_session` 支持真浏览器 DOM/Storage/Network 响应体/Console/自动接管 `dialogs`（防 XSS 弹窗卡死）与文件上传。
- **致命缺口与卡壳点**：
  - **长连接与 WebSocket 断层**：`browser-gateway.js:52-55` 30 秒强杀 HTTPS/WSS 隧道；`browser-gateway.js:50` 拦截 HTTP 源下的 `ws://`；`http_request` 不支持 WebSocket、自定义 HTTP 方法（WebDAV/PROPFIND）、重复同名请求头、原始报文（HTTP 请求走私/CRLF）及高并发竞态发包（Race Condition）。
  - **Cookie Jar 缺陷**：`http-client.js:288-295` 无 PSL 校验且对 IP 做后缀匹配（`192.168.1.10` 接受 `Domain=1.10`）；`mergeCookieHeader`（`431-438`）按 name 去重会覆盖高优先级路径 Cookie；忽略 `SameSite`。
  - **强赛卡壳**：自签证书靶机打不开 `browser_session`；单次 `waitFor` 超时直接杀浏览器丢登录态（`browser-session.js:317-321`）；`POST` → `303 See Other` 被误判 `request_replay` 拦截（`http-client.js:597`）。

#### 2.2 Pwn（6.8 / 10）
- **强在哪**：`inspect_elf` 原生做 checksec/PLT/GOT/libc 导出/`/bin/sh`；`net_session` 支持 TCP 长连接 + 二进制 hexdump；`gdb_driver` 在 Windows 下可自动桥接 Linux 沙箱 GDB；Docker 镜像内置 `pwntools`/`gef`/`pwninit`/`seccomp-tools`/`one_gadget`/`qemu-user`。
- **致命缺口与卡壳点**：
  - **无节头 ELF 瘫痪**：`elf.js:297-365, 491-493` 不回退 `PT_DYNAMIC`，去节头 ELF 误报 Full RELRO 为 `partial`、丢 `DT_NEEDED`/导入表/canary，甚至跳过 `/bin/sh` 扫描；`canary` 漏检 32 位 PIE 的 `__stack_chk_fail_local`（`:316`）；`FORTIFY` 用 `endsWith('_chk')` 误报用户函数（`:317`）。
  - **GDB 白名单捆住手脚**：`extra-tools.js:17-32` 禁止 `set`（无法设 `follow-fork-mode`/改寄存器/内存）、`handle`（无法忽略 `SIGALRM`）、`watch`/条件断点及 GEF 堆命令（`heap chunks`/`bins`/`vis`），且硬编码 `gdb` 而非 `gdb-multiarch`（`:1375`）——真打堆题或跨架构 Pwn 只能放弃 `gdb_driver` 改写 `ctf_sandbox(exec)` 脚本。
  - **Payload 组装器玩具化**：`pwn_cyclic`/`pwn_payload` 藏在扩展层；`pwn_payload` 仅支持 x86-64 单参数 `ret2libc`（无 32 位/ARM/AArch64、无 ORW/seccomp 多参数 ROP、无 SROP、无保留 Canary 布局）。

#### 2.3 Reverse（6.9 / 10）
- **强在哪**：`rev_query` 支持 ELF32/64（x86/x64/ARM/AArch64/RISC-V）与 PE32/32+，且 `triage` 无需 `capstone` 即可识壳/编译器/密码常量；`ctf_sandbox(decompile)` 支持 r2/r2ghidra 与重型镜像 Ghidra Headless + SHA-256 缓存。
- **致命缺口与卡壳点**：
  - **Ghidra 反编译核心链路断裂**：`list` 返回补零地址（`0x00401000`）与 lookup 去零不匹配（`sandbox-runner.js:492, 498-499`）；`run_headless` 硬编码 `timeout=90` 覆盖 120s/180s（`:518`）；并发缓存 `os.replace` 冲突被静默吞错（`:578-581`）；`except Exception: return None` 吞掉所有 Java/Jython 崩溃（`:601-602`）。
  - **r2 与反汇编脆弱**：`clean_r2_pseudo`（`:474-476`）只要伪代码里含 `"Cannot find"` 字符串就丢弃整段反编译；`objdump`/`gdb` 兜底硬编码 Intel 语法（`:729, 747`），ARM/RISC-V 直接报错。
  - **格式盲区**：`rev-disasm-worker.py` 不支持 Mach-O、WASM、DEX、`.pyc`；PE 无导入/导出表与 CFG；`_scan_strings` 仅扫 ASCII 漏掉 Windows/.NET 遍地的 UTF-16LE（`:1112`）；篡改节头大小的 ELF 直接让解析器抛错降级为 `raw`（`:275-277`）；无节熵检测；`.NET` 漏检 .NET Core/5+；Unity/IL2CPP、eBPF 均无专门支持。

#### 2.4 Crypto（7.3 / 10）
- **强在哪**：内置无依赖 `crypto-toolbox.js`（JWT/Flask/LCG/MT19937）+ Worker 隔离 `calculate_offline` + 7 个真正可跑通的 `crypto_solver` 脚手架（含 `fpylll` LLL/BKZ、Pohlig-Hellman + Smart 攻击、Z3、Padding Oracle、Hash Ext）。
- **致命缺口与卡壳点**：
  - **4096-bit RSA 静默丢明文**：`offline-calculation.js:1029-1036` 受 `MAX_VALUE_CHARACTERS = 4096` 截断，静默删除 `plaintext`；`rsaKnownD`（`:1323`）误拒 `e*d-1 > 4096 bit`；`pollardBrent`（`:1065-1071`）缺回溯逻辑；不支持多素数 RSA 与 `gcd(e1,e2) > 1` 共模攻击。
  - **LCG/JWT/Flask 暗坑**：`recoverLcg`（`crypto-toolbox.js:407`）失败仍改写 `candidate` 且 `gcd > 64`（`:344`）在 2^32/2^64 模数易失效；`jwt_inspect` 对极端时间戳抛未捕获 `RangeError`（`:121-129`）；`timeout_ms=NaN` 绕过超时（`:154, 242`）；Flask 仅支持 `hmac` 派生且无**伪造签发**模式；MT19937 Schema `maxItems: 624` 拒绝多粘贴 1 个测试值（`extra-tools.js:1698`），且不支持截断输出（GF(2)）/倒推。
  - **强赛高难短板**：Coppersmith/格规约/SageMath 均无直接交互工具，只能先写模板再走 `ctf_sandbox(exec)`，且 SageMath 在 `Dockerfile.heavy` 中默认关闭（需手动 `--build-arg WITH_SAGE=1`）。

#### 2.5 Misc / Forensics（7.4 / 10）
- **强在哪**：全栈最成熟的方向——ZIP 伪加密识别、跨块签名扫描 `scan_binary`、PNG 连续 `bitstream`→QR 零拷贝拼接、24-bit `WAVEFORMATEXTENSIBLE` 选段/声道 LSB 与频谱图、PDF 渲染/附件提取、只读 SQLite/Office。
- **致命缺口与卡壳点**：
  - **大 PCAP 内存陷阱与协议盲区**：64 MiB+ 流式读取因 `subarray` 钉死 1 MiB slab 导致内存飙升（`pcap-stream.js:344, 356, 775-785`）；不支持 IPv6、TLS Keylog 解密、HTTP Keep-Alive/Chunked/Gzip/HTTP2、USB HID、非 TXT 的 DNS 隧道（A/CNAME/NULL 记录全丢）；IPv4 重叠分片直接丢弃（`pcap-fragments.js:39`）；TCP 未锚定 SYN ISN。
  - **图片/EXIF 过于严苛反伤 CTF**：`image-metadata.js:114-116` 遇到 PNG CRC 校验失败直接抛错中止，连宽高/分块/尾随字节都不返回——恰恰撞上最经典的“改 PNG IHDR 高度隐写”题；`exif.js:49-69` 遇到非标 Orientation 丢弃整块 EXIF，且完全忽略 `UserComment`/`MakerNote`。
  - **归档与取证盲区**：`archive-directory-worker.py:178-186` 在 Docker `C` locale 下丢弃非 ASCII 文件名、拒绝 mode=0 的 7z/RAR 条目、无条目数上限；不支持 WinZip AES；`bkcrack`/Volatility3/Sleuthkit 仅预装在 Docker 中，无封装工具与引导。

#### 2.6 Mobile & AI-Sec / 新兴题型（6.8 / 10）
- **强在哪**：前瞻性加入了纯静态零执行 `inspect_media(kind: "model")`（覆盖 Pickle/PyTorch/Safetensors/GGUF/ONNX）与 `mobile_apk` 沙箱自动桥接。
- **致命缺口与卡壳点**：
  - **AI 模型静态体检存在多条明确绕过**：Pickle 栈模拟失同步 + `torch`/`numpy` 白名单过宽（漏 `load_inline`/`torch.hub.load`）+ 忽略 `NEWOBJ`/`BUILD` + `max_ops` 截断不升风险；PyTorch ZIP 仅扫前 8 个 `.pkl`/`.py` 且不扫 `.npz`/`.keras`/嵌套压缩；GGUF 仅扫前 64 个 KV 且先截断 1024 字节再查 SSTI；ONNX 仅解析前 1 MiB protobuf 且不查 `NodeProto` 自定义 op（`media-reader-worker.py:556-1137`）。
  - **Mobile 覆盖单薄**：`mobile_apk` 被隐藏在扩展层；`signature` 动作未桥接沙箱；无 Native `.so` JNI 符号/动态注册分析、无 Frida/Android 动态调试或模拟器联动。

---

### 维度 3：Agent 可用性与上下文工程（7.6 / 10，权重 15%）
- **Schema Token 开销实测**：Core Tier 27 个工具占 **32,072 chars（~9.2k tokens）**，其中 Top 3 巨无霸为 `calculate_offline`（4,451 chars）、`ctf_progress`（3,018 chars）、`ctf_graph`（3,034 chars）；再加上 **29.4 KB 的 `SKILL.md`**（约 10k+ tokens），开局未干活上下文已吃掉 ~20k tokens。
- **错误返回体系漏洞**：`ctf-tools.js` 虽有统一的 `tool-errors.js`，但 `ctf-progress.js` 大量直接 `throw new Error(...)`（包括 CAS 冲突 `line 755` 和只读拒绝 `ctf-tools.js:643`），被 `describeToolError` 全部归为无指导意义的 `kind: 'other'`；`EBUSY` 未映射（`tool-errors.js:16-39`）。
- **结果缓存与参数摩擦**：
  - `ctf-result-values.js:62` 对顶层指针 `'/status'` 寻址错误（查 `report['']`）；`:144` 对超 64 KiB 的无源输出静默不发 `result_id`；
  - `crypto_solver(template)` 用 `flag: 'wx'`，重复生成同名模板直接 `EEXIST` 报错（`extra-tools.js:1755`）；
  - `ctf_status(board)` 强制要求可写会话，只读会话连榜单都看不了（`ctf-tools.js:812`）；
  - `ctf_progress` Schema 声明 `writeup` 需 `revision`（`ctf-progress.js:75`），源码却使其可选（`:744`）。
- **文档与现实一致性**：`SKILL.md` 对 Core vs Extended 做了区分，未出现大面积诱导调用未启用工具的问题，但 211 行/29 KB 信息密度过高，模型在长对话中极易遗忘中后段规则。

---

### 维度 4：比赛全流程表现与多代理协同（7.0 / 10，权重 15%）
- **平台适配（CTFd / GZCTF / 通用）**：
  - 自动探测、GZCTF `Cookie: GZCTF_Token=`、`container(extend)` 续期、按分值升序 + `solves` 降序排优都很贴近实战；
  - 但 `ctf-arena.js:21, 338, 394` 死卡 50 题无分页；`resolveAdapter`（`:79-99`）吞掉所有网络/Abort/HTTPS 权限错直接静默降级 `generic`；`platform-request.js` 不支持自签 HTTPS 与 301/308 跳转；GZCTF `container` 未调用 `extractEndpointsFromText`（`:470`），且不兼容新版 GZCTF 异步提交返回整型 submission ID（`:194-204`）。
- **多代理并发图谱（`.ctf-graph/`）**：
  - `board` 分层索引 + `expand` + `dispatch_plan` + `steal_overdue` 理念先进；
  - 但 **Fencing 机制形同虚设**（无单调 lease token，`worker-1` 跨波次重名撞车，`add_fact`/`add_intent` 无 fencing，`open` intent 任何人可 `finish_intent`）、**500 条硬上限无归档**、每次变更重写 `graph.json` + `graph.saved.json` + `BOARD.md` 造成 O(C×(F+I)) 与 ~25–30 MB 磁盘写放大、分页把 `facts`/`intents` 共用一个 `offset` 且 `ruled_out` 忽略 `offset`（`ctf-graph.js:428-466`）。
- **防误交与续接**：`check_flag`/`submit_flag` 纪律清晰，但 `submission.js:23, 28, 130-135` 把平台 401/429/500 错判为 `rejected`（错 Flag）并在网络异常时写入 `unknown` 回执阻塞重试；`ctf-progress.js` `handoff` 在只读+旧标题同时触发时丢失警告（`:884-885`）。

---

### 维度 5：工程质量、代码健壮性与测试可信度（6.7 / 10，权重 10%）
- **反作弊测试戳穿（核心失分项）**：
  1. **10 个 JS 模块函数覆盖率 0.00%**：`archive-directory.js`、`archive-password.js`、`batch-text.js`、`compressed-stream.js`、`flask-route.js`、`rev-address.js`、`rev-evidence.js`、`rev-export.js`、`rev-machine.js`、`rev-trace.js`。
  2. **关键交互模块严重低覆盖/全 Mock**：`image-metadata.js`（17.13% lines / 8.33% funcs）、`browser-session.js`（25.67% lines，**全程未启动过一次真浏览器**，仅喂合成 CDP JSON）、`workbench-base100.js`（28.81% lines）、`offline-calculation.js`（44.76% lines）。
  3. **约 150 KB Python worker 0% 覆盖追踪**：`rev-disasm-worker.py`（54 KB）、`media-reader-worker.py`（53 KB）、`flask-route-worker.py`（32 KB）、`archive-directory-worker.py`（10 KB）均不在 `check-coverage.mjs` 视野内。
  4. **测试夹具掩盖真实故障**：`ctf-graph.test.js` 100% 内存 Map Mock；`ctf-arena.test.js` 用非原子 `writeFile` 假装 CAS；`sandbox.test.js` 用假 Python shim 替代 `r2`/`analyzeHeadless`，唯一真沙箱测试在无 Docker/WSL2 时 `t.skip` 且即使 `heavy` 失败也照样通过。甚至测试清理自己都需要 `rm(..., { maxRetries: 8, retryDelay: 120 })` 来绕开 Windows `EBUSY`/`EPERM`，却没给生产代码 `ctf-graph.js`/`ctf-status.js` 写锁重试。
- **取消信号与进程健壮性**：`http-client.js:817-821` 重定向授权与 `ctf-arena.js:79-99` 平台探测均吞掉 `AbortError`；`httpRequest` 每跳重定向重置超时（最多 6×30s=180s）；`sandbox-runner.js:199-203` 在 Windows 上 `taskkill wsl.exe` 杀不掉 WSL2 VM 内孤儿进程，且 `docker kill` 存在容器尚未建好时的竞态泄漏（`:405-409`）。

---

### 维度 6：安全边界与对抗鲁棒性（6.4 / 10，权重 10%）
- **沙箱与容器加固**：Docker 默认 `--cap-drop=ALL`、`--security-opt=no-new-privileges:true`、`--network=none` 值得肯定，但**未设 `USER`/`--user`（容器内以 UID 0 root 运行）**、无 `--read-only` 根文件系统、无 `--memory-swap`（可吃 2× 内存的 swap）、`decompile` 挂载 `/work` 为读写（只为写 `.ctf-cache/ghidra`）；WSL2 降级则彻底裸奔。
- **SSRF / 代理 / 命令注入**：
  - `ctf-arena.js:359-367` 题面文本自动授权内网/任意地址；
  - `browser-gateway.js:13-66` 本地代理无 `Proxy-Authorization` 认证；
  - `extra-tools.js:1403-1404` `gdb_driver` 双引号重定向允许工作区文件名命令展开；
  - `sandbox-runner.js:671-676, 749, 978` `args.function` 允许 `@`/`+`/`-`/`$` 导致 r2/GDB 命令解析干扰；
  - `network-boundary.js:225-231` IPv6 冒号被正则误拒导致动态 IPv6 TCP 授权恒失败，`parseHttpRule` 丢弃纯数字路径 URL（`:130-144`），单地址 DNS Pin 破坏双栈回退（`:63-78`）；
  - `platform-request.js:29-60` 脱敏不覆盖 URL/Base64 编码回显与重定向 URL；
  - `workbench-config.js:51-54, 166` `base100Source` 允许 `..` 与符号链接。
- **对抗性附件**：Pickle/PyTorch/GGUF/ONNX 静态体检绕过（见缺陷 #3）、PCAP 内存钉死（缺陷 #7）、libarchive 无条目数上限（`archive-directory-worker.py:167-194`）、ZIP 无压缩比/嵌套深度限制。

---

### 维度 7：配置管理、兼容性与跨平台部署（6.9 / 10，权重 10%）
- **热重载与优先级 Bug**：
  - `workbench-config.js:141` `resolvePython()` 在调用 `settings()` 之前先检查 `if (python !== undefined) return python;`，**彻底绕过热重载**；
  - `workbench-config.js:124` 冷启动 `overrides` 永远覆盖热重载后的 `ctf-workbench.json`；
  - `Base100Workbench` 60 秒空闲期内不感知配置变更（`workbench-base100.js:133`）；
  - `enableExtendedAudit` 只能冷启动生效（`ctf-tools.js:1868`）。
- **Windows 跨平台暗坑**：
  - CAS 遇 `EPERM`/`EBUSY` 零重试；
  - 工作区 `.sh` 含 Windows CRLF 在 Linux 沙箱执行报 `$'\r': command not found`（`sandbox-runner.js:931-941`）；
  - `gdb_driver` 在 Windows 把 `args` 里的 `\` 全替换为 `/`（`extra-tools.js:1408-1409`）；
  - `DECOMPILE_SCRIPT` 约 14 KB 内联传参逼近 Windows 32 KiB 命令行上限；
  - `workbench-config.js:160` 校验 `ctf_extra_ops.py` 区分大小写，且 `constants.X_OK` 在 Windows 无效。
- **双层 Dockerfile 可复现性与国内网络**：
  - `ubuntu:24.04` 未锁 digest，~55 个 apt 包、21+ 个 pip 包、3 个 gem 包与 `r2ghidra` 均未锁版本；
  - 所有二进制下载（Ghidra/jadx/apktool/bkcrack/pwninit/ffuf/GEF）**无 SHA-256 校验**；
  - `Dockerfile:143` `(r2pm -U && r2pm -ci r2ghidra || echo WARN)` 静默吞错；
  - 仅支持 `PIP_INDEX_URL`，缺 APT / RubyGems / GitHub Release 镜像源参数，国内裸建极易超时失败；且未清理编译依赖（`cmake`/`meson`/`/opt/radare2`）与 Ghidra/jadx GUI，镜像膨胀严重。

---

## 5. 5 大极限压力场景推演结论

1. **无 Docker 的纯 Windows 笔记本打一场综合赛（有/无 WSL2）**
   - **有 WSL2**：`ctf_sandbox` 会自动降级到 WSL2，能跑通基础 Linux 工具，但**所有沙箱隔离（断网、只读、内存/PID 限制）静默失效**；执行 Windows 保存的 CRLF `.sh` 脚本直接报错；超时 `taskkill` 后 WSL2 内子进程残留成僵尸；若中途在 `ctf-workbench.json` 修正 `pythonPath`，因 `resolvePython()` 缓存 Bug 不会生效。
   - **无 WSL2**：Web/Crypto/基础 Misc 可战（依赖本机 Python 3.14 + Chrome/Edge），但 Pwn/深度 Reverse/Linux Misc 全线瘫痪——`gdb_driver` 无法调试 Linux ELF，`rev_query` 无 `capstone` 时退化为仅 `triage/strings`，`pwn_triage`/`decompile` 全部不可用。
2. **48 小时大型国际赛（40+ 道题、3–5 个并行子代理同时抢题与写图谱）**
   - **必崩点 1（开场）**：若题数 > 50，`ctf_arena(sync_graph)` 静默截断，第 51 题起不可见。
   - **必崩点 2（中期）**：3–5 代理在 Windows 并发写 `.ctf-graph/graph.json`，遇 `EPERM`/`EBUSY` 零重试即假报 `permission`/`other` 错；且每次变更触发 25–30 MB 全图读写与 Markdown 重渲染，CAS 饥饿加剧；第二波 `dispatch_plan` 再次分配 `worker-1`，与超时未退出的第一波 `worker-1` 撞名互相覆写。
   - **必崩点 3（中后期）**：40 题 × 12 条 Facts/Intents 迅速撞破 `MAX_FACTS/MAX_INTENTS = 500` 硬墙，且**没有归档/清理动作**，整张图谱彻底锁死。
3. **线下断网内网赛（HTTP 无 HTTPS、自签证书、非标平台 API、动态靶机高频轮换）**
   - **自签 HTTPS 平台**：`platform-request.js` 无 `allow_insecure` 参数，**`ctf_arena`/`submit_flag`/`ctf_instance` 100% 连接失败**；`browser_session` 同样无法访问自签 HTTPS 靶机。
   - **HTTP 内网平台**：配 `allowInsecurePlatformHttp: true` 可通，但若平台有 301/308 尾斜杠跳转或严格校验 `GET`/`DELETE` 不带 `Content-Type: application/json`，依然失败；`resolveAdapter` 会吞掉错误并静默退回 `generic`。
   - **高频轮换**：`network-boundary` 动态授权表仅 64 条 FIFO，高频开靶机或浏览带链接题面会不断挤掉正在打的靶机端口；若是 IPv6 靶机则直接无法授权。
4. **恶意/对抗性题目附件（Prompt Injection 网页、混淆 Pickle、500 MB PCAP、无节头去符号加壳 ELF）**
   - **Prompt Injection 题面/网页**：若出现在赛题描述中，直接借 `ctf-arena.js:359-367` 注入内网 IP 到动态白名单实现 SSRF；网页内 XSS 弹窗可被 `dialogs` 拦截，但单次操作超时会销毁整个浏览器会话。
   - **混淆 Pickle / 恶意 GGUF**：加一条 `SETITEM` 或放进第 65 个 KV / 第 9 个 `.pkl` 即可绕过 `inspect_media(model)` 拿 `low` 风险评定。
   - **500 MB PCAP**：流式读取因 `subarray` 钉死 1 MiB 父 Buffer，引发数百 MB 内存滞留甚至 OOM；若为畸形 16 字节 SHB 则直接 `RangeError` 崩溃。
   - **无节头去符号加壳 ELF**：`inspect_elf` 丢失 RELRO/canary/导入/`/bin/sh`；`rev_query` 若遇篡改节头直接降级 `raw`；`ctf_sandbox(decompile)` 用 `profile: "heavy"` 列完函数后按补零地址查反编译失败，或 90 秒被硬编码超时静默掐断。
5. **长会话中断 / DSH 重载后接手半成品题目**
   - **能接上的部分**：`.ctf/state.json`、`notes.md`、`handoff.md`、`.ctf-graph/graph.json` 与 `.ctf/results.json` 能保留主线结论与部分已落盘证据。
   - **会断掉的部分**：所有内存派生字节缓存（`source_result_id` 对应的 PNG bitstream/PDF 渲染页/归档解压字节）、`http_request` 的 `cookie_jar`、长连接 `net_session` 与 `browser_session` 状态全部归零；若中断恰好发生在 `ctf_progress(save)` 的 4 文件顺序写之间，`state.json` 与 `notes.md` 撕裂需手工 `repair`；若之前靠 `ctf_arena`/`ctf_instance` 动态授权了靶机端口，重载后内存中的 64 条动态授权全部丢失，必须重新 `detail`/`list` 才能连回靶机。

---

## 6. 分阶段可执行整改路线图

### P0：必须立即修复的安全 / 正确性 / 翻车级缺陷（阻断发布）

| 编号 | 改造目标 | 涉及文件 | 验收标准 | 改动成本 | 预期提分 |
|---|---|---|---|---|---|
| **P0-1** | **阻断 WSL2 静默丢隔离**：当请求 `network: "none"` 或 `read_only_work: true`（或 `allow_exec: true`）且 Docker 不可用时，禁止自动降级 WSL2，返回明确 `dependency` 错误并要求用户显式传 `backend: "wsl"` | `sandbox-runner.js` | 单测覆盖：`backend: "auto"` + `network: "none"` 在无 Docker 时拒绝回退 WSL2；仅显式 `backend: "wsl"` 放行 | 小（0.5 天） | 维度 6 **+0.8** |
| **P0-2** | **收紧题面自动授权防 SSRF**：`ctf_arena` 仅从结构化 `connection`/`container` 字段提取靶机，禁止自动授权 `description` 自由文本；`grantHttp`/`grantTcp` 默认拦截回环与 RFC1918（除非命中已配置平台网段）并修复 IPv6 冒号误拒 | `ctf-arena.js`, `network-boundary.js` | 含 `127.0.0.1:2375` 的题面描述不进入白名单；IPv6 `[::1]:8080` 动态授权通过单测 | 小（0.5 天） | 维度 6 **+0.7**，维度 4 **+0.2** |
| **P0-3** | **修复 `gdb_driver` 命令展开与 `browser-gateway` 30s 断连**：POSIX 下 `stdin_file` 改用单引号转义；`browser-gateway` 仅在建连阶段用超时、连接建立后移除定时器，并支持 `ws://` 与可选本地 `Proxy-Authorization` | `extra-tools.js`, `browser-gateway.js` | 文件名含 `$(touch pwn)` 不触发执行；HTTPS/WSS 隧道保活 > 35s 不中断 | 小（0.5 天） | 维度 6 **+0.5**，维度 2 **+0.3** |
| **P0-4** | **修补 AI 模型静态体检绕过**：Pickle 完整模拟栈变动 opcode、移除 `torch`/`numpy` 宽泛放行、标记 `NEWOBJ`/`BUILD` 与 `max_ops` 截断风险；GGUF/PyTorch ZIP 移除静默截断（超限即升风险警告） | `media-reader-worker.py` | 构造 `SETITEM` 栈失同步 Pickle、`torch.hub.load`、第 65 KV GGUF SSTI、第 9 `.pkl` ZIP 均检出 `high` 风险 | 中（1 天） | 维度 6 **+0.6**，维度 2 **+0.3** |
| **P0-5** | **修复 Ghidra 查址/超时、4096-bit RSA 丢明文与大 PCAP 内存钉死**：Ghidra 地址统一标准化、透传 `timeout_ms` 并暴露 stderr；RSA 明文优先保留不被截断、`rsaKnownD` 放宽位宽；PCAP 流式存储 `Buffer.from(bytes)` 拷贝并补 SHB 长度校验 | `sandbox-runner.js`, `offline-calculation.js`, `pcap-stream.js` | Ghidra `list`→反编译端到端命中；4096-bit RSA 返回完整 `plaintext`；500 MB PCAP RSS 峰值 < 120 MB | 中（1 天） | 维度 2 **+0.6**，维度 5 **+0.3** |

---

### P1：显著拉高实战胜率与工程上限的高价值补强

| 编号 | 改造目标 | 涉及文件 | 验收标准 | 改动成本 | 预期提分 |
|---|---|---|---|---|---|
| **P1-1** | **加固多代理图谱与 Windows CAS**：引入单调 `lease_id` Fencing + UUID worker 槽位；Windows `EPERM`/`EBUSY` 纳入指数退避+抖动重试；新增 `archive_done` / 突破 500 上限；补发 `fs/observed`；`ctf-progress` 报错统一走 `ToolError` | `ctf-graph.js`, `ctf-status.js`, `ctf-progress.js`, `tool-errors.js` | Windows 真实磁盘 5 并发压测 200 次抢题 0 假报错；旧租约提交返回 `conflict`；支持 100 题归档不触顶 | 中（1.5 天） | 维度 4 **+0.9**，维度 1 **+0.4** |
| **P1-2** | **打通线下内网赛与大场平台适配**：`platform-request.js` 支持 `allowInsecurePlatformTls`（自签证书）与受控同源跳转、去掉无体 `Content-Type`；`ctf-arena.js` 支持分页拉题；`submission.js` 仅在 2xx/明确拒答时判 `rejected`，网络错不锁死重试 | `platform-request.js`, `ctf-arena.js`, `submission.js` | 本地自签 HTTPS CTFd/GZCTF + 80 题分页 + 429 限流恢复测试全绿 | 中（1 天） | 维度 4 **+0.6**，维度 7 **+0.3** |
| **P1-3** | **修复配置热重载与跨平台兼容**：`resolvePython()` 先调 `settings()`；调整配置合并优先级让热重载生效；`sandbox-runner` 自动检测/告警 `.sh` CRLF 并改用临时文件传 `DECOMPILE_SCRIPT`；修复 `gdb_driver` Windows `args` 路径 | `workbench-config.js`, `sandbox-runner.js`, `extra-tools.js` | 运行中修改 `ctf-workbench.json` `pythonPath` 立即生效；CRLF 脚本可在 Linux 沙箱直接执行 | 小（0.5 天） | 维度 7 **+0.7** |
| **P1-4** | **补强逆向/Pwn/取证核心短板**：`elf.js` 补 `PT_DYNAMIC` 回退与 `__stack_chk_fail_local`；PNG CRC 错降级为 warning 不中止解析；EXIF 支持 `UserComment`/容错；`gdb_driver` 支持 `gdb-multiarch` 与安全只读堆检命令；`pwn_cyclic` 升回 Core Tier | `elf.js`, `image-metadata.js`, `exif.js`, `ctf-tools.js` | 无节头 ELF 与改高度坏 CRC PNG 均可正常产出完整结构报告 | 中（1.5 天） | 维度 2 **+0.6** |
| **P1-5** | **反作弊测试补齐与 Dockerfile 工业化**：为 10 个 0% 覆盖 JS 模块与 Python worker 补真实单测/pytest；Docker 改非 root `USER` + `--memory-swap` + 镜像源 ARG + 移除 `r2ghidra` 静默吞错 + 校验下载 SHA-256 | `docker/Dockerfile`, `docker/Dockerfile.heavy`, `test/*.test.js` | 0% func 模块清零；新增 Python worker 测试套件；Docker 以非 root 运行且支持国内全链路镜像源 | 大（2 天） | 维度 5 **+1.0**，维度 7 **+0.6** |

---

### P2：长期演进与体验打磨

| 编号 | 改造目标 | 涉及文件 | 验收标准 | 改动成本 | 预期提分 |
|---|---|---|---|---|---|
| **P2-1** | **拆解 God Object 与瘦身上下文**：按领域拆分 `ctf-tools.js`（131 KB）与 `extra-tools.js`（90 KB）；压缩 `calculate_offline`/`ctf_progress`/`ctf_graph` Schema 与 `SKILL.md`（目标 Core Schema < 20 KB、`SKILL.md` < 12 KB） | `ctf-tools.js`, `extra-tools.js`, `SKILL.md` | 单文件 < 600 行；首轮上下文开销下降 40%+ | 大（2–3 天） | 维度 1 **+0.6**，维度 3 **+0.8** |
| **P2-2** | **高级协议与密码/取证扩展**：PCAP 支持 IPv6/非 TXT DNS/TLS Keylog；`http_request` 支持原始报文/并发竞态发包；`crypto-toolbox` 增加 Flask 伪造与 LCG 幂模数修复；`rev-disasm-worker.py` 补 UTF-16LE 与 PE 导入表 | `pcap-stream.js`, `http-client.js`, `crypto-toolbox.js`, `rev-disasm-worker.py` | 通过对应高级 CTF 样本端到端测试 | 大（3 天） | 维度 2 **+0.5** |

> **预期路线图收益**：完成全部 **P0** 后加权总分预计由 **7.05 → ~7.8**（消除所有安全与实战硬翻车点）；完成 **P0 + P1** 后预计达到 **~8.5 / 10**（真正进入强赛主力级水准）。
