# CTF 模式

为 DeepSeek Harness 新增可手动选择的 **CTF** 模式。支持本地文本、归档、图片、音频、抓包和二进制分析。工具返回原件位置、SHA-256 或可复核的结果编号。

在 DSH 的 **插件 → 添加插件** 中选择 `ctf-preset` 目录。包内自带技能文件 `SKILL.md`，安装后复制到 `<DSH_HOME>/skills/ctf/SKILL.md`，或放到题目工作区的 `.dsh/skills/ctf/SKILL.md`。

安装自检：

- DSH 版本满足 `engines.dsh`（当前 `>=0.2.2-rc.5 <0.3.0`）；Windows 用 `pwsh`，Linux/macOS 用 `bash`。
- 需要读 7z/RAR、bzip2/xz、Flask 路由或 `rev_query` 时，确认 Python 3.11 或更新版本可用；可在 `~/.dsh/ctf-workbench.json` 指定 `pythonPath`。
- 7z/RAR 还需要本机 `libarchive` 动态库（Windows 默认尝试系统自带的 `archiveint.dll`，其他平台尝试系统 `libarchive`，也可配置 `libarchivePath`）；`rev_query` 的反汇编与控制流分析需要 Python `capstone`，缺失时 strings 仍可用。
- 扩展工具需要本机 Chrome 或 Edge（`browser_session`）、PATH 上的 `gdb`（`gdb_driver`）、`jadx`/`apktool` 与 `apksigner`/`jarsigner`（`mobile_apk` 的反编译与签名）；可用 `browserPath`、`gdbPath` 指定路径。`crypto_solver` 的模板需要 Python 的 z3/fpylll/pycryptodome，缺失时 `check` 会逐项报告。
- 可选 `dsh-ops` 提供 `ops_bash`；本 preset 不依赖它，原生 shell 已覆盖命令执行。

本 preset 已声明平台自带的 shell：Windows 使用 `pwsh`，Linux/macOS 使用 `bash`，无需额外安装 shell 插件；宿主另行安装 `dsh-ops` 时还会提供 `ops_bash`。

新建空白会话，选择 **CTF**，并将工作目录指向题目目录。给出题面、附件相对路径和需要验证的问题。默认在对话中给出结果。需要留档时，可以要求整理 `notes.md` 和 `writeup.md`。

附件优先使用题目目录内的相对路径。工作区外附件须位于用户配置的 `attachmentImportRoots` 内，并由可写会话导入。导入和下载按块校验 SHA-256，在 `.ctf-attachments/manifest.jsonl` 登记来源与结果。

工具调用失败时返回 `ok: false` 和 `error: { kind, message, hint }`。`kind` 为 `path`、`missing`、`size`、`encoding`、`dependency`、`network`、`timeout`、`conflict`、`abort`、`permission`、`unsupported` 或 `other`，`hint` 给出修正方向；按提示改参数或换等效工具，不要原样重试。

## 快速开始

三步装好：

1. 在 DSH **插件 → 添加插件** 选择本目录，重启 DSH，新建会话选 **CTF**，工作目录指向题目目录。
2. 把 `SKILL.md` 复制到 `<DSH_HOME>/skills/ctf/SKILL.md`（或题目工作区 `.dsh/skills/ctf/`）。
3. 在会话里跑一次 `ctf_doctor`（`{"action":"check"}`），缺失项照返回的 `pip install …`、`skill_sync` 或路径提示补齐。

端到端示例：把附件放进题目目录（或用 `fetch_attachment` / `ctf_arena` 下载）→ `inspect_attachment` / `read_binary_range` / `ctf_sandbox` 收集证据 → `ctf_progress check` 或 `ctf_graph` 复核并记录 `result_id` → `ctf_progress save` 落盘 → 需要提交时 `check_flag` 再 `submit_flag` / `ctf_arena(submit)` → `ctf_progress writeup` 生成 `writeup.md`。

## 任务索引

| 我要… | 用哪个 |
|---|---|
| 赛题平台拉题/同步图谱/下附件/提 Flag（CTFd/GZCTF） | `ctf_arena` |
| 共享事实-意图图谱与多代理并行分派 | `ctf_graph`（`.ctf-graph/` + `BOARD.md` + `dispatch_plan`） |
| Linux 安全兵器库 / 反编译 / Pwn 侦察 | `ctf_sandbox`（Docker 优先；要求隔离的任务不会静默回退到 WSL2） |
| 看字节、strings、翻页 | `read_binary_range` |
| 在未知附件中定位格式签名或指定字节 | `scan_binary` |
| 识别附件结构、归档目录 | `inspect_attachment`、`read_archive_member` |
| 让已读成员或派生字节继续进入分析 | `source_result_id` / `source_result_ids` |
| PDF 页面与内嵌附件 | `inspect_media`（`kind: pdf`） |
| SQLite / Office / AI 模型与 Pickle 静态体检 | `inspect_media`（`kind: sqlite` / `office` / `model`） |
| 复算编码/密码/哈希/RSA | `calculate_offline` |
| JWT/Flask Session/LCG/MT19937 求解与脚手架 | `crypto_solver`（`solve` / `template` / `check`） |
| 发 HTTP / 连 TCP | `http_request` / `net_session` |
| 真浏览器交互与抓包/控制台 | `browser_session` |
| 本地二进制侦察、反汇编、控制流与调试 | `inspect_elf`、`rev_query`、`gdb_driver` |
| ZIP 口令与 WAV 音频隐写 | `archive_crack`、`stego_audio` |
| 续接、保存、写题解、交接 | `ctf_progress` |
| 心跳、查榜单 | `ctf_status` |
| 自检依赖与沙箱状态 | `ctf_doctor` |
| 下载题目附件 | `fetch_attachment` |
| 提交前校验 / 平台提交 | `check_flag` / `submit_flag` |
| 实例列表、创建、轮换、删除 | `ctf_instance` |
| 扩展取证审计（18 个旧/低频工具，按需开启） | 配置 `enableExtendedAudit: true` 后启用 |


- `read_ctf_files`（扩展审计层）批量读取已知的文本范围。一次传入最多 10 段 `files`，每段包含 `file_path`，也可指定从 1 起算的 `start_line` 和 `line_count`。默认从第 1 行读 64 行，每段最多 160 行。结果附行号、字节偏移及原件 SHA-256。有后续内容时返回 `next_line`。每份 UTF-8 原件限 8 MiB，合计每次返回最多 8 KiB 文本。遇到超长单行，可用返回的字节偏移接 `read_log_range`。
- `inspect_attachment` 返回原件 SHA-256 和分页结构。传 `next_offset` 继续翻页，可用 `expected_sha256` 核对上一页的原件。
  - PNG 给出尺寸、位深、颜色类型和分页的数据块及文本预览，并核对每个数据块的 CRC-32。JPEG 给出帧尺寸、分页的段位置、EXIF 方向和文件中记录的拍摄时间。两种格式都标出结束位置、尾随字节数及检测到的截断位置。 [W3C PNG 规范](https://www.w3.org/TR/png/) [CIPA Exif 规范](https://www.cipa.jp/e/std/std-sec.html)
  - 7z、RAR4 和 RAR5 支持单卷目录检查。返回成员名、类型、原始大小和加密状态。目录头加密时报告 `encrypted_headers`。此功能使用本机 Python 和 libarchive，从内存读取原件。PNG、JPEG、7z 和 RAR 原件限 32 MiB。 [libarchive 内存读取接口](https://github.com/libarchive/libarchive/wiki/LibarchiveIO) [RAR5 格式说明](https://www.rarlab.com/technote.htm)
  - 单卷 ZIP 和 ZIP64 的原件可超过 32 MiB，中央目录限 32 MiB。首次核对后按需读取当前页的目录条目。
  - ZIP 末尾可有最多 1 MiB 的附加字节。返回 `trailing_offset` 和 `trailing_size`，可接 `read_binary_range` 查看原件片段。MZ 前缀内的 ZIP 目录也可检查，并给出 `archive_offset`。其他前缀可向 `inspect_attachment` 和 `read_archive_member` 传 `format_hint: zip`。
  - zlib、bzip2 和 XZ 流可自动识别。Raw Deflate 没有固定头部，按来源证据确认格式后传 `format_hint: deflate_raw`。这些格式解出的内容可作为单成员读取，也可继续检查为 TAR；原件和解压后总量各限 32 MiB，单文件成员限 1 MiB。bzip2/XZ 解压使用 Python 标准库。
  - ELF、PE32、PE32+、WebAssembly core module 版本 1、TAR、TAR.GZ、PCAP 和 PCAPNG 的原件限 32 MiB。TAR 支持 USTAR、PAX 和常见 GNU 长文件名。只带一个全零结束块的归档仍可列出和读取成员，并返回警告及尾随区坐标。压缩 TAR 展开后限 32 MiB，成员偏移以展开后的 TAR 为准。
  - 捕获文件支持 PCAP 2.4 和 PCAPNG 1.0/1.2。报告包含包数、捕获长度和记录偏移等结构元数据。
  - PCAPNG 可用 `section_index`、`interface_id`、`start_utc` 和 `end_utc` 筛选。默认包含起点，传 `end_inclusive: true` 可包含终点。`packet_count` 是筛选后的包数，`file_packet_count` 是原件总数，`count_scope` 标明是否筛选，`excluded_untimed_packets` 单列因无时间戳而被筛除的包。
  - `pcapng.view` 设为 `packets` 时分页显示匹配包的块类型、时间和 `file_offset`。`offset` 和 `next_offset` 是结果页的记录序号。类型 2 是旧式 Packet Block，类型 3 是 Simple Packet Block。时间按对应接口的精度和偏移换算。 [IETF PCAPNG 草案](https://datatracker.ietf.org/doc/html/draft-ietf-opsawg-pcapng-06#section-4.4) [旧式 Packet Block](https://datatracker.ietf.org/doc/html/draft-ietf-opsawg-pcapng-06#appendix-A)
- `read_png_pixels` 支持灰度、索引色和多通道 PNG。非交错 16 位 RGB、RGBA 和灰度加 Alpha 可读取原始数值，展开样本限 32 MiB。APNG 可用 `frame_index` 选帧，`frame_semantics` 区分默认图和合成 RGBA 帧。每页最多 128 个像素，用 `region` 选区，用 `next_pixel_offset` 和原件 SHA-256 续读。 [Pillow 格式说明](https://pillow.readthedocs.io/en/stable/handbook/image-file-formats.html#png)
  - `operation: lsb` 按行、按所选通道的顺序提取位。默认 `bit_index: 0`、`bit_order: msb_first`，每页最多 8192 个像素。每页独立打包为 Hex，最后一个不满的字节补零，`bit_count` 和 `padding_bits` 标出边界。
  - `operation: bitstream` 把整张图或 `region` 内选定通道展平成连续位流，每页最多 32768 位。以 `next_bit_offset` 续读，页边界按整字节对齐，不插入页内填充。把一页或连续页的 `result_id` 传给 `inspect_media kind: qr`，可直接尝试把隐藏字节当作下一张二维码图读取。
- `inspect_media` 检查不超过 32 MiB 的本地原件。用 `kind: pdf` 查看 PDF 元数据、加密状态、页数和页尺寸。`include_text: true` 返回内嵌文本预览，每页最多 2048 字符。`next_page_offset` 用于继续翻页。依赖工作台 Python 的 PyMuPDF。 [PyMuPDF 文档](https://pymupdf.readthedocs.io/en/2.0/document.html)
  - PDF 的 `pdf_action: render_page` 按 `page_offset` 渲染单页 PNG（最多 4096 单边像素、4 MP、12 MiB），`list_attachments` 列出最多 64 个嵌入附件，`read_attachment` 读取指定附件（最多 1 MiB）。渲染图和附件作为当前会话的派生字节缓存，可用返回的 `result_id` 接着做图像、二维码、归档或二进制检查。
  - `kind: image` 检查 PNG、JPEG、GIF、BMP、TIFF 和 WebP 的选定帧尺寸、模式、帧数和可用时长，依赖 Pillow。`inspect_attachment` 的 JPEG 和 PNG EXIF 报告含相机、曝光和可用 GPS 标签及原件偏移。
  - `kind: qr` 用 Pillow、OpenCV 和 NumPy 读取 PNG/JPEG 的二维码。返回检测位置和最多 8 条已解码内容。读取器能返回字节时会给出十六进制和内容 SHA-256。二维码内的链接作为文本返回。 [OpenCV 二维码读取器](https://docs.opencv.org/4.x/de/dc3/classcv_1_1QRCodeDetector.html)
  - `kind: audio` 读取 RIFF/RIFX WAV 头和 INFO 标签、原生 FLAC STREAMINFO 和 Vorbis 注释、ID3v1 和常规 ID3v2.3/2.4 文字帧，无需额外软件。WAV 的 PCM 和 FLAC 可在样本数已知时给出时长。 [FLAC 元数据规范](https://www.rfc-editor.org/rfc/rfc9639.html#section-8)
  - `kind: sqlite` 只读列出 SQLite 表或运行单条 SELECT / WITH 查询，默认每页 25 行、最多 100 行；写入、PRAGMA、ATTACH 和扩展加载会被拒绝。数据库在内存中打开，不落盘。
  - `kind: office` 从 DOCX、XLSX、PPTX、ODT、ODS 和 ODP 的 ZIP/XML 部件提取段落或单元格预览，不执行宏。可传 `office_part` 指定部件。旧式 `.doc` / `.xls` 暂不支持。
  - `kind: model` 零执行静态体检 AI 模型与序列化文件（纯 Python 标准库）：支持 **Pickle**（`pickletools` 栈跟踪 `GLOBAL`/`STACK_GLOBAL`/`REDUCE` 与危险模块、尾随字节）、**PyTorch ZIP**（扫描 `.pkl` 与 TorchScript `.py`）、**Safetensors**（`__metadata__`、张量表与尾部附加字节）、**GGUF**（版本、KV 元数据与可疑模板）和 **ONNX**（IR 版本、自定义域与外部路径穿越）。ONNX GraphProto 节点尚未遍历，因此结果会标记 `status: incomplete` 且风险至少为中；同样支持从 `read_archive_member` 经 `source_result_id` 链式检查。
  - `file_path` 可换成前一步的 `source_result_id`。可接 `read_archive_member`、PDF 派生结果、音频 LSB 或 PNG 位流；`source_result_ids` 只用于按顺序拼接同图像、同区域、同通道且偏移连续的 `bitstream` 页。派生结果保留输入 SHA-256 和来源位置。缓存限当前会话，DSH 重载后需重新读取来源。
  - PNG 和二维码图像限单边 16384、总像素 16777216。依赖缺失时返回 `dependency_missing`、缺失组件和原件 SHA-256。
- `read_log_range`（扩展审计层）按 `byte_offset` 读取 UTF-8 日志或文本，`byte_length` 可传 1 至 4096。工具会向外对齐完整字符，返回实际范围和 `next_byte_offset`。读取下一段时，可将上一段的 SHA-256 填入 `expected_sha256`，核对原件是否变化。
- `read_binary_range` 直接按原件字节偏移读取普通文件，每段最多 4 KiB。默认从偏移 0 读 256 字节，返回 Hex/ASCII 对照、`range_sha256` 和 `next_byte_offset`。可选 `hex`、`base64`、`utf8` 或 `auto`。传 `strings: true` 可提取段内最多 32 条可打印 ASCII 字符串及其原件偏移，`min_string_length` 默认为 4。超过 128 MiB 的文件默认只散列选中片段，可用 `hash_scope: file` 获取原件 SHA-256，或用 `range` 只读片段。核对原件哈希可传 `expected_sha256`。
- `scan_binary` 从 `byte_offset` 开始分块定位已知字节。默认 `mode: signatures` 搜索 ZIP、PNG、PDF、ELF 等常见格式签名，也可用 `mode: hex` 或 `utf8` 搜索 `pattern`。每页默认检查 32 MiB 的起点范围，最多 64 MiB 和 48 个命中，支持跨块匹配。每个命中带原件位置和片段 SHA-256。继续搜索时保留原查询参数并将 `next_byte_offset` 填入 `byte_offset`。启用 `hash_scope: file` 可获得原件 SHA-256，后续用 `expected_sha256` 核对。签名是候选，接 `inspect_attachment` 确认结构或用 `read_binary_range` 核对字节。
- `read_archive_member` 接收归档目录的 `member_index`，按原件 SHA-256 核对。ZIP/ZIP64 成员解压后限 32 MiB；大于 1 MiB 时 `result_id` 仅引用当前页。TAR 和压缩的单文件成员限 1 MiB。ZIP 可用 `password` 提供一个已知口令读取单个成员，原件限 32 MiB。单文件 gzip、zlib、bzip2、XZ 和 Raw Deflate 用 `member_index: 0`。页内字节与完整成员各有独立 SHA-256。
  - 典型链路：`read_archive_member.result_id` → `read_png_pixels(source_result_id=...)` → `operation: bitstream` 按 `next_bit_offset` 续页 → `inspect_media(kind: qr, source_result_ids=[...])`。最后一步按页序拼接并验证字节哈希，不需要复制 Hex 或临时文件。
  - 内嵌 ZIP 的起点和长度已知时，给 `inspect_attachment` 同时传 `archive_offset` 和 `archive_length`。取得成员编号后，给 `read_archive_member` 传同一区间和 `member_index`。返回的 `archive_range` 是原件区间，成员内容的 `byte_offset` 从解压后的成员起算。已知口令读取对所选 ZIP 区间应用 32 MiB 上限。扫描和指定 ZIP 区间依赖 DSH 的分段读取能力。
  - 边界未知时，用 `scan_binary` 找 `zip` 和 `zip_end` 候选。读取 `zip_end` 起点的 22 字节，取最后两字节的小端注释长度。用结束记录偏移、22 字节固定长度和注释长度算出末端，再由目录检查核实所选范围。
  - 同一会话可把签名扫描的 `result_id` 作为 `inspect_attachment.scan_result_id`，同时传原来的 `file_path`。工具检查普通单卷 ZIP 候选的结束记录、目录和首个成员头，逐项返回 `confirmed`、`rejected` 或 `insufficient`。通过的 `archive_range` 可直接用于读取成员。ZIP64 和无成员的结束记录仍用已知区间确认。候选检查每页最多读取 32 MiB 的结构数据，另按现有规则核对原件哈希。
  - ZIP 的加密标记与实际未加密字节不一致时，读取要同时通过长度、解压及 CRC-32 检查，结果以 `encryption_flag_only` 标记。目录优先读取 UTF-8 和校验过的 Unicode 路径，对符合特征的传统中文名尝试 GB18030 并标明推断。归档成员名预览最多 1,024 字符。
- ZIP/ZIP64 支持未加密的 Store 和 Deflate，成员压缩数据限 32 MiB。DOCX、XLSX 和 APK 可按 ZIP 目录读取。TAR、TAR.GZ、gzip、zlib、bzip2、XZ、指定格式的 Raw Deflate、7z、RAR4 和 RAR5 的原件限 32 MiB。压缩 TAR 展开后的整个内容另限 32 MiB。
- ZIP 和日志首次读取时分块计算原件 SHA-256。同一版本的后续读取可复用校验结果。`hash_reused` 表示是否复用，`bytes_read` 记录本次读取的字节数。
- `inspect_elf` 给出 ELF 文件头、入口、符号表状态和 SHA-256。`security` 按 checksec 口径报告 NX、PIE、RELRO、canary、FORTIFY，并列出动态导入（最多 96 个）、危险导入、`DT_NEEDED` 库和 x86-64 常见 gadget 的字节扫描结果（只扫可执行 `PT_LOAD` 段前 8 MiB，不是反汇编，可能有数据误报；剥离符号时 canary 可能为 `null`）。`security` 依赖节头：节头被移除时只能确认 NX、PIE 和保守的 RELRO，导入可能为 0、canary 可能为 `null`。x86-64 额外返回 `pwn`：`relocations`（JUMP_SLOT/GLOB_DAT/ABS64/COPY，最多 24 条）、`plt`（符号、GOT 槽和 PLT stub 地址，优先带 `endbr64` 的 `.plt.sec`）、`exports`（`system`、`execve`、`environ` 等 libc 符号地址，最多 24 个，共享库中即偏移）和 `strings.bin_sh`（`/bin/sh` 的虚拟地址与文件偏移）。对匹配的 x86-64 glibc 启动形式，工具也核对入口传参、重定位和 `main` 地址。
- `pwn_cyclic`（扩展审计层）生成或查找 pwntools 兼容的 De Bruijn 循环模式（阶 4、字母表 a–z）。`create` 返回最多 4096 字符的前缀；`find` 接受十六进制字节串（如 `6c616161`），或 `0x` 开头的整数按 `byte_order`（默认小端）转换，返回 0 起始偏移、出现次数和是否歧义。用于栈溢出 offset、泄露值定位。
- `pwn_payload`（扩展审计层）的 `libc_base` / `pie_base` 用一个地址泄漏和相应 ELF 符号偏移计算基址，可附目标符号偏移生成运行时地址。`ret2libc_x64` 用溢出偏移、`pop rdi; ret`、`/bin/sh` 与 `system` 地址组装最多 16 KiB 的小端 payload，可选插入对齐 `ret` 和返回到 `exit`。只排布给定地址，不验证映像版本、偏移、gadget、远程交互或栈对齐。
- `net_session` 管理最多 8 个 TCP 会话，操作是 `connect`、`send`、`recv`、`read_until`、`close`、`list`。`send` 单次限 1 MiB；`recv` 默认 2000 ms、最多 64 KiB，文本安全时返回 UTF-8，否则返回 Hex 和 hexdump；`read_until` 读取到分隔符或 64 KiB 上限。会话空闲 10 分钟后在下一次调用时清理，取消操作会关闭对应 socket。用于 pwn 远程交互和自定义 TCP 协议。
- `http_request` 返回状态码、完整赛题响应头（保留 `Set-Cookie`/`WWW-Authenticate` 等赛题头，仅脱敏已配置的平台令牌）、耗时、远程地址和已读正文的 SHA-256。允许自定义 `Host` 头（用于 VHost/Host 头注入等赛题），支持 `cookie_jar` 按名称维持多会话 Cookie（含重定向自动续带）和 `multipart` 表单/工作区文件上传。正文支持 gzip/deflate/br，预览上限 1 MiB。正文读取中断时返回 `body_error`、已收字节和响应元数据。GET/HEAD 无请求体时可跟随同源跳转或同主机 HTTP 到 HTTPS 升级，最多 5 跳；升级需通过目标来源授权并清除原请求自定义头，其余跳转返回 `redirect_blocked`。 [RFC 9110 HTTP 语义](https://www.rfc-editor.org/rfc/rfc9110)
- `pcap_stream` 对整份 PCAP/PCAPNG 重组 IPv4/TCP 字节流，支持 BSD 回环（链路类型 0）和 Linux SLL/SLL2，记录并跳过坏包。文件不超过 64 MiB 时走内存解析；更大文件用分块读取，最多 1 GiB，读取内存不随整份文件增长。可按 IPv4 源/目的、TCP/UDP/DNS、端口和带 `Z` 的 UTC 时间筛选；`capture_scope` 保留全文件包数和筛选条件，`filtered_ipv4_packets` 记录筛除数。`warnings[]` 和 `analysis_status` 标出丢包、截断、流数上限和未完成重组；遇到可跳过的坏包会继续分析并保留告警。PCAPNG 的 EPB、SPB 和旧式 PB 分开计数，SPB 采用当前节第一个接口的快照长度。`sequence_gap` 标记未填补的序列缺口，`reassembly_incomplete` 标记结果不完整。TCP 乱序缓存最多保留 16 MiB，超限时显式标记 `pending_segments_dropped`。HTTP 预览来自连续片段。最多 16 条方向流，每条最多 1 MiB。 [BSD 回环链路格式](https://www.tcpdump.org/linktypes/LINKTYPE_NULL.html)
  - TCP 流的 `first_packet`、`last_packet` 保留捕获记录的文件偏移和 UTC 时间。SPB 等没有时间戳的记录返回 `timestamp_utc: null`。
  - `dns_udp.samples` 返回前 24 条有完整 DNS 头的 UDP 53 样本，附捕获位置、查询名和响应 TXT。解析会保留畸形或截断标记，头部计数仍统计整份抓包。 [DNS 报文格式](https://www.rfc-editor.org/rfc/rfc1035.html#section-4.1)
  - UDP 统计包括 IPv4 数据报数量及端口 53 上可读取的 DNS 报文头数量、查询、响应、截断标志和基础响应码。IPv4 分片及截断包单列，避免将首段当完整报文。
- `browser_session` 在隔离的浏览器配置中查看已授权页面、DOM、标题、Cookie、localStorage/sessionStorage、捕获的网络请求（`network`，传 `request_id` 可读最多 64 KiB 响应体）、控制台日志/JS 异常（`console`）以及自动捕获并放行的弹窗记录（`dialogs`，防止 XSS 弹窗阻塞会话），并支持截图到题目目录。`click`、`fill`、`select`、`press`、`evaluate`（执行页面 JS 表达式）、`set_cookie`（受 `authorize` 来源约束）、`set_headers`（附加自定义请求头）与 `upload_file`（上传工作区内文件到 `<input type="file">`）均须处于可写会话。`press` 支持 Enter、Tab、Escape、方向键、空格、Backspace 和 Delete。`wait_for` 等待动态页面元素，最长 30 秒。填充值最多 16 KiB；存储结果最多 32 项、每值 2 KiB。`cookies` 默认返回赛题 Cookie 值（仅脱敏平台令牌；设 `include_values: false` 可仅列元数据）。`timeout_ms` 覆盖启动与操作；取消、超时和关闭都会清理进程及临时配置目录。
- `ctf_sandbox` 提供跨平台 Linux 安全工具沙箱（`backend: "auto"` 优先 Docker；要求隔离的执行、反编译和 Pwn 侦察在 Docker 不可用时会拒绝运行，不会静默降级到共享宿主权限与网络的 WSL2；仅在明确接受该边界时传 `backend: "wsl"`；内置 30 秒探测缓存，支持 `backend: "auto" | "docker" | "wsl"` 与 `profile: "auto" | "base" | "heavy"` 覆盖；Docker 容器使用 UID 10001 非特权用户，启用 `--cap-drop=ALL`、`--security-opt=no-new-privileges:true`，并把 RAM 与 swap 限额设为相同值）：
  - `status` 探测当前可用后端、双层镜像就绪状态（`profiles.base` / `profiles.heavy`）及内部兵器库二进制与 Python 模块矩阵（只读挂载 `/work:ro`）。
  - `exec` 运行单行命令或工作区相对脚本（`.py`/`.sh`/`.sage`）；`.sh` 会先移除 CRLF 行尾，按 LF 交给 Bash；默认 `profile: "auto"` 自动检测 `angr`/`ghidra`/`jadx`/`apktool`/`sage` 及 `.py` 脚本导入头部，按需自动切入 `dsh-ctf-sandbox:heavy` 并扩容容器内存至 `4g`；Docker 后端默认 `--network=none` 纯离线运行，连远程靶机可传 `network: "bridge"`，动态调试传 `ptrace: true`，仅做只读扫描可传 `read_only_work: true` 挂载 `/work:ro`。
  - `decompile` 默认优先 `r2`/`r2ghidra`（单次 `-A` 分析输出 `pdg`/`pdc` 与 `pdf`/`axt`；基础镜像无 `r2` 且本机有 `heavy` 时自动升级 Ghidra；显式传 `profile: "heavy"` 时优先调用 Ghidra Headless 并默认给足 120 秒超时，按二进制 SHA-256 持久化缓存项目至 `.ctf-cache/ghidra/` 复用，仍保留 `objdump`/PT_LOAD/gdb 兜底）。引擎退出失败或函数级结果为空时返回失败/回退诊断，不会把空反编译报告标成成功。省略 `function` 时列函数表，传入函数名或地址输出伪 C/汇编。
  - `pwn_triage` 一次性采集 `file`、`checksec`、`DT_NEEDED`/解释器、`ROPgadget` 关键 gadget，以及可选（`allow_exec: true`）`seccomp-tools dump`（默认只读挂载 `/work:ro`）。
  - 双层镜像构建（在 `ctf-preset` 目录按需手动执行，建完后无需修改配置即可自动按需切换）：
    - 基础全栈版（版本锁定 `radare2`/`GEF`/`bkcrack`/`ffuf`/`pwninit`，覆盖 ~90% 题型，含 32 位运行库、`qemu-user`/`gdb-multiarch`/`gef`、`radare2`+`r2ghidra`、`pwntools`/`pwninit`/`z3`/`fpylll`/`ROPgadget`/`ropper`/`seccomp-tools`/`one_gadget`/`bkcrack`/`ffuf`/`sqlmap`/`john`/`tesseract-ocr`/`pyinstxtractor-ng`/`zsteg`/`exiftool`/`volatility3`/`wabt`/`sleuthkit`/`cpio`/`pillow`/`numpy`/`scipy`/`scapy`/`xdis`/`php`/`node`）：`docker build -t dsh-ctf-sandbox:latest docker/`。可用 `APT_MIRROR`、`PIP_INDEX_URL`、`GITHUB_BASE_URL`、`GITHUB_RAW_BASE_URL`、`RUBYGEMS_SOURCE_URL` 为包管理器与 GitHub 下载配置镜像；`WITH_R2=0` 可跳过 r2。
    - 重型扩展版（`FROM dsh-ctf-sandbox:latest` 增量叠加，默认含 Ghidra Headless + `angr` + `jadx`/`apktool`，可加 `--build-arg WITH_SAGE=1` 启用 SageMath）：`docker build -f docker/Dockerfile.heavy -t dsh-ctf-sandbox:heavy docker/`；构建完成后 `ctf_sandbox` 默认 `profile: "auto"` 会自动发现并按需启用（亦可通过 `sandboxHeavyImage` 自定义重型镜像名）。heavy 构建也接受 `APT_MIRROR`、`PIP_INDEX_URL` 和 `GITHUB_BASE_URL`。
- `ctf_arena` 原生适配 **CTFd**、**GZCTF** 与通用赛题平台（`platformType: "auto" | "ctfd" | "gzctf" | "generic"`，GZCTF 自动适配 `Cookie: GZCTF_Token=` 认证并可配 `platformGameId`）：支持 `status` / `games` / `challenges` / `detail`（仅从专用连接信息字段授权靶机；题目描述中的 URL 不会自动授权）/ `sync_graph`（幂等导入 `.ctf-graph/`，按分值升序、同分按解出人数 `solves` 降序排优）/ `fetch_files` / `container`（`create`/`delete`/`extend` 容器续期）/ `submit`。`fetch_files` 单次最多下载 8 个附件，超过时返回 `status: "partial"`、`omitted_file_count` 和补充方式。自动探测遇到认证拒绝、网络错误或取消会明确报错；只有正常响应但平台形状不匹配时才继续探测通用 API。动态靶机授权限定在发起会话和工作区，最长保留 30 分钟；删除实例或容器时撤销对应授权。`ctf_arena(container create/extend)` 将记录 `container:<challenge_id>`，动态提交和 `submit_flag` 都只接受账本中 30 分钟内且未删除的实例；调用方传入的 `refreshed_at` 不作为可信证明。
- `ctf_graph` 在工作区 `.ctf-graph/` 维护跨题/跨代理分层 Fact-Intent DAG（`graph.json` + `graph.saved.json` 恢复副本 + 自动投影的 `BOARD.md`）：
  - `board` 返回第一层极简标题索引、按题汇总（`challenges`）、已排除路线（`ruled_out`）与超时预警（`overdue`），支持 `status_filter`（`all|active|open|claimed|done|dead|overdue`）、`limit`/`offset` 分页与 `summary_only` 控制上下文开销；完整列表的 `paging` 同时报告 Facts、Intents 和 `ruled_out` 页数；`BOARD.md` 自动生成总览表与进行中/已结案分区；
  - `expand` 按 `fact_ids`/`intent_ids` 按需展开二/三层摘要与证据；
  - `export_writeup` 只读导出单题或全图谱 Markdown 题解草稿；
  - `add_fact` / `add_intent` 写入确认事实（支持 `dedupe_key` 去重与 `spawn_intents` 派生任务）；
  - `claim_intent` 通过 CAS 乐观锁互斥认领指定 ID 或 `next: true` 最高优任务，超时卡死支持 `steal_overdue: true` 接管；
  - `finish_intent` 仅允许当前已认领者使用认领时的 `lease_id` 原子结案（`done`/`dead`），并写入产出 `facts` 与新 `spawn_intents`；未认领、租约过期或重复结案均会冲突返回；
  - `dispatch_plan` 自动避开进行中题目并按优先级生成多代理分派方案（含 `recommended_prompt` 与 `overdue_recovery` 超时接管清单）。
- `gdb_driver` 对工作区内的二进制做静态检查或受限调试。`action: inspect` 的 `kind` 为 `files`/`sections`；`action: debug` 接受 1–24 条只读白名单命令（支持算术偏移如 `b *main+0x1a`、`x/20gx $rbp-0x40`、`p/x $rax-$rbx`、`p *(void**)$rsp` 及常用缩写 `c`/`ni`/`si`/`n`/`s`/`i r`/`disas`/`fin`），可选 `args` 传命令行参数与 `stdin_file` 重定向输入。在 Windows 宿主遇到 Linux ELF 时，隔离要求会使 `auto` 仅使用 Docker；若 Docker 不可用，明确设置 `sandboxBackend: "wsl"` 才会在共享宿主权限的 WSL2 中运行。路径会按 POSIX shell 规则引用。仍禁用 shell、Python、`source`、写内存赋值与自动加载。
- `archive_crack` 读取 ZIP 中央目录并尝试 ZipCrypto 口令：`passwords`、`wordlist`、`mask`（`?l` `?u` `?d` `?h` `?s` `?a` 与字面字符）和内置弱口令，默认 30 秒；命中后用解压 CRC 复核。AES（method 99）或需要 john/hashcat 的场景会给出替代提示。
- `stego_audio` 解析 WAV（PCM 8/16/24 位）的元数据和 LSB，或用多窗 FFT 生成时频谱 PNG。`start_seconds` / `duration_seconds` 或帧号限定片段，`channels` 选择声道；默认混合全部声道。图的横轴为所选片段时间，纵轴为频率，返回窗长、步长、频率刻度及主要峰值。
- `mobile_apk`（扩展审计层）读取 APK 的清单、dex、ABI、native 库、assets、META-INF 签名文件和 APK Sig Block；`decompile` 优先调本机 jadx/apktool，本机缺失时自动桥接 `ctf_sandbox`（优先 `heavy` 镜像）；`signature` 调 apksigner/jarsigner。
- 云环境取证需把脱敏后的日志或配置作为附件放入题目目录，再用文本和证据工具检查。`cloud_metadata`（扩展审计层）仅保留兼容入口，实际探测已关闭。
- `crypto_solver` 支持 `check`（探测 Python 密码库）、`template`（生成 7 个零占位可运行脚手架到 `.ctf-templates/`：`z3_bitvec`/`coppersmith`/`lattice`/`aes_mode`/`ecc_weak`/`padding_oracle`/`hash_ext`）以及 `solve`（零依赖纯 Node.js 即用求解：`jwt_inspect`、`jwt_crack`、`flask_session`、`lcg_recover`、`mt19937_recover`）。
- `verify_elf`（扩展审计层）重新读取原文件，核验指定的入口、`main`、动态符号偏移标注或 SHA-256。
- `rev_query` 用本机 Python 3.11+ 支持 **ELF32 / ELF64**（x86、x86-64、ARM、AArch64、RISC-V）与 **PE32 / PE32+**（x86、x86-64、AArch64）：`triage` 无需 `capstone` 即可快检格式、节表、加壳/编译器（UPX/PyInstaller/Go/Rust/.NET/GCC/Clang/MSVC）与密码常量（AES S-box、SHA-256、MD5、ChaCha20、TEA delta、CRC32、自定义 Base64 表）；`cfg` 支持 x86-64/x86/AArch64 ELF 函数控制流；`disassemble` 返回 20–400 条线性指令；`strings` 扫描可见字符串。文件限 64 MiB。
- `verify_evidence`（扩展审计层）对照 2 至 8 个证据位置，适合核验源码声明、配置和日志里的同一字段。选定普通 UTF-8 文本文件和目标值前的原样 `prefix`，可用 1 起始的 `line` 消歧，或指定值后的 `suffix`。省略后缀时取到行尾。也可以直接传 `{ "result_id": "..." }` 引用 `read_binary_range`、`read_log_range` 等结果的记录位置，工具按记录的偏移和 SHA-256 复核，不必重写前缀。工具按原样比较值，返回一致、冲突或证据不足，并记录原件 SHA-256、行号、从 0 起算的字节偏移和长度。每个文件限 32 MiB。
  - 可直接传 `file_path`、`byte_offset`、`byte_length` 和原件 `sha256`，也可附片段 `range_sha256`。同时传 `result_id` 时，用这组字段在编号过期后复算原件。`used_fallback` 标记使用了补充范围，`recomputed` 标记范围已通过原件校验。
- `verify_http_evidence`（扩展审计层）用 `request.method`、`request.path` 和可选 `request.request_id` 核对 1 至 6 份已有的本地 HTTP 记录。方法、路径大小写及百分号编码按原样匹配，查询串从记录中去除。按方法和路径比较时，结论适用于同一路由的记录。关联同一个请求优先使用记录中的请求 ID。找到多条、格式不完整或拿不到 HTTP 状态时，报告证据不足。
  - `har` 读取 `log.entries`，用 `X-Request-ID` 关联已有记录。返回状态码、文件中的 JSON 字段路径与 SHA-256。响应头只汇总媒体类型和 `Location`、`Set-Cookie` 的记录情况。输出保留所选方法和路径、定位信息及有限元数据。 [Chrome DevTools 的 HAR 导出](https://developer.chrome.com/docs/devtools/network/reference#save-all-network-requests-to-a-har-file)
  - `access_jsonl` 每行使用 `method`、`path`、`status`，可附 `request_id` 和带时区的 `timestamp`。接受三位数字或同样的数字字符串作为状态码。`expectations_jsonl` 使用同样的字段来记下预期状态，例如 `{"method":"GET","path":"/ready","status":200}`。文本报告附原件行号、字节范围和 SHA-256。
  - `access_combined` 读取常见 Common/Combined 访问日志，按方法和路径核对。每份原件须为 UTF-8，最多 8 MiB 和 50,000 行或条目。 [Nginx 的访问日志格式](https://nginx.org/en/docs/http/ngx_http_log_module.html#log_format)
- `trace_flask_route`（扩展审计层）把一条已知的方法和路径定位到本地 Flask 源码。传 `entry_file`、`request` 和相关的 `source_files`。源码位于当前工作目录的子目录时传 `source_root`，其余 Python 路径相对源码根，报告中的引用使用相对工作目录的完整路径。`entrypoint` 默认使用 `app`，应用工厂可传 `create_app` 等实际函数名。工具从入口沿静态导入查找给定文件中的注册声明。读取本机 Python 3.11+ 的语法树，每次最多 8 个 UTF-8 Python 文件，每个最多 256 KiB。
  - 支持固定路径和参数化路径的路由装饰器、`add_url_rule`、普通应用入口、直接返回应用的工厂、局部导入别名和多级蓝图挂载。例如用实际路径 `/jobs/42` 查询声明 `/jobs/<int:job_id>`。工具报告匹配规则及转换器，命中多条时列出可定位的候选。 [Flask 蓝图文档](https://flask.palletsprojects.com/en/stable/blueprints/)
  - 每个路径段可带一个变量及固定前后缀。支持无附加参数的默认字符串、`string`、`int`、`float`、`uuid`、`path`，每条规则最多使用一个跨段 `path`。参数化的蓝图前缀随路由一同核对。转换器带选项、检测到自定义覆盖、遇到条件挂载或缺少模块时，返回待核对位置。核对采用给定的路径文本。 [Werkzeug 内置转换器](https://werkzeug.palletsprojects.com/en/stable/routing/#built-in-converters)
  - `status_sites` 列出可静态识别的状态码及源码行。URL 路径按 UTF-8 百分号解码，回显 `decoded_path`。隐式 HEAD、自动 OPTIONS 和默认严格尾斜杠的跳转在 `framework_response` 中报告。需要留档时可用 `ctf_progress` 核对相应字段。 [Werkzeug 路由](https://werkzeug.palletsprojects.com/en/stable/routing/)
  - `trace.response_hooks` 单独列出适用于当前路由的应用级和蓝图级 `after_request` / `after_app_request`。实际记录的 `response_returned` 可以核对钩子的静态返回点。动态响应处理仍标记待复核。 [Flask 响应钩子](https://flask.palletsprojects.com/en/stable/api/#flask.Flask.after_request)
- `verify_flask_response`（扩展审计层）核对已有的应用返回事件。传入同一会话和目录下 `verify_http_evidence` 的 `http_result_id`、实际响应的 `observation_index`（从 0 起算）、`trace_flask_route` 的 `trace_result_id` 和事件日志 `file_path`。HTTP 观测需按已知的请求 ID 唯一定位。事件日志使用 UTF-8 JSONL，沿用每份 8 MiB 和 50,000 行上限。
  - 静态依赖图之外的语法错误单列为 `unrelated_source_issues`。如果唯一匹配的路由只有响应钩子或错误处理器待复核，可用明确的 `response_returned` 事件对照。报告仍会标记 `response_processing_unverified`，表示响应处理过程需要复核。
  - 对记录中的 `response_returned`，工具核对请求 ID、方法、路径、状态码和源码位置。`source.file_path` 相对源码根目录，`source.line` 从 1 起算，`source.sha256` 可附记录时的源码哈希。没有记录哈希时，关联依据为已记录的文件位置与本次读取的源码。源文件或 HTTP 原件变化后，工具会要求重新核对。
  - 同一请求只有入口记录时，保留源码中的状态码候选。有效返回事件指向一处时保留 HTTP、事件行和源码行三方引用。出现多处时报告歧义。可将 `/origin/source/line` 等字段交给 `ctf_progress` 核对并留档。

```json
{"request_id":"example-42","method":"GET","path":"/jobs/42","event":"response_returned","status":503,"source":{"file_path":"jobs.py","line":17}}
```

- `calculate_offline` 一次复算最多 12 步。工具在独立线程执行，整批限 5 秒，最多同时运行两批。取消或超时会清理计算线程。整数运算使用十进制字符串，支持加、减、乘、整除、取模和模幂。整除朝零截断，取模要求正模数并返回非负余数。模幂的指数和模数各限 4096 位二进制。除整数/字运算外，还支持哈希、编码、XOR、古典密码、AES、RSA 原始运算和 RSA 攻击。
  - `convert_base` 通过 `from_base` 和 `to_base` 指定 2 至 36 的进制，结果使用小写数字字符。
  - `convert_encoding` 可转换 UTF-8、Hex、Base64 和 Base64URL。Base64 输入支持换行及 ASCII 空白，仍核对所选字母表与末尾位。
  - 输入可用 `{"step":1}` 引用前序完整值，`expected` 按完整值比较。普通计算的长结果可在 65,536 字符内翻页，每页最多 4,096 字符。结果附完整 SHA-256 和 `next_result_offset`，下一次传到该步骤的 `result_offset`。
  - `lcg_replay` 复算已知种子的线性同余序列。`inputs` 依次给出种子、乘数、增量、模数，均为十进制字符串。下标 0 是初始状态，`start_index` 默认 1，`count` 默认 1，最多返回 32 个状态。返回值为十进制字符串数组的 JSON 文本。
  - 确定性复算可指定 `candidates`，例如 `[{"label":"参数 A","checkpoints":[1,3]}]`。检查点须指向带 `expected` 的递增步骤号。每个候选单独报告 `match`、`mismatch` 或 `incomplete`，并定位首个不符或无法验证的步骤。
  - 确定性复算超时后，`completed_steps` 和 `next_step` 表示进度。若已得到检查点，把返回的 `resume_id` 与原来的 `steps`、`candidates` 一起传回同一会话。编号在内存中保留最多 15 分钟，引用附件时仍会重验原件。续算从步骤边界开始，耗时超过 5 秒的单步需要拆分。
  - 编码、解码、编码转换、哈希和 `bytes_to_integer` 可用 `{"result_id":"..."}` 引用 `read_binary_range` 或 `read_archive_member` 的结果。同批整数运算通过 `{"step":1}` 接前序结果。计算会复核原件并重新读完整片段或成员，`input_evidence` 保留原件及输入数据的哈希和位置。每批引用的原始数据合计最多 2 MiB。引用结果必须带原件哈希；已加密成员使用本地已解密资料，引用本身不保存口令。
  - `bytes_to_integer` 与 `integer_to_bytes` 处理 1–1024 字节的无符号值，须指定 `byte_order` 为 `big` 或 `little`。字节编码默认 Hex，也可用 `base64` 或 `base64url`，分别通过 `from_encoding` 或 `to_encoding` 指定。直接引用附件时也可通过引用内的 `encoding` 指定。转回字节时把原长填入 `byte_length` 即可补回高位零，省略时使用最短表示。
  - `modular_inverse` 依次输入值和模数，返回十进制逆元、`gcd` 与乘积的余数 `product_remainder`。不存在逆元时返回实际 `gcd`。 `check_congruence` 依次输入左值、右值和正模数，返回字符串 `"true"` 或 `"false"` 及两边余数。
  - `word_` 运算支持 8、16、32、64 位。可用带 `0x` 的十六进制或十进制字符串。`word_xor`、`word_and`、`word_or`、`word_not`、`word_add`、`word_subtract`、`word_multiply` 按字宽截断。`word_shl`、`word_lshr`、`word_ashr`、`word_rol`、`word_ror` 的第二个输入是次数。旋转按字宽取模，超过字宽的移位按补位规则处理。
  - `word_sign_extend` 用 `from_width` 和 `width` 指定原字宽与目标字宽。`word_truncate` 按目标字宽保留低位，`word_as_signed` 给出有符号十进制值。`word_from_bytes` 和 `word_to_bytes` 使用 `byte_order` 的 `little` 或 `big`，Hex 字节串须与字宽一致。整数结果可继续传给下一步，样例首次不符的步骤记录在 `first_mismatch`。
  - `hash` 支持 `md5`、`sha1`、`sha256`、`sha512`，输入可用 `utf8`、`hex`、`base64`、`base64url`，输出可用 `hex`、`base64`、`base64url`。`hmac` 的第二个输入是密钥，密钥编码用 `key_encoding` 指定 `utf8` 或 `hex`。
  - `encode`/`decode` 支持 `base32`、`base58`、RFC1924 字母表的 `base85`、`ascii85`、`z85`、`base91`、`url`、`form`、`html` 和 `html_bytes`。ASCII85 编码输出不带外框，解码也接受 Adobe `<~ ~>` 外框和 `z` 零组缩写；Z85 要求输入字节数是 4 的倍数、编码字符数是 5 的倍数；basE91 解码忽略 ASCII 空白。
  - `xor` 用 `key` 和 `key_encoding` 指定单字节或多字节重复密钥；`xor_bruteforce` 尝试单字节密钥，`xor_repeating_bruteforce` 按归一化汉明距离筛选密钥长度，再逐列按英文频率选字节。两者都返回带评分的候选；重复密钥分析是英文启发式，不保证适合非文本明文。
  - 古典密码：`caesar`（`shift` 0–25，`decrypt` 反向）、`caesar_bruteforce`（按同一评分返回候选）、`atbash`、`vigenere`（第二个输入是字母密钥）、`affine`（`a` 与 26 互质，`b` 0–25）、`affine_bruteforce`、`rail_fence`（`rails` 2–32）。爆破只覆盖可打印或类英文的候选，不是穷举展示。
  - `aes_encrypt`/`aes_decrypt` 用十六进制 `key`（16/24/32 字节）和 16 字节 `iv`，模式为 `ecb`、`cbc`（默认）或 `ctr`，填充为 `pkcs7`（默认）或 `none`；CTR 只能用 `none`，ECB 不传 `iv`。输入/输出编码用 `from_encoding`/`to_encoding`。
  - `rsa_encrypt`/`rsa_decrypt` 用十进制 `n` 和 `e` 或 `d`，对 `0` 至 `n-1` 的输入做原始模幂；输入和输出进制用 `input_base`/`output_base` 指定 10 或 16。`integer_root` 判断某数是否为完全 `degree` 次方，可用于小指数 RSA 的整数开方。
  - `rsa_attack` 用 `rsa_mode` 选择 `factor`、`fermat`、`wiener`、`common_modulus`、`broadcast`（2 至 8 组）、`small_e`、`batch_gcd`（2 至 8 个模数）或 `known_d`（输入 n/e/d 恢复因数，最多 256 个确定性底数）。`batch_gcd` 逐对计算最大公因数；`known_d` 可能返回合数因数。攻击失败只标记该步 `error`，不中断管道。
  - `ecdsa_nonce_reuse` 输入子群阶 `n`、`r` 和两条签名的 `s1,z1,s2,z2`；`z` 是 ECDSA 截断后的摘要整数。计算复用 nonce 的私钥候选，并覆盖低 s 归一化分支。可附 `field_p`、`curve_a/b`、`generator_x/y` 和 `public_key_x/y`，核验曲线子群、两条签名及候选私钥。
  - 直接输入与 `expected` 最多 4,096 字符，整批最多 12 步。运算错误会标记该步和受影响的后续步骤。
- `workbench_base100`（扩展审计层）调用本机 CTF 工作台的 Base100 编解码，可在一个请求里提交 1 至 8 项。编码接受 UTF-8 或成对 Hex。解码返回 Hex，并在字节是有效 UTF-8 时返回文本。每项最多处理 4096 字节，按工作台规则识别编码偏移。
  - 使用下方本机配置关联工作台的 `ctf_extra_ops.py` 和已验证的 SHA-256。连续调用会复用 Python 进程，空闲 60 秒后退出。
- `ctf_progress` 用当前题目目录的 `notes.md` + `.ctf/state.json` 续接分析。运行时按 `action` 严格限定对应字段（schema 保持精简紧凑）：`check` 只收 `claims`，`save` 收 `revision`、`progress` 和可选 `instance`，`repair` 收 `revision`。`notes.md` 只保留人读的"结论/命令/排除/待办"（以及判断来源、提示吸收），机器状态（revision、session、instance、values）在 `.ctf/state.json`。保存以 revision 做 CAS；旧 revision 会拒绝覆盖，状态文件保留上一份和恢复副本，`repair` 为手改笔记另留备份。`load` 恢复结论、已排除假设、待补证据和工具值，并核对原件的 SHA-256 与引用范围；旧版内联 JSON 块仍可读，`save` 后自动迁移。
- `load` 的 `value_status` 区分 `reverified`（当前工具值和原件引用均已复核）、`tool_match`（当前工具值一致，缺少可复核的原件引用）、`recorded`（仅从笔记恢复）、`review`（原件或引用待复核）、`unavailable` 和 `mismatch`。笔记、题解和简报也会区分这些状态。
- `ctf_progress check` 对照当前工具输出核对 `claims`。每项传 `label`、`result_id`、`pointer` 和 `value`，例如 `/steps/0/result`。字符串 `"12"` 和数值 `12` 会判为不一致。只有工具值时返回 `tool_match`，只有笔记保存值时返回 `recorded`。原件的当前哈希和引用位置可通过 `load` 复核。
- `progress.experiments` 可保存单题验证，每项填写 `label`、`hypothesis`、`pointer`、`expected` 和可选的 `result_id`。保存时从结果取得实际标量值。用 `action: experiments` 查阅，或传 `experiment_query: {"tool":"calculate_offline","args":{...}}` 按原调用参数找回验证。响应复核原件，并区分支持、反驳与证据不足；`observation_status` 标明观测来自当前会话或历史记录。
- 同一会话中的本地附件结果按题目目录独立保留，最多保留最近使用的 8 个目录，每个目录上限为 128 条或 4 MiB。离线计算和 Base100 另用同等容量，其他会话工具单独保留最多 48 条。查到的结果会刷新保留顺序。
  - 带原件引用的报告超过 64 KiB 时，仍返回 `result_id` 和完整当前输出。缓存保留有界的可核对标量及对应来源，`result_cache.mode: fields` 表示该结果可用于 `ctf_progress check/save`。如果所需字段未被保留，缩小结果页后重新读取。需要完整结构的跨工具调用请使用较小结果。
- 用户要求留档时，用 `save` 传本次 `load` 返回的 `revision` 和 `progress`。把已核对的条目放进 `progress.values`，每次最多 24 项；`progress.commands` 可记录命令、退出码、输出和目录（每次最多 16 条）。`progress.insights` 记录每条关键判断的来源：`self` 自行推导、`human` 队长或队友提示、`external` 参考了外部题解或 WP，可选 `note` 记提示大意；被提示或被参考过的题照实标注。`progress.hints` 记录提示吸收：`hint` 原文或大意、`source` 来源、`hypothesis` 可证伪假设、`test` 最小验证、`verified` 是否通过；未验证的假设留在 hints，不要写进 `confirmed`。目录必须写命令实际 cwd：`ops_bash` 不继承 `working_directory` 的切换，切目录后要在命令里显式传 `workdir`，或先 `cd` 并用 `pwd` 确认。保存时再次核对值与原件，记录工具名、输出字段和来源。HAR 引用保留 `json_pointer`，日志引用保留行号和字节范围。
  - 超过 32 MiB 的原件按块复核 SHA-256、字节范围与 UTF-8 行号，依赖 DSH 的分段读取。大文件的 JSON 字段定位仍以 32 MiB 为上限，超限会单独标记字段待复核。
- `writeup` 使用同题目录的续接记录生成 `writeup.md` 草稿。可传入 `revision` 核对笔记版本。未在本会话复算的值标为“未复算（待复核）”，并列入“待复核”段；题解标题相应标为“部分未复算，待复核”。`save` 和 `writeup` 均只更新工具管理的记录区，保留已有手写内容。若本题 `.ctf-status.json` 少于 2 条心跳记录，`writeup` 会附收尾提醒。
- `handoff` 返回题目工作目录、附件清单、下一步和 Markdown 接替简报，并把简报写入同目录的 `handoff.md`（只读会话只返回文本）。附件合并原件引用与 `progress.attachments` 中列出的相对路径。简报中的记录值指向工具及证据，接替会话可在相同目录重新核对。新会话接手时先 `load`，再读 `handoff.md`。
- `ctf_progress results` 列出当前会话可引用的 `result_id`、工具名、字节数和创建时间，方便传给 `check`/`save`；清单覆盖当前题目目录、离线计算和会话缓存。
- `ctf_status` 记录时间盒心跳：阶段、卡点、已排除假设、下一步和需要谁，写入题目目录的 `.ctf-status.json`。并发追加使用版本校验并最多重试 3 次；最新有效状态保存在 `.ctf/status.saved.json`，主文件损坏时可恢复。`set` 追加一条（每题建议至少 2 次），`show` 返回 `warnings[]`（含 `code`、`severity`、建议 `action`）和可读兼容字段 `warning_messages[]`；15 分钟提醒换方向、30 分钟列三条路径、60 分钟升级求助。`board` 按 `platformLeaderboardPath`（默认 `/scoreboard`）拉取榜单并在可写会话保存排名/分数/解题数；只读会话仍可查看实时榜单，返回 `recorded: false` 且不写入本地状态。
- 工具结果默认使用紧凑 JSON；在插件配置中设 `compact: false` 可恢复缩进输出。`ctf_progress` 参数 schema 按 action 限定字段，只展示当前操作允许的参数。
- `check_flag`（旧名 `submit_check` 兼容）在本地核对 flag 的格式、长度、来源和动态实例刷新时间，并检查正式提交回执。默认只读。传 `record: true` 才会把预检回执写入 `.ctf-submissions.jsonl`。
  - 自定义 `pattern` 在独立线程限时核对。提交回执只保存允许的字段与 flag 哈希，下一次写入时会清理旧回执里的明文与预览字段。
- `submit_flag` 先跑同一套本地校验，通过后按配置的 `platformUrl` 提交，解析平台响应为 `accepted` / `rejected` / `duplicate`，并把回执写入 `.ctf-submissions.jsonl`；未配置平台时返回 dependency。
- `ctf_instance` 管理比赛实例；`create`/`rotate`/`list` 成功返回的赛题 HTTP/TCP 地址会在当前会话自动授权给 `http_request`/`browser_session`/`net_session`。`rotate` 先创建并记录新实例的 ID，再删除传入 ID。平台拒绝新的槽位时保留旧实例。旧实例删除失败时反馈新旧实例状态。
- `fetch_attachment` 流式下载 HTTP(S) 附件，每跳校验地址，整个调用限 60 秒。未授权来源仅允许公网地址；位于 `networkOrigins` 或与 `platformUrl` 同源的目标支持内网/VPN 下载，且与 `platformUrl` 同源时自动附带平台认证头（跨源跳转自动剥离）。默认 32 MiB，明确需要大附件时可传 `max_bytes`，最高 256 MiB。大文件结果返回区间读取提示。
- `ctf_doctor` 自检宿主必需接口、工具分层同步（`tool_tier_sync`）、包内与本机 `SKILL.md` 同步（`skill_sync`）、Python 3.11+、Python 模块、双层 Linux 沙箱镜像就绪状态（`sandbox_summary` + `sandbox:docker_base`/`sandbox:docker_heavy` 检查与构建提示）和可选本机工具。缺失的 Python 包、GDB、浏览器、APK 与口令审计工具列入 `optional_missing`，状态为 `partial`，不再误报为核心故障；`notes.md`、`handoff.md`、`.ctf-status.json` 和 `.ctf-submissions.jsonl` 尚未创建时标为可选项。macOS 会探测 Chrome/Edge `.app` 内可执行文件。支持的 DSH 范围仍由 `engines.dsh` 限定；无 `systemPrompt.context` 时续接规则退回包内 SKILL。只读，不改题目文件。
- `competition_api`（扩展审计层）按配置的 `platformUrl` 访问比赛平台：`status` 查看配置与 token 环境变量，`instances` 列出实例，`create` 新建（`body` 为请求体），`delete` 删除（需 `id`），`submit` 提交 flag 并追加本地回执。未配置平台时返回 dependency 提示；不回显 token。

- `notes.md` 是已提交状态的可读视图。`.ctf/state.json` 按版本提交，并保留最新恢复副本及上一份状态。`repair` 可重建视图。手改的交接和题解内容保留在新托管区之外。
- 已有反汇编文本可先用 `grep` 定位标签，再用 `read` 的 `offset` 和 `limit` 分段阅读。可引用文件行号和指令地址。
- CTF 会话使用附件核验、命令执行、联网检索和子代理工具。preset 自带平台 shell（Windows 为 `pwsh`，其他平台为 `bash`）；宿主安装 `dsh-ops` 时还可使用 `ops_bash`。
- shell 工具运行命令和脚本。长脚本先写入题目目录再执行；`ops_bash` 用 `script_path` 传入，`bash`/`pwsh` 直接执行文件路径。后台任务用 `run_in_background`，用 `job_output`/`job_list`/`job_kill` 管理。`ops_bash` 不继承 `working_directory` 的切换；所有 shell 运行前显式传 `workdir`，或先 `cd` 并用 `pwd` 确认实际目录。
- 需要联网时用 `web_search`/`web_fetch`；需要并行分析或独立子任务时用 `subagent`/`subagent_fork`/`workflow`。

## 本机依赖与配置

preset 已声明平台 shell（Windows 为 `pwsh`，其他平台为 `bash`），无需依赖宿主；宿主 profile 另装 `dsh-ops` 时还会提供 `ops_bash`。`tool-jobs` 随 preset 挂载，用于后台命令和任务收集。

本机配置保存在 `<DSH_HOME>/ctf-workbench.json`，默认位于 `~/.dsh`。工具和自检使用同一份合并配置。插件节点的显式字段优先于用户文件，省略时使用对应工具的默认值或本机探测。

- `enableExtendedAudit`：布尔开关，默认 `false`（仅加载 27 个核心实战工具以降低上下文 Schema 体积）；设为 `true` 时额外启用全部 18 个扩展审计、低频与兼容工具（共 45 个）。修改此开关后需重启或重载 DSH 生效，`ctf_doctor` 的 `tool_tier_sync` 会提示当前进程是否已同步。
- `sandboxBackend`（`'auto' | 'docker' | 'wsl'`，默认 `'auto'`）、`sandboxImage`（默认 `'dsh-ctf-sandbox:latest'`）、`sandboxHeavyImage`（默认 `'dsh-ctf-sandbox:heavy'`，用于按需自动升级重型工具）、`sandboxWslDistro`（默认自动选择首个非 `docker-desktop*` 发行版）：控制 `ctf_sandbox` 与 Windows 下 `gdb_driver` 的 Linux 后端与双层镜像选择。
- `pythonPath` 指定本机 Python 3.11 或更新版本的绝对路径。DSH 的 `ctf-attachment-tools` 节点也可配置同名字段，优先于该文件。省略时，Windows 尝试 `py -3` 或 PATH 上的 Python，其他平台尝试 `python3` 或 `python`，也可发现 DSH 已安装的 Python。 [Python Windows 启动器文档](https://docs.python.org/3/using/windows.html)
- `networkOrigins` 填批准访问的 HTTP(S) 来源，支持精确来源、通配端口、端口范围、子域通配与 CIDR 网段（例如 `["https://challenge.example.test", "http://10.0.0.0/8:*", "https://*.ctf.example:10000-65535"]`）。`tcpTargets` 填批准连接的主机和端口，同样支持通配端口、端口范围、子域通配与 CIDR（例如 `["10.0.0.0/8:*", "pwn.ctf.example:20000-40000"]`）。平台返回的动态靶机授权另按发起会话和工作区隔离，30 分钟后失效；删除实例或容器会撤销对应授权。仍始终阻止云元数据及链路本地等基础设施地址。`attachmentImportRoots` 填批准导入附件的本机绝对目录。工作台 JSON 修改后自动热重载，无需重启 DSH；插件节点显式字段优先。
- `gdbPath` 和 `browserPath` 可指定本机绝对路径。自动探测支持系统 PATH 中的 GDB 和常见 Chrome/Edge 安装目录，并识别 `GDB`、`CHROME_PATH`。
- `platformUrl` 为平台 API 根地址，`platformType` 支持 `auto`（默认）、`ctfd`、`gzctf`、`generic`，`platformGameId` 为 GZCTF 默认比赛 ID，`platformChallengesPath` 为通用平台题单路径；`platformTokenEnv` 指向令牌环境变量，默认 `CTF_PLATFORM_TOKEN`。可用 `platformAuthHeader`（默认 `Authorization`）与 `platformAuthScheme`（默认 `Bearer`，CTFd 自动默认 `Token`，空串表示直接传值）适配不同平台认证；API 请求可跟随经来源校验的同源跳转，`ctf_arena fetch_files` 会将同一适配器认证用于平台同源附件，跨来源请求不会携带平台令牌。内网/线下 HTTP 平台需显式设 `allowInsecurePlatformHttp: true` 才允许携带令牌。`platformInstancesPath`、`platformSubmitPath`、`platformLeaderboardPath` 的默认值分别为 `/instances`、`/submissions`、`/scoreboard`。榜单返回多队列表时可用 `platformTeamId` 选择本队，状态文件只保存本队摘要。
- `libarchivePath` 可指定本机 libarchive 的绝对路径。省略时尝试本机系统库。7z/RAR 缺少依赖时仍会返回识别出的格式和原件 SHA-256，可用 `read_binary_range` 查看原始字节。
- `base100Source` 和 `base100Sha256` 分别为工作台 `ctf_extra_ops.py` 的绝对路径及已验证的 SHA-256。Windows 文件名按大小写不敏感方式识别；更改本机配置后重载 DSH。

从旧版迁移时，将包内 `workbench.local.json` 的 `python`、`base100_source`、`base100_sha256` 分别转入上述 `pythonPath`、`base100Source`、`base100Sha256`。升级会保留本机配置；已有 `.ctf/state.json` 保留版本校验、CAS 和恢复副本。ZIP、TAR、gzip 和二进制切片可独立使用。兼容范围见包清单的 `engines.dsh`。插件要求 DSH `>=0.2.2-rc.5 <0.3.0`；`ctf_doctor` 会显示工具注册、文件系统和续接提示能力，低于范围或缺少必需文件接口时需升级 DSH。

## Rev 证据核对（扩展审计层）

以下四项工具需在配置中启用 `enableExtendedAudit: true` 后注册：

- `query_rev_export` 从已有文本导出核对指定 `query.kind` 和 `value`。查找种类为 `function`、`address` 或 `string`。`format: "listing"` 读取 GNU 式带地址标签、指令位置和已显示的直接调用。`format: "jsonl"` 读取下列显式记录，字符串精确匹配，地址可查已声明的函数范围。关系记录中的 `source` 是调用或引用位置，`from_definitions` 和 `to_definitions` 给出同一原件里的名称定义位置。用 `ctf_progress check` 核对名称会同时带上这两处证据。别名或范围冲突时给出候选。 [GNU objdump 文档](https://sourceware.org/binutils/docs/binutils/objdump.html)

```jsonl
{"kind":"function","name":"fold","address":"0x401020","size":16}
{"kind":"call","address":"0x401014","from":"0x401010","to":"0x401020"}
{"kind":"string","address":"0x402000","value":"seed-mask"}
{"kind":"ref","address":"0x401023","from":"0x401020","to":"0x402000"}
```

- `map_rev_address` 一次核对最多 12 处原件坐标。每项传 `kind`、带 `0x` 的 `value`，可附 `byte_length` 和十进制 `expected_file_offset`。ELF、PE 支持原件 `file_offset`、链接时 `va`、`rva` 与 `runtime_va`。PE 使用头部的 `ImageBase`。对照 ELF 的相对或运行时地址时传已知的 `image_base`。核对 `runtime_va` 时同时传记录里实际的 `load_base`。仅在内存中的区域、跨区间和多重映射均有相应标记。Wasm 以节内容与原件偏移对照，`section_offset` 须附从 0 起的 `section_index`。原件限 32 MiB。 [ELF 程序头](https://gabi.xinuos.com/elf/07-pheader.html) [Microsoft PE 格式](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) [WebAssembly 二进制节](https://webassembly.github.io/spec/core/binary/modules.html#sections)
- `verify_rev_machine` 读取已给出的字节规则 JSONL，按 `input_hex` 的原始顺序处理最多 64 字节。第一行用 `kind: "start"` 声明 `state`、`width`、`value`。后续 `kind: "rule"` 用 `state`、`byte`、`next` 声明转换。`byte` 是两位 Hex，`"*"` 用作同状态下的后备规则。可附 `operation` 和 `operand` 执行定宽算术或移位，`"input"` 表示取当前输入字节。`emit: true` 保存当前累加值到输出。结果保留每步的规则行，可以附 `expected_state`、`expected_value` 核对最终状态和十进制值。

```jsonl
{"kind":"start","state":"seed","width":8,"value":"0x33"}
{"kind":"rule","state":"seed","byte":"10","next":"done","operation":"word_xor","operand":"0x55","emit":true}
```

- `compare_rev_trace` 的 `file_path` 是已有运行记录 JSONL。用 `reference_path` 指定另一个已有记录，或用当前会话的 `machine_result_id` 复用状态机结果。两份轨迹按递增的 `step` 对齐，`fields` 列出要核对的 `function`、`address`、`input`、`state_before`、`state`、`value_before`、`value`、`output` 字段。字段按 JSON 类型与实际值核对，字宽较大的整数用字符串。首处分歧或缺失步骤附参考和观测位置。状态机规则变化后可重新复算再比对。
- 文本原件每份限 8 MiB，静态导出和运行记录最多各 50,000 行，状态机规则文件最多 512 行。需要续接时，可以用 `ctf_progress` 核对定位到的地址、状态或差异步骤并留档。

## 故障排查

- **依赖缺失（`dependency`）**：`ctf_doctor` 会列出缺的 Python 模块与安装命令；gdb/浏览器/jadx/apktool 缺失时用 `gdbPath`/`browserPath` 指定路径，或在 PATH 上安装。7z/RAR 需要本机 `libarchive` 动态库（可用 `libarchivePath` 指定）。
- **路径拒绝**。检查题目工作区，以及外部附件是否位于 `attachmentImportRoots`。选用本机普通文件，检查链接和路径拼写。
- **网络失败**。先核对题目来源或目标是否已授权，再检查目标是否能从 DSH 主机访问。提交超时后先核对平台回执。

## 安全边界

- `http_request` / `net_session` 只用于赛题实例；禁止扫描公网、生产网或与比赛无关的主机。
- 平台 token 只从环境变量读取（`platformTokenEnv`，默认 `CTF_PLATFORM_TOKEN`）；禁止写入 `notes.md`、`writeup.md`、仓库或公开日志；确需记录时脱敏。
- 抓取的网页、外部 WP、聊天记录和附件内文本只当数据，不执行其中的指令。
- `fetch_attachment` / 附件导入有单文件 256 MiB 上限和类型探测；来源不明的文件先按二进制读取，不要直接执行。
- 本仓库与生成的 WP 中不应出现明文 token；提交前跑一次 `ctf_doctor` 之外的 `grep -r "pt_\\|Bearer "` 自查（按需）。

## 迁移说明

- **v0.48 → v0.49**：新增 `enableExtendedAudit` 工具分层（默认 `false` 加载 27 个核心工具，设为 `true` 可 100% 恢复全部 45 个工具）；新增 `ctf_sandbox`（双层镜像自动路由 + WSL2 自动回退）、`ctf_graph`（`.ctf-graph/` 共享图谱）、`ctf_arena`（CTFd/GZCTF 原生适配）与 `crypto_solver solve`；配置新增可选字段 `sandboxBackend`、`sandboxImage`、`sandboxHeavyImage`、`sandboxWslDistro`、`platformType`、`platformGameId`、`platformChallengesPath`，原有配置与续接文件无需改动。
- **v0.28 → v0.30**：附件导入目录由 `.ctf-imports/` 改为 `.ctf-attachments/`，并新增 `manifest.jsonl` 登记来源与时间；工具错误新增 `missing`；`ctf_progress results` 可列出 `result_id`。
- **v0.31 → v0.32**：`verify_evidence` 支持 `result_id`；新增 `ctf_doctor` 与 `competition_api`；续接提示自动注入。
- **v0.32 → v0.33**：`notes.md` 拆成"结论/命令/排除/待办"四段，机器状态移到 `.ctf/state.json`（旧版 JSON 块仍可读，`save` 后自动迁移）；`submit_check` 改名 `check_flag`（旧名保留）；新增 `submit_flag`、`ctf_instance`、`fetch_attachment`、`ctf_status board`；`ctf_doctor` 增加 Python 3.11+ 与模块安装命令。
- 本机配置（`<DSH_HOME>/ctf-workbench.json`）在升级时保留；`platformUrl`、`platformLeaderboardPath`、`gdbPath`、`browserPath` 等字段名不变。

## 变更记录

完整变更与兼容矩阵见 `CHANGELOG.md`（当前 `0.51.1`）。近期摘要：

- Unreleased：图谱租约拒绝未认领任务直接结案并分页 `ruled_out`；Python 热重载、CRLF Bash 脚本、反编译失败诊断、平台认证探测、只读看板与续接错误分类得到加固；平台附件复用适配器认证，模型扫描截断显示不完整状态。

- 0.51.1 基础镜像恢复 r2/r2ghidra（radare2 5.9.8 真安装并同号锁定，修掉缺 `patch`、`symstall` 悬空、r2ghidra ABI 冲突三个构建缺陷）；修复 r2 反编译把 `--` 当选项结束导致的空函数列表，以及函数名需 `sym.` 前缀回退。
- 0.51.0 补审计回归用例（PCAP UTC 过滤、GGUF/Safetensors 元数据注入、Ghidra `image_base`、`ctf_sandbox` 的 `result_id`、账本坏行容错）；CI 新增 Python worker 编译与真实容器隔离冒烟；基础镜像按 digest 固定、下载物校验 SHA-256；`check_flag`/`submit_flag` 回报 `corrupted_receipts`。
- 0.50.0 精简 `ctf_progress` schema（-61%）；`ctf_graph` 新增 `board` 分页/过滤与只读 `export_writeup`；`ctf_arena` 支持 GZCTF `Cookie: GZCTF_Token=` 自动认证、`container extend` 与同分按 `solves` 排优；`browser_session` 新增弹窗自动捕获（`dialogs`）、`evaluate`/`set_cookie`/`set_headers`/`upload_file`；Docker 沙箱加固 `--cap-drop=ALL`/`no-new-privileges`/`read_only_work` 并增补 `bkcrack`/`ffuf`/`sqlmap`/`john`/`tesseract-ocr`/`pyinstxtractor-ng`/`pwninit`；`mobile_apk` 缺失本机工具时自动桥接沙箱；`inspect_media` 新增 `kind: "model"`（Pickle/PyTorch/Safetensors/GGUF/ONNX 静态安全体检）；`crypto_solver` 新增 `ecc_weak`/`padding_oracle`/`hash_ext` 脚手架；回归测试增至 180 项、覆盖率超 70%。
- 0.49.1 加固 `ctf_graph finish_intent` 持有者与终态 Fencing 校验；`ctf_sandbox decompile` 合并 `r2` 单次分析并为 Ghidra 持久化项目缓存；`ctf_doctor` 增加 `tool_tier_sync` 与 `skill_sync` 自检；统一只读 `permission` 与 `EEXIST -> conflict` 错误分类并对齐扩展层文档。
- 0.49.0 新增工具分层（27 核心 / 45 全量）、`ctf_sandbox` 双层镜像自动路由与 WSL2 兜底、`ctf_graph` 共享图谱与 `dispatch_plan`、`ctf_arena` CTFd/GZCTF 适配、`crypto_solver solve` 零依赖求解、`rev_query` 多架构/PE/`triage`、`gdb_driver` Linux 自动桥接与 `ctf_doctor` 双镜像自检。
- 0.48.0 `rev_query` 新增函数级 `cfg` 控制流分析（基本块、分支/调用与 RIP 相对数据引用）。
- 0.47.0 Pwn 增加受限 GDB 批量调试与 `pwn_payload`（libc/PIE 基址及基础 ret2libc_x64 组装）。
- 0.46.0 `browser_session` 增加受限点击、填表、下拉选择、按键发送、动态等待与 Web Storage 查看。
- 0.43.0–0.45.0 补充重复密钥 XOR、zlib/bzip2/XZ/raw Deflate、ASCII85/Z85/basE91，以及 RSA `batch_gcd`/`known_d` 与 ECDSA nonce 重用。
- 0.38.0–0.42.0 新增 `scan_binary`、内嵌 ZIP 区间验证、大整数与字节互转、LCG 复算与断点续算、派生字节 `source_result_id` 链路、PDF 渲染/附件、SQLite 只读查询、Office 提取及 1 GiB 流式 PCAP。
- 0.37.0 统一平台请求与错误提示；默认紧凑 JSON，按 action 收窄 `ctf_progress` schema；补充模块/导入检查、覆盖率门槛与 CI。
- 0.36.0 修复 HTTP 正文中断、重定向和 URL 处理，补全 Flask 路由、编码与媒体取证。改进实例轮换、自检、浏览器生命周期和回执留存。
- 0.35.0 预检默认只读，证据编号失效时可按原件哈希复算。支持 BSD 回环抓包、DNS 查询名和 TXT 及捕获时间，兼容一个全零结束块的 TAR，并单列 Flask 响应钩子。
- 0.34.0 增加统一的来源与附件路径限制，修复提交、实例轮换与续接恢复。支持已知口令读取 ZIP、TAR 尾随数据、IPv4 分片及 Linux cooked 抓包。证据字段可按题目目录留档。
- 0.33.0 `notes.md` 拆分为人读四段，机器状态迁移至 `.ctf/state.json`；新增 `check_flag`、`submit_flag`、`ctf_instance`、`fetch_attachment`、`ctf_status board` 与 Python 依赖探测。

- 0.32.0：`verify_evidence` 支持 `result_id` 引用（按记录偏移与 SHA-256 复核，无需重写 prefix）；新增 `ctf_doctor` 自检本机依赖与续接文件；新增 `competition_api` 封装平台实例与提交（配置 `platformUrl` 后可用，未配置返回 dependency）；CTF 会话系统提示自动提醒先读 notes.md/handoff.md/.ctf-status.json/.ctf-submissions.jsonl。

- 0.31.0：新增 `ctf_status`（每题至少两次心跳，写入 `.ctf-status.json`，按 15/30/60 分钟给出换方向、三条路径、升级求助提醒）与 `submit_check`（提交前校验格式、长度、来源、实例新鲜度，回执写入 `.ctf-submissions.jsonl`，重复提交提示）；`ctf_progress` 新增 `progress.hints` 记录提示吸收（提示→假设→最小验证→verified）；SKILL 新增工具选择表、时间盒、提交纪律、提示吸收、并行调度和收尾清单。

- 0.30.0：附件导入目录改为 `.ctf-attachments/`，并在 `manifest.jsonl` 登记文件名、SHA-256、大小、来源路径和导入时间；工具错误新增 `missing` 类别；`read_ctf_files`、`http_request`、`net_session` 的描述首行注明了与 `read`/shell 的边界；`ctf_progress` 新增 `results` 列出可引用的 `result_id`。
- 0.29.0：新增 7 个扩展工具——`browser_session`（Chrome/Edge CDP）、`gdb_driver`（批处理 gdb）、`archive_crack`（ZIP/ZipCrypto 口令）、`stego_audio`（WAV LSB 与频谱 PNG）、`mobile_apk`（APK 结构/反编译/签名）、`cloud_metadata`（云元数据/K8s token/端口探活）、`crypto_solver`（z3/fpylll 模板与运行）；配置新增 `browserPath`、`gdbPath`。
- 0.28.1：读取类工具接受浏览器下载的绝对路径，自动复制到题目目录 `.ctf-imports/`（0.30.0 起改名为 `.ctf-attachments/`）；工具失败返回结构化 `ok:false` 与 `error.kind`/`error.hint`；`ctf_progress` 支持 `progress.insights` 记录关键判断来源；`handoff` 把接替简报写入 `handoff.md`。
- 0.28.0：上一版本。

如需撤销，从 **插件** 页移除此包，并移除本次添加的技能文件。移除前先保存需要保留的会话输出。
