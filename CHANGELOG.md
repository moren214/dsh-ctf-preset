# 变更记录

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
| 0.37.x | `>=0.2.2-rc.5 <0.3.0` | 当前版本；要求 `ctx.fs` 与 `tools.register`；系统提示接口缺失时回退包内 SKILL |
| 0.33–0.36 | `>=0.2.2-rc.5 <0.3.0` | 旧版本；升级后工具输出默认改为紧凑 JSON |
| 更低 | 未验证 | 低于声明范围不支持；运行时 `ctf_doctor` 可报告宿主能力缺失 |

升级 DSH 前先跑 `npm test`；若 `engines.dsh` 上限不再满足，先在本机冒烟测试通过再改 `engines` 字段。
