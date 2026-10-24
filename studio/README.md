# CTF Studio

一个本地优先的图形化 CTF 入口。外观和交互参考了 Muteki 的单题工作台，但后端直接复用本仓库已经验收过的离线工具链，不要求先配置模型账号。

部署、故障排查和非 Codex 客户端适配的完整说明见
[`docs/USAGE.zh-CN.md`](../docs/USAGE.zh-CN.md)。

## 三分钟上手

1. 就在仓库根目录，双击 `START-HERE.cmd` 并输入 `1`；需要完整离线语料和桌面版时运行 `.\bootstrap.cmd -Full`。
2. 运行 `bin\ctf-studio.cmd`，或双击已构建的 **CTF Studio** 快捷方式。程序已经在运行时，再点快捷方式只会把旧窗口提到前台。
3. 在“开始解题”里粘贴题面；附件直接拖进输入框；有题目地址就展开“高级”填到“题目 URL”。
4. 先选 **本地快解** 点“派发”：它不需要模型账号，会立刻做附件分诊、字符串扫描和离线语料检索。
5. 需要多 Agent 竞速时再选 **Codex 蜂群**；已启动 Muteki 服务时可选 **Muteki 蜂群**。
6. 结果在“运行”页：先看“共享事实”和“下一手”，需要时在下方 Kali 控制台执行命令；flag 在台账里区分候选 / 已验证。

左侧问号按钮随时可以打开同一份使用指南。其他入口：放大镜是离线语料检索，扳手是编解码/古典密码变换台，滑杆是环境诊断。

## 启动

```powershell
bin\ctf-studio.cmd
```

默认打开 `http://127.0.0.1:8765/`。也可以指定端口：

```powershell
bin\ctf-studio.cmd --port 8777
```

创建桌面快捷方式：

```powershell
pwsh -File scripts\create-studio-shortcut.ps1
```

### 原生桌面版

不想看到浏览器地址栏时，构建 WebView2 原生窗口：

```powershell
pwsh -File scripts\build-desktop.ps1
pwsh -File scripts\create-studio-shortcut.ps1
```

产物是 `studio\dist\CTFStudio.exe`，双击后只出现一个应用窗口；桌面快捷方式
会自动优先指向这个 exe。它仍然读取仓库里的工具链和语料，所以不要把 exe 单独
复制到没有 `muteki-tool-root/` 的目录。Windows 需要 WebView2 Runtime（Windows
11 和较新的 Windows 10 通常已经带）。

服务只绑定回环地址，并在页面里注入一次性 token；API 同时校验 `Host`、`Origin` 和 `X-Studio-Token`，避免其它网页借浏览器调用本机命令执行接口。

## 三种模式

| 模式 | 做什么 | 依赖 |
| --- | --- | --- |
| 本地快解 | 并行跑附件分诊、字符串扫描、BM25 语料检索、Web 情报、二进制保护/策略分析，最后由协调器合并事实与下一手 | Python 3；`ctf-kali` 可选 |
| Codex 蜂群 | 2–8 个 `codex exec` Worker 在隔离目录中竞速；先出可验证 flag 的 Worker 获胜，其余取消 | 已登录的 Codex CLI |
| Muteki 蜂群 | 把题目派发给运行中的 Project Muteki，镜像它的 SSE 事件流 | Muteki 服务 + 至少一个已登录的 agent CLI + Planner |

### 本地快解

- **附件分诊**：调用 `ctf-triage`，把类型、熵、嵌入对象、字符串和下一步命令变成事实。
- **字符串扫描**：只在附件原始字节里找 flag 形态，标成“候选”，不会冒充已验证。
- **离线语料**：`ctf-index` 的 BM25 检索，支持中文；命中会变成可复制的命令。
- **二进制计划**：对 ELF/PE 跑 `file`、`checksec`、`readelf`、`strings`，按 NX/PIE/Canary/RELRO 给出策略排序。
- **Web 情报**：对题目 URL 做一次授权 GET，记录状态码、响应头、标题、表单、注释和链接；不跟随跨站重定向，不读 Cookie 值。
- **协调器**：去重事实、推断类别、汇总 `brief.md` 和“下一手”。

### Flag 生命周期

`候选 → 待复核/已验证 → 已驳回` 是显式的。只有以下来源会自动标为已验证：

1. 命令/工具的真实输出里出现且匹配 flag 合同；
2. Worker 的 `flag.txt` 内容能在同一 Worker 的工具输出里找到；
3. 人工在台账里确认。

其余只标为候选，并保留来源；可以一键确认或驳回。这个设计借自 CTF-Boom 的证据中心模型。

### 变换台

浏览器本地执行，不发网络请求：

- Base64 / Base32 / Hex / URL / Binary / Decimal / Morse / HTML Entity
- ROT13 / Atbash / Caesar 全偏移 / 反转
- 单字节 XOR 暴力、哈希长度识别、JWT 解码、Brainfuck 解释、Flag 提取
- Magic：尝试常见的两层组合，按可读性和 flag 形态排序
- 配方（recipe）按顺序执行，可删除单步；输出可以复制、回填输入、放进题面或记入当前台账

这部分借鉴了 CyberChef 的配方模型、CTFCrackTools X 的节点化思路和 CaptfEncoder 的常见编码分类；实现是独立的，不复制它们的代码或语料。

### 设计参考

只借鉴交互和数据模型，未复制代码：

完整调研清单和“为什么没接”写在 [`REFERENCES.md`](REFERENCES.md)。

| 项目 | 许可 | 借鉴点 |
| --- | --- | --- |
| [CyberChef](https://github.com/gchq/CyberChef) | Apache-2.0 | 输入 / 配方 / 输出三栏，Magic |
| [CTFCrackTools X](https://github.com/0Chencc/CTFCrackTools) | GPL-3.0 | 节点化、可组合的变换流程 |
| [CTFever](https://github.com/HoshinoSuzumi/CTFever) | GPL-3.0 | 按题型分类的工具目录 |
| [CaptfEncoder](https://github.com/guyoung/CaptfEncoder) | MIT | 常见编码 / 古典密码分类 |
| [CTF-Boom](https://github.com/wbw16/CTF-Boom) | Apache-2.0 | 候选 Flag 生命周期、证据留痕 |
| [Triage](https://github.com/0-Bobo/Triage) | MIT | 二进制侦察 + 策略排序 |
| [LingXi](https://github.com/adrian803/LingXi) | GPL-3.0 | Planner / Executor / Reflector 与经验回放 |
| [Project Muteki](https://github.com/FishCodeTech/muteki) | AGPL-3.0 | 只共享已验证事实的蜂群总线 |

## 多 Agent 协同

`Codex 蜂群` 的每个 Worker 得到：

- 同一道题的题面和附件副本；
- 独立的 `workers/wN/` 工作目录；
- 不同的角色提示（侦察、知识、执行、反证、工具、横向、收尾、复核）；
- 固定的工具入口和“只共享已验证事实”的约束。

协调器不把某个 Worker 的猜测广播给其它 Worker；它只把工具输出、文件事实、flag 候选和下一手汇总到共享事实面板。这一点和 Muteki 的 `FactDiscovered / DeadEndMarked / FlagFound` 总线原则一致。

`Muteki 蜂群` 通过 `POST /api/runs`、`POST /api/runs/{id}/start` 和 `/events` SSE 接入现有服务。设置页会显示服务、WSL、Codex 和语料的实时状态；服务不在线时会给出明确的启动入口，而不是静默失败。

> 当前源码中的“Codex 蜂群”直接调用 `codex exec --json`，不是通用的
> Agent 协议。使用 Claude Code、Cursor、Kimi 等服务时，可以继续使用本地快解
> 和 Muteki 模式；若要替换蜂群后端，需要修改 `server.py` 中的
> `resolve_codex()`、`_codex_worker()` 和对应的事件解析逻辑。

## 目录

```text
studio/
  server.py          # stdlib-only HTTP/API server
  web/
    index.html
    app.js
    styles.css
  runs/              # generated per-run workspaces (gitignored)
  experience.jsonl   # technique-only replay log (gitignored)
```

每个运行目录：

```text
runs/<id>/
  files/             # uploaded attachments
  workers/wN/        # Codex worker sandboxes
  logs/              # per-worker JSONL/stdout and events.jsonl
  brief.md           # coordinator summary
  run.json           # state, facts, flags, actions
```

## API 摘要

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| GET | `/api/status` | 语料、工具、WSL、Codex、Muteki 状态 |
| POST | `/api/runs` | 创建运行 |
| PUT | `/api/runs/{id}/files?name=` | 上传附件（单文件原始字节） |
| POST | `/api/runs/{id}/dispatch` | 派发本地/Codex/Muteki |
| GET | `/api/runs/{id}?after=` | 拉取状态与增量事件 |
| POST | `/api/runs/{id}/command` | 在 Kali 或 Windows 执行命令 |
| POST | `/api/runs/{id}/flag` | 确认/驳回 flag |
| POST | `/api/search` | BM25 或 ripgrep 检索 |
| POST | `/api/muteki/start` | 在 ctf-kali 中启动 Muteki 服务 |

所有 `/api/*` 都需要 `X-Studio-Token`。

## 安全边界

- 只用于已授权的 CTF、靶场或自己的题目。
- 服务默认只监听 `127.0.0.1`；不要把端口暴露到公网。
- 命令执行是显式的人工动作，不是自动提权或自动攻击。
- 附件只写到运行目录；API 读取文件时校验路径必须落在运行目录内。
- Web 探测只做一次 GET，不主动爆破、不跟随到外部主机、不记录 Cookie 值。
- Codex Worker 用 `workspace-write` 沙箱启动，并在提示里禁止读取 benchmark manifest、答案文件和其他 Worker 目录。

## 验收

```powershell
pwsh -File scripts\verify-studio.ps1
```

脚本会启动一个临时端口，验证 token、路径穿越拒绝、创建/上传/派发、事实与命令、flag 审核，以及变换台的静态资源。
