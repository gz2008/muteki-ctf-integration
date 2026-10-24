# CTF Studio 中文使用指南

这份指南面向第一次部署 CTF Studio 的用户，说明安装、三种解题模式、非 Codex
客户端的适配方式、需要修改的代码和常见故障。

> 仅用于获得授权的 CTF 比赛、公开靶场、本地实验环境或你自己的系统。

## 1. 它是什么

CTF Studio 是一个本地优先的 CTF 工作台。它不替代解题 Agent，而是把以下环节放进
同一个界面：

- 题目描述、URL 和附件管理；
- 文件类型、熵、字符串、归档和二进制保护检查；
- 离线语料正则搜索和中文 BM25 检索；
- PCAP 重组、文件修复和编码变换；
- 2–8 个 Agent Worker 独立竞速；
- 候选 flag、真实工具输出和人工复核记录；
- 在 Kali/WSL 或 Windows 中手动执行命令。

本地快解模式不调用大模型。Codex 蜂群模式才需要已登录的 Codex CLI。

## 2. 环境要求

| 组件 | 用途 | 是否必需 |
|---|---|---|
| Python 3.10+ | Studio 服务、分诊和基础分析器 | 是 |
| PowerShell 7 | Windows 启动与构建脚本 | Windows 推荐 |
| WebView2 Runtime | 原生桌面窗口 | 构建 EXE 时需要 |
| WSL2 + Kali | `ctf-linux`、pwntools、GDB、Z3、Docker 等 | 完整功能需要 |
| Codex CLI | Codex 蜂群 | 仅该模式需要 |
| Project Muteki | Muteki 蜂群 | 仅该模式需要 |

仓库不附带 Kali 根文件系统、工具镜像、离线语料或大模型凭证。语料由固定版本的
下载脚本获取，工具链需要用户自行准备。

### 平台边界

- Windows 10/11：当前发布版的主要目标平台。
- Linux/macOS：Python 分析器和 `scripts/*.sh` 可用；Studio 的部分启动矩阵目前
  硬编码 Windows 的 `.cmd` 入口和 WSL，需要按第 6 节修改后才能完整运行。
- Android 模拟器和 WSL2 在 Windows 上可以同时使用，前提是双方都走 WHPX；
  不要为了模拟器关闭 Hyper-V/WHPX。

## 3. 安装和启动

```powershell
git clone https://github.com/gz2008/muteki-ctf-integration.git
cd muteki-ctf-integration
bin\ctf-studio.cmd
```

浏览器打开 `http://127.0.0.1:8765/`。可以指定其他回环端口：

```powershell
bin\ctf-studio.cmd --port 8777
```

### 获取离线语料

完整检索需要先拉取九套固定 commit 的语料：

```powershell
pwsh -File scripts\fetch-knowledge.ps1
pwsh -File scripts\verify-knowledge.ps1
```

这些文件会写入 `muteki-tool-root/`、`archives/` 和 `index/`，已在 `.gitignore`
中排除。不要把语料重新提交到仓库，各来源仍受自己的许可证约束。

### 构建原生窗口

```powershell
pwsh -File scripts\build-desktop.ps1
```

产物位于 `studio\dist\CTFStudio.exe`。该 EXE 仍会读取仓库内的工具和语料，
不能单独复制到其他目录。

## 4. 三分钟操作流程

1. 在“开始解题”中填写题名和题面。
2. 有附件就拖入输入区；有题目地址就展开“高级”填入 URL。
3. 选择模式并点击“派发”。
4. 在运行页先看“共享事实”和“下一手”，再决定是否执行建议命令。
5. flag 只有在真实工具输出或人工复核后才进入“已验证”；普通字符串只是候选。

### 本地快解

不需要模型账号，适合：

- 文件识别、熵、内嵌对象和字符串；
- PCAP、压缩包和图片的第一轮检查；
- 离线语料检索；
- ELF/PE 保护与策略分析；
- 编解码、XOR、ROT、JWT 和常见变换。

### Codex 蜂群

需要已登录的 `codex` CLI。每个 Worker 有独立目录和附件副本，角色包括侦察、
知识、执行、反证、工具、横向、收尾和复核。

Studio 会把仓库内的
`skills/muteki-ctf-local-playbook/` 复制到每个 Worker 作为 `./skill/`。Worker
先读该目录的 `SKILL.md`，再只加载最匹配的题型参考。

### Muteki 蜂群

需要能够访问 `http://127.0.0.1:8000/api/health` 的 Project Muteki 服务。
使用哪个底层 Agent 由 Muteki 配置决定，不由 Studio 决定。

## 5. 不使用 Codex 时怎么办

| 使用方式 | 是否需要改代码 |
|---|---|
| 只用本地分析器或变换台 | 不需要 |
| 用 Studio 的 Muteki 模式 | 通常不需要，前提是 Muteki 已配置好其他 Agent |
| 用 Claude Code、Cursor、Kimi 等替代“Codex 蜂群” | 需要适配 |
| 在 Linux/macOS 上运行完整 Studio | 需要适配平台命令和 WSL 层 |

### 5.1 非 Codex CLI 的适配位置

当前 `studio/server.py` 中的 `_codex_worker()` 会构造以下调用：

```text
codex exec --skip-git-repo-check -C <worker> -s workspace-write --json -o <last> <prompt>
```

如果改用 Claude Code、Cursor CLI 或其他 Agent，需要同时处理：

1. `resolve_codex()`：从查找 `codex` 改为查找你的 CLI。
2. `_codex_worker()`：替换命令参数、工作目录和沙箱参数。
3. JSON 事件解析：当前代码读取 Codex 的 JSONL 事件。其他客户端如果只输出普通
   stdout，需要增加相应的输出解析器。
4. `worker_prompt`：保留安全边界和 flag 证据规则。仓库内置的
   `./skill/SKILL.md` 不依赖 Codex，可以继续使用。
5. `status()`：把 `codex` 状态字段换成你的 Agent 状态，并同步修改
   `studio/web/app.js` 和 `studio/web/index.html` 中的名称。

不要直接开启 `--dangerously-skip-permissions`、`--yolo` 或等价的全局提权参数。
Worker 默认应保持工作目录写权限、网络按题目需要开放，并禁止读取答案目录。

### 5.2 非 Windows 的适配位置

当前 Studio 的 Windows 路径矩阵会调用：

- `bin/*.cmd`
- `wsl.exe`
- 默认发行版 `ctf-kali`

Linux/macOS 使用者可以：

- 直接运行 `scripts/ctf-triage.py`、`ctf-net.py`、`ctf-repair.py` 等分析器；
- 使用对应的 `scripts/*.sh` 入口；
- 在 `studio/server.py` 中增加平台判断，把工具入口映射到 `scripts/`；
- 去掉或替换 `WSL_EXE`、`wsl_path()` 和 `ctf-linux` 的调用。

### 5.3 可配置环境变量

| 变量 | 作用 |
|---|---|
| `CTF_STUDIO_HOME` | Studio 目录 |
| `CTF_STUDIO_ROOT` | 工具仓库根目录 |
| `CTF_STUDIO_WEB` | Web 静态文件目录 |
| `CTF_STUDIO_RUNS` | 运行记录目录 |
| `CTF_STUDIO_EXPERIENCE` | 经验回放文件 |
| `CTF_LOCAL_PYTHON` | Python 解释器路径 |
| `CTF_KALI_DISTRO` | WSL 发行版名称，默认 `ctf-kali` |
| `CTF_KALI_USER` | WSL 用户，默认 `ctf` |
| `MUTEKI_ROOT` | 包含 `run.sh` 的 Project Muteki 目录 |

例如：

```powershell
$env:CTF_KALI_DISTRO = "Kali"
$env:CTF_KALI_USER = "kali"
$env:MUTEKI_ROOT = "D:\tools\muteki"
bin\ctf-studio.cmd
```

## 6. 个人路径和本地工具

仓库中的启动脚本以自身目录为根，不要求必须位于 `D:\codex`。仍需自行准备：

- 名为 `ctf-kali` 的 WSL 发行版，或通过 `CTF_KALI_DISTRO` 指定其他名称；
- `/opt/ctf/venvs/core/bin/python` 以及所需的 Kali 工具；
- `muteki-tool-root/` 中的离线语料和索引；
- 可用的 Codex 或其他 Agent CLI。

如果你只是使用核心 Python 分析器，不需要上面的完整 Kali 工具链。

## 7. 数据和隐私

- 运行记录在 `studio/runs/`；
- 技术经验在 `studio/experience.jsonl`；
- Codex Worker 日志在 `studio/runs/<id>/logs/`；
- 原始题面和附件会复制到每个 Worker 的独立目录。

这些目录默认不提交到 Git。发 issue、截图或公开日志前，应删除附件、flag、
Cookie、Token、内网地址和个人路径。

服务只绑定 `127.0.0.1`，但命令执行能力仍应视为高权限功能。不要把服务反向代理
到公网，也不要关闭 API token 校验。

## 8. 常见问题

### WSL 报 `HCS_E_SERVICE_NOT_AVAILABLE`

通常是 `VirtualMachinePlatform` 或 WSL 可选组件被关闭。管理员执行：

```powershell
wsl.exe --install --no-distribution
```

重启后验证：

```powershell
wsl.exe -d ctf-kali -- echo WSL_OK
```

不要为了修复 WSL 删除发行版或 `.vhdx` 文件。

### Codex 显示不可用

```powershell
codex --version
codex login
```

如果 CLI 不在 `PATH`，可在启动 Studio 前修正 `PATH`。当前状态检测仍可能寻找
Codex 的默认安装位置，非 Codex 用户应按第 5 节替换。

### 语料显示未就绪

运行：

```powershell
pwsh -File scripts\fetch-knowledge.ps1
pwsh -File scripts\verify-knowledge.ps1
```

### 端口被占用

```powershell
bin\ctf-studio.cmd --port 8788
```

### 原生窗口无法启动

确认 WebView2 Runtime 已安装，并重新构建：

```powershell
pwsh -File scripts\build-desktop.ps1
```

## 9. 许可证

本项目使用 AGPL-3.0。通过网络向其他用户提供修改后的服务时，应遵守 AGPL 的源码
提供义务。第三方工具、语料、Docker 镜像和模型客户端仍分别受自己的许可证约束。
