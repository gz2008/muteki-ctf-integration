# Muteki CTF Integration

> 英文完整版（含全部工程记录与实测数据）：[README_EN.md](README_EN.md)

一个**离线优先的 CTF 工具链**：一条命令做完开场情报、用文件格式自身的校验来判定
抓包分析结果、九套钉死 commit 的离线语料、支持中文的排序检索，以及一套**先审计
题目、再测量 agent** 的基准。

它可以独立使用；也可以作为
[Project Muteki](https://github.com/FishCodeTech/muteki) 的本地工具根接进去，
让 Muteki 的 Worker 通过 `./toolbox` 拿到同一套工具和语料。

许可证：AGPL-3.0（见 `LICENSE`）。**第三方语料不在本仓库内重新分发**，而是按
钉死的 commit 从各自上游拉取。

## 你会得到什么

**五个入口，覆盖一道题里"机械"的那一半工作。**

- **`ctf-triage`** — 一次调用替代开场的前五到十次工具往返：文件类型、熵、嵌入
  对象、归档内容、ELF 保护、PE 事实、图片尺寸、值得一看的字符串，并为每一种
  检测到的类型列出"接下来值得跑的命令"。
- **`ctf-net`** — 把抓包变成结构：按序列号重组 TCP、从重复的 magic 值与固定间
  距识别应用层帧、从格式必然存在的明文反推 XOR 填充，并且**只有通过格式自身
  校验**的 carve 结果才被接受。
- **`ctf-repair`** — 定位并修复一个错误/多余/缺失的字节，每个候选都由格式自身
  的校验来判分，而不是按"看起来合理"。找不到单字节修复时会直接说明。
- **`ctf-corpus` / `ctf-index`** — 离线语料的 ripgrep 直搜与 BM25 排序检索，支
  持中文，所以中文的 `ctf-wiki` 也能搜。
- **`ctf-linux`** — 在 WSL/Kali 里执行命令，并把钉死的工具链挂上 `PATH`。在
  Windows 上，这是真正运行一个 Linux ELF 的唯一通道。

**约 1.4 GB 离线语料**，九个来源，每个都钉死 commit 并在
`locks/knowledge-sources.json` 里记录许可：hacktricks、hacktricks-cloud、
ctf-wiki、PayloadsAllTheThings、InternalAllTheThings、how2heap、vulhub、
Awesome-POC、nuclei-templates，外加 Kali 的 SecLists 与 rockyou。

**约 1800 个工具入口**：checksec、gdb、ghidra、radare2、angr、jadx、vol3、
hashcat、john、nuclei、tshark、binwalk、stegseek、sage、ropper、one_gadget、
pwntools 等。

**一套先审计题目、再测量 agent 的基准**：`verify-bench.ps1` 会先证明每道题都能
被它自己的参考答案解出、且准备给 agent 的工作目录里没有任何明文 flag，因此结
果不会被一道坏题或泄题悄悄作废。

## 多 agent 协同集成

这套工具链可以独立用，也可以接进
[Project Muteki](https://github.com/FishCodeTech/muteki) 的多 agent 协同：一个
Coordinator 让多个**异构** Agent 引擎（Claude Code、Codex、Cursor、Pi、OMP、
Kimi、Grok、OpenCode）竞速解同一道题，通过一个**只共享已验证事实、不共享猜测**的
总线协作；谁先产出可验证且格式正确的 flag 谁赢，其余立即取消。

`integrations/muteki/` 里是给 Muteki 的补丁——把本仓库的工具索引、分类先验和
Playbook 送进每个 worker 的可见范围。改动清单、应用方式，以及**实测到的运行条件**
（Windows 原生跑不起来、Worker 必须是一个已登录的 agent CLI）都写在
[integrations/muteki/README.md](integrations/muteki/README.md)。

需要说明的是：补丁本身通过四项功能检查，但**"多个 worker 协同解题"的端到端效果我
没有验证过**，原因就写在那份文档里，没有数据我不编。

## 特色

1. **判定来自文件格式，而不是模式匹配。** 两个字节的 magic 可以通过挑选填充凑
   出大量"命中"；这里的候选是按**走通格式真实结构的程度**排序的。在那个卡住过
   三轮的抓包上，它报出 688 个候选命中、其中恰好 1 个推进到了结构性里程碑。
2. **把往返次数当作成本。** 每次工具调用都要驱动者花时间读输出再决策，无论驱
   动者是人还是 agent。`ctf-triage` 的存在就是为了把五到十次调用压成一次，并顺
   带告诉你下一步该跑什么。
3. **宁可报"无法判定"，也不猜。** 跑不了的检查会被报成"尚未测量"，绝不会被当
   成"文件里没有"。
4. **核心分析器只用 Python 标准库。** 在拒绝启动 WSL 的沙箱里它们照常可用——而
   沙箱恰恰是抓包最需要被分析的地方。
5. **边界写在明处。** 做不到的事和做得到的事并排写在一起。

## 平台

| 平台 | 可用范围 |
|---|---|
| Windows 10/11 + WSL2 | 全部功能，包括 `bin\*.cmd` 入口与 `ctf-linux` |
| Linux / macOS | Python 分析器、bash 脚本、语料与检索；Windows 专属入口在 `scripts/` 下有对应的 bash 版本 |

三个分析器除 Python 3 外不需要任何依赖。Windows 入口内含 Windows 专用的路径处
理，因此请把这个仓库当作**以 Windows 为主**。

## 快速开始

```powershell
git clone https://github.com/gz2008/muteki-ctf-integration.git
cd muteki-ctf-integration

# 拉取九套钉死的语料并链接字典（约 1.4 GB，支持断点续传）
pwsh -File scripts\fetch-knowledge.ps1
pwsh -File scripts\verify-knowledge.ps1

# 对任意题目目录试用
bin\ctf-triage.cmd .\some-challenge
```

## 仓库结构

| 路径 | 内容 |
|---|---|
| `scripts/` | 分析器、语料拉取、索引、基准与校验脚本 |
| `bin/` | Windows 入口（`*.cmd` 及其调用的 PowerShell 脚本） |
| `locks/` | 钉死的来源清单，含 commit 与许可 |
| `skills/` | 面向 agent 的分类路由 CTF Playbook |
| `skill/` | 集成工作流的 Codex skill 包 |
| `integrations/` | 给 Project Muteki 的多 agent 协同补丁与说明 |

## 工程记录

[README_EN.md](README_EN.md) 的后半部分是完整的工程记录：测了什么、哪些设计选择
是被实测逼出来的、哪些失败模式是踩过坑才发现的。关心维护或想核实可信度的人可以
看那部分。
