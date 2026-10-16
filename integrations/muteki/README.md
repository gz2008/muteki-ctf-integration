# 给 Project Muteki 的 CTF 集成补丁

这份补丁把本仓库的工具、语料和方法论，接进
[Project Muteki](https://github.com/FishCodeTech/muteki) 的多 agent 协同链路。

## Muteki 的协同是什么

一个 Coordinator 把同一道题派给多个**异构** Agent 引擎（Claude Code、Codex、
Cursor、Pi、OMP、Kimi、Grok、OpenCode）竞速。它们通过一个洞察总线交换三类消息：
已确认的事实（`FactDiscovered`）、被排除的路径（`DeadEndMarked`）、以及第一个有效
flag（`FlagFound`，触发全场取消）。设计上**只共享已验证的客观事实，不共享猜测或
计划**——因为共享猜测会把整个 swarm 带偏到某个 solver 的错误想法上。默认的
`fixed` 调度模式，就是让所有选中的 worker 一起进第一轮 Race。

上游源码里有一句自我定位值得引用：*the real edge is per-Solver cognition, not the
racing harness*（真正的优势在单个 solver 的认知，不在竞速框架）。这正是这份补丁的
着眼点。

## 补丁做了什么

| 文件 | 改动 |
|---|---|
| `muteki/solver/worker_skills.py` | 新增 `stage_ctf_playbook_skill()`：把 CTF Playbook 投影进每个 CTF worker 的工作目录 |
| `muteki/solver/ctf_taxonomy.py`（新） | 把仓库里原本无人引用的六份分类文件，转成 worker 可见的动作先验 |
| `muteki/swarm/coordinator_dispatch.py` | 把题目 `category` 传进 reason 层，让协调层知道面对的是哪类题 |
| `muteki/solver/reason.py`、`cli_prompts.py`、`cli_process.py` | 提示与推理层适配 |
| `muteki/capability_management.py`、`apps/web/capability_management_api.py` | 能力开关 |
| `skills/muteki-ctf-local-playbook/**` | Playbook 本体（六类方法论） |

一个设计取舍值得说明：Playbook 做成**参考型 Skill 而不是塞进 prompt**——worker 只在
需要时打开 `SKILL.md` 和至多一个 `references/<category>.md`，所以每步 prompt 的体积
不随方法论增长。渗透测试模式的 worker 被显式跳过（它们有自己的指引）。

## 应用

```bash
git clone https://github.com/FishCodeTech/muteki.git
cd muteki
git apply /path/to/muteki-ctf-playbook.patch
```

补丁基于上游 **v0.4.5**（`144df76`），已在纯净的上游代码树上 `git apply --check` 通过。
上游版本变化后，上下文可能需要手动调整。

配套的 Playbook 文本也在本仓库的 `skills/muteki-ctf-local-playbook/`，与补丁内容一致。

## 运行条件（实测，避免重复踩坑）

1. **不能在 Windows 原生运行。** 后端 `import fcntl`（Unix 专有模块）直接失败，进程以
   `status 1` 退出——这不是配置问题。官方 README 给 Windows 用户的指引同样是让 Muteki
   与 Workers 跑在 Ubuntu 里。
2. **Worker 必须是一个已登录的 agent CLI。** 实测 `ctf-kali` 与 `Ubuntu` 两个 WSL
   发行版里 `uv` / `codex` / `claude` / `node` / `npm` 全都不存在；先装好 CLI 并完成
   登录，`uv sync` 才有意义。
3. Planner 另需一个可用的模型端点。

## 验证状态

`checks/` 下是四项功能检查，当前全部通过：工具索引注入、分类先验下发、reason 层先验、
以及 Playbook staging（含 prompt 体积与桌面运行时片段可编译）。

```bash
PYTHONPATH=/path/to/muteki python checks/muteki_tool_index_check.py
```

**未验证的部分**：多个 worker 协同解题的端到端效果。上面三个运行条件尚未同时满足，
所以协同带来的增量（解出率、耗时、token 成本）目前没有数据。上游 README 自述的战绩
（RIFFHACK 2026 三小时无人干预解出全部题目并获第 8 名、NYU CTF Bench 200/200）是官方
数据，本仓库不把它当作自己的测量结果。
