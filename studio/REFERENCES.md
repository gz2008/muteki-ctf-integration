# GitHub 参考项目

调研时间：2026-10-18。用 GitHub API 搜索了 `ctf gui`、`ctf workbench`、`ctf toolkit`、`ctf agent llm` 等关键词，并读了下列项目的 README。这里记录的是**借鉴点**，不是代码来源；本仓库没有复制它们的源码或语料。

## 直接借鉴

| 项目 | 星标* | 许可 | 借鉴点 | 没有照搬的部分 |
| --- | ---: | --- | --- | --- |
| [CyberChef](https://github.com/gchq/CyberChef) | 36k | Apache-2.0 | 输入 / 配方 / 输出三栏，Magic 自动识别 | 没有打包整个 CyberChef；实现了一个离线 mini 变换台 |
| [CTFCrackTools X](https://github.com/0Chencc/CTFCrackTools) | 2.1k | GPL-3.0 | 可组合的节点化处理流程 | 用线性 recipe 代替完整节点画布 |
| [CTFever](https://github.com/HoshinoSuzumi/CTFever) | 925 | GPL-3.0 | 按题型分类的工具目录 | 没有复刻它的全部在线工具 |
| [CaptfEncoder](https://github.com/guyoung/CaptfEncoder) | 1.3k | MIT | 编码 / 古典密码 / 杂项的分类方式 | 没有引入 Rust 桌面端 |
| [CTF-Boom](https://github.com/wbw16/CTF-Boom) | 4 | Apache-2.0 | 候选 Flag 生命周期、证据留痕、任务工作区 | 没有接入它的模型 Provider / Bun 运行时 |
| [Triage](https://github.com/0-Bobo/Triage) | 1 | MIT | 二进制侦察 + 按保护条件排序策略 | 没有复制它的反编译器；只做 checksec/readelf/strings 和策略提示 |
| [LingXi](https://github.com/adrian803/LingXi) | 40 | GPL-3.0 | Planner / Executor / Reflector、经验回放 | 没有引入 LangChain / Milvus / Kali MCP |
| [Project Muteki](https://github.com/FishCodeTech/muteki) | 上游项目 | AGPL-3.0 | 只共享已验证事实的蜂群总线 | GUI 不复制 Muteki 前端；通过 `/api/runs` + SSE 适配 |

\* 星标只是调研时的量级参考，会变化。

## 还看过但本轮没接

| 项目 | 为什么没接 |
| --- | --- |
| [stego-toolkit](https://github.com/DominicBreuker/stego-toolkit) | 工具已通过 `zsteg` / `stegseek` / `binwalk` 进入 Kali 通道 |
| [VolatilityPro](https://github.com/Tokeii0/VolatilityPro) | 内存取证用 `vol3` 命令即可；GUI 另起一轮 |
| [hyperpwn](https://github.com/bet4it/hyperpwn) | GDB GUI 与终端控制台重叠，先保留 `gdb` / `pwndbg` 命令路线 |
| [MTP](https://github.com/CameronLonsdale/MTP) | Many-Time Pad 交互很好，但属于 crypto 专项；可以后续做成 recipe |
| [CTF-Boom](https://github.com/wbw16/CTF-Boom) | 功能面很大，本轮只借了证据/候选 Flag 模型 |

## 结论

最值得借的不是“再做一个工具箱”，而是三件事：

1. **配方化**：让操作可以串联、回退、复用，而不是每次从菜单重新点。
2. **证据化**：候选 Flag 和已验证 Flag 必须分开，驳回也要留痕。
3. **计划化**：二进制/Web 题先给排序后的下一手，而不是把 1800 个工具列给用户。

这三条已经落到 `server.py` 的 facts / actions / flags 模型和前端三个面板里。
