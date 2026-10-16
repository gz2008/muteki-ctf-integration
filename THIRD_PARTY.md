# Third-Party Sources and Licenses

The integration references the tools and corpora below. Each source keeps its own
license; nothing here is relicensed, and no third-party text is vendored into the
AGPL-3.0 muteki repository.

## Offline corpora (locks/knowledge-sources.json)

| Target | Source | License | Notes |
|---|---|---|---|
| `knowledges/PayloadsAllTheThings` | swisskyrepo/PayloadsAllTheThings | MIT | payload and technique reference |
| `knowledges/InternalAllTheThings` | swisskyrepo/InternalAllTheThings | NOASSERTION | local use only |
| `knowledges/hacktricks` | HackTricks-wiki/hacktricks | NOASSERTION | local use only |
| `knowledges/hacktricks-cloud` | HackTricks-wiki/hacktricks-cloud | NOASSERTION | local use only |
| `knowledges/how2heap` | shellphish/how2heap | MIT | heap exploitation techniques |
| `pocs/vulhub` | vulhub/vulhub | MIT | reproducible vulnerability labs |
| `pocs/Awesome-POC` | Threekiii/Awesome-POC | NOASSERTION | Chinese PoC index, local use only |
| `knowledges/ctf-wiki` | ctf-wiki/ctf-wiki | CC-BY-NC-SA-4.0 | Chinese CTF wiki; non-commercial, local use only, never copied into the repository |
| `nuclei-templates` | projectdiscovery/nuclei-templates | MIT | scanner templates |

Repositories without a declared license are fetched for local, non-redistributed
use only and are marked `NOASSERTION (local use only)` in the lock file.

These corpora contain public proof-of-concept documents with embedded webshell and
exploit samples. Windows Defender flags them by signature, so
`D:\codex\output\muteki-ctf-integration` is kept in the Defender exclusion list
(see `README.md` for the removal command). Files are never executed here; they are
read offline by authorized CTF workers.

## Wordlists

| Target | Source | License |
|---|---|---|
| `wordlists/SecLists` | Kali package `seclists` inside ctf-kali (`/usr/share/seclists`) | per-package (MIT upstream) |
| `wordlists/kali/rockyou.txt` | Kali package `wordlists` inside ctf-kali | per-package |

## Runtime

| Source | Use | License |
|---|---|---|
| ctf-kali (Kali Linux 2026.2) | isolated tool runtime | per-package licenses |
| Project Muteki | worker runtime, unmodified checkout | AGPL-3.0 |

## Pinned tools (locks/tool-sources.json)

| Tool | Source | License |
|---|---|---|
| ysoserial | frohoff/ysoserial v0.0.6 release asset | MIT |
| marshalsec | RandomRobbieBF/marshalsec-jar (prebuilt, hash taken from the muteki worker Dockerfile) | MIT (mbechler/marshalsec) |
| JNDI-Injection-Exploit | welk1n/JNDI-Injection-Exploit v1.0 release asset | MIT |
| StegSolve | Giotino/stegsolve v1.4 release asset | MIT |
| evtx_dump | omerbenamram/evtx v0.12.3 release asset | Apache-2.0 |
| pwninit | io12/pwninit 3.3.3, built with cargo | MIT |
| stegoveritas | PyPI package (bannsec/stegoVeritas) | MIT |
| glibc builds | Ubuntu packages via glibc-all-in-one / Kali mirrors | GPL-2.0/LGPL-2.1 |
| libc-database offsets | niklasb/libc-database | MIT |
| Foundry | foundry-rs/foundry v1.8.5 release asset (official SHA256 asset) | MIT/Apache-2.0 |
| Chainsaw | WithSecureOpenSource/chainsaw v2.17.1 release asset | GPL-3.0 |
| Hayabusa | Yamato-Security/hayabusa v4.2.0 release asset | AGPL-3.0 |
| pycdc / pycdas | zrax/pycdc (built from source) | GPL-3.0 |
| .NET SDK 8.0.424 + ilspycmd 9.1.0.7988 | Microsoft builds feed + NuGet, pins copied from the muteki worker Dockerfile | MIT |
| jadx, apktool, dex2jar, aapt, apksigner, adb, wpscan, ncat, clang, cmake | Kali packages | per-package |
| semgrep, slither-analyzer, vyper, uncompyle6, decompyle3, pyinstaller, stegoveritas | PyPI packages | MIT / GPL-3.0 / LGPL-2.1 |
| chisel target binaries | jpillora/chisel v1.12.0 release assets | MIT |
| gqrx-sdr, openocd, pulseview, sigrok, rtl-433, gnuradio | Kali packages | GPL-2.0/GPL-3.0 |
| cloudfox | BishopFox/cloudfox v2.0.5 release asset (official SHA256) | MIT |
| pacu, scoutsuite, prowler, cloudsplaining, certipy-ad, pyocd, unblob, pymodbus | PyPI packages | Apache-2.0 / GPL-3.0 / BSD |
| bkcrack | kimci86/bkcrack v1.8.1 release asset (SHA256 recorded in the lock) | zlib |
| CFR 0.152 | Maven Central `org.benf:cfr` (jar only, no build step) | MIT |
| tesseract-ocr, wabt, yq, sqlite3, tftp-hpa | Kali packages | Apache-2.0 / MIT / public domain / BSD |
| smbclient (samba), smbmap, netexec | Kali packages | GPL-3.0 / GPL-3.0 / BSD-2-Clause |
| multimon-ng, gmp-ecm, testdisk-photorec | Kali packages | GPL-2.0 / LGPL-3.0 / GPL-2.0 |
| volatility3 | PyPI package (VSL-1.0, not an OSI licence - review before redistribution) | Volatility Software License |
| fpylll, cysignals, regipy, dnfile, csvkit, pycryptodomex, hashpumpy | PyPI packages | GPL-2.0+ / GPL-3.0 / MIT / MIT / MIT / public domain+BSD / MIT |
| detect-it-easy (`diec`) | Kali package | MIT |
| kerbrute | ropnop/kerbrute v1.0.3 release asset (SHA256 in the lock) | Apache-2.0 |
| OpenStego 0.8.6 | syvaidya/openstego release asset, jar extracted (SHA256 in the lock) | Apache-2.0 |
| pypykatz, pefile, vmlinux-to-elf, apkleaks | PyPI packages | MIT / MIT / MIT / Apache-2.0 |

Registered asset/cargo/pip pins, including SHA256 for every downloaded asset,
live in `locks/tool-sources.json`; `scripts/provision-tool-gaps.sh check` and
`scripts/verify-tools.ps1` re-verify them.

`garak` and `pyrit` are intentionally not installed: the LLM-security stack pulls
the full torch/transformers tree, which is disproportionate for the classic
categories and destabilises the shared `core` venv. The lock file records them
under `skipped` with the reason, so the omission is deliberate and reviewable
rather than an unrecorded gap.

Re-run `scripts/fetch-knowledge.ps1` to refresh a pinned commit; the archive under
`archives/knowledge/` keeps the exact bytes used for a run.
