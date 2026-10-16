# Reverse

## 1. Identify what you are actually looking at

```bash
file ./chall; strings -a -n 6 ./chall | head -60
exiftool ./chall; binwalk ./chall
go version -m ./chall 2>/dev/null        # Go build info
```

Language/toolchain fingerprints that decide the workflow:

| Fingerprint | Workflow |
| --- | --- |
| Go build info, large static binary | symbols usually intact: `go tool objdump`, `r2`, string-driven |
| Rust panic strings (`panicked at`) | symbols frequently stripped; focus on string xrefs and data flow |
| `.NET` (`dnfile`, `mscoree`) | `ilspycmd`/dnSpy decompile to near-source |
| Java jar/class | `jar tf`, `jadx`, `cfr` |
| PyInstaller / `.pyc` | `pyinstxtractor` then `pycdc`/`decompyle3`; match the Python version |
| Android APK | `apktool d`, `jadx -d`, check native `.so` too |
| WASM | `wasm2wat`, `wasm-decompile` |
| Clear UPX marker / high entropy sections | `upx -d` first, else unpack manually |

## 2. Static pass

```bash
r2 -A ./chall -c 'afl; s main; pdf; izz'
ghidraRun            # or analyzeHeadless for scripted decompilation
objdump -d -M intel ./chall | less
```

Read the comparison that decides "correct/wrong": trace back from
`strcmp`/`memcmp`/`strncmp`, note the transform applied to the input, then
decide whether the transform is invertible (write the inverse) or satisfiable
(hand it to z3).

For stripped binaries, locate `main` through `__libc_start_main`'s first
argument, or start from `write`/`puts` xrefs and walk backwards to the caller.

## 3. Dynamic pass

```bash
ltrace -s 200 ./chall ; strace -f -s 200 ./chall
gdb -q ./chall -ex 'break strcmp' -ex 'run' -ex 'x/s $rdi' -ex 'x/s $rsi'
LD_PRELOAD=./hook.so ./chall       # hook the comparison and dump both operands
python3 -c "import angr; p=angr.Project('./chall'); ..."    # symbolic find/avoid
```

Dynamic beats static when: the algorithm is long, the binary self-modifies, or
the checker runs a large loop. Symbolic execution (angr) is the right tool when
the check is branchy with few variables — keep the find/avoid addresses tight,
it is slow when over-constrained.

Anti-analysis handling: single-step past `ptrace(PTRACE_TRACEME)` checks, patch
the anti-debug branch, or skip the timing loop. Note that a patched local copy
is evidence about your copy, not about the original — verify the flag against
the original if the environment allows.

## 4. Common patterns and their inverse

- Byte-wise XOR with a fixed or derived key: recover the key from a
  known-plaintext region (e.g. the flag prefix).
- Compare-after-transform: invert the transform (`z3` if it is bit-twiddling
  with mixed arithmetic).
- Multi-stage: a first input unlocks a second check; dump each stage's expected
  value rather than reconstructing by hand.
- "Key" derived from input: feed a self-consistent input, or symbolically solve
  for a satisfying assignment instead of a fixed answer.
- Embedded data: appended archives, an encrypted blob decrypted with a literal
  key inside the binary (`strings` first, then xrefs to the literal).

## 5. Pitfalls

- Treating `strings` output as an answer; it usually shows the *hint*, not the
  flag (or it shows a decoy).
- Assuming packer/obfuscation when the binary is simply stripped.
- Running someone else's solver on a different version/build of the challenge.
- Forgetting that a `.pyc`/jar may contain a second stage in a resource file.

## Publish as Fact

Toolchain/version, the responsible function or comparison, the recovered
transform (as an equation or pseudocode), the input that passes, and the exact
bytes of the artifact you recovered.
