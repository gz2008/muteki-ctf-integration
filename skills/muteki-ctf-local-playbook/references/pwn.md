# Pwn

## 1. Triage the binary and the protocol

```bash
file ./chall; checksec --file=./chall
readelf -h ./chall | head -20; readelf -d ./chall | rg -i 'bind_now|now'
strings -a -n 6 ./chall | rg -i 'flag|/bin/sh|system|win'
ldd ./chall; ./chall          # learn the exact I/O protocol before anything else
```

Do not write an exploit before you know: how input is read (line/raw/length),
what is printed back, and whether it loops or exits.

## 2. Protection matrix to exploitation path

| Protections | First path to try |
| --- | --- |
| NX disabled | shellcode on stack/heap, jump to buffer |
| No PIE, no canary, NX on | ret2win / ret2plt, plain ROP |
| Canary | leak it (format string, `puts` of adjacent data, off-by-one) before overflow |
| PIE | leak code base first (GOT read, format string, partial overwrite) |
| Partial RELRO | GOT overwrite (`printf@got` -> `system`) |
| Full RELRO | GOT readonly: ret2libc, `one_gadget`, or FSOP/exit handlers on modern glibc |
| Static binary | `ROPgadget --binary ./chall`, syscall gadgets, `read(0, bss)` staging |
| seccomp | `seccomp-tools dump ./chall`, then ORW ROP chain instead of `execve` |

## 3. Offset and primitive discovery

```bash
python3 -c "from pwn import *; print(cyclic(200))" | ./chall        # find crash offset
gdb -q ./chall -ex 'run < payload' -ex 'info registers' -ex 'bt'
r2 -A ./chall -c 'afl; pdf @ main; iz' ; objdump -d -M intel ./chall | head -100
checksec --file=./chall; one_gadget ./libc.so.6
```

Workflow order that saves time: identify the bug class (`objdump`/decompiler on
the parse function) -> find the offset with `cyclic` -> build the minimal
control-flow proof (crash with `0x41414141` in `RIP`) -> then spend the exploit
effort.

## 4. Leaks, libc and chains

- Identify the remote libc before assuming offsets: leak a GOT entry via
  `puts`/`printf`, then resolve with a libc database; use the challenge's own
  `libc.so.6` when supplied (`./libc.so.6` prints its version).
- `libc_base = leaked_address - symbol_offset`; then `system`, `/bin/sh`, and
  gadgets come from the same libc.
- `one_gadget ./libc.so.6` gives single-gadget shortcuts; the constraints are
  real — check them in gdb, do not assume they hold.
- Format string: find the argument offset with `AAAA.%p.%p...` or `%6$p`,
  read with `%s` on a pointer you control, write with `%hn` split half-words.
- Heap (older glibc): tcache/fastbin dup and poisoning, unsorted-bin libc leak,
  `__free_hook`/`__malloc_hook` overwrite. glibc 2.32+ adds safe-linking (you
  need a heap leak to forge pointers); 2.34+ removes the hooks, so plan FSOP or
  a `_IO`/exit-handler target instead.

pwntools skeleton to adapt (keep the local/remote switch so the same script
validates both):

```python
from pwn import *
context.binary = elf = ELF('./chall'); libc = ELF('./libc.so.6')
p = process('./chall') if not args.REMOTE else remote('host', 1337)
p.recvuntil(b'> ')
p.sendline(payload_stage1)
leak = u64(p.recvline().strip().ljust(8, b'\x00'))
libc.address = leak - libc.sym['puts']
```

## 5. Remote-specific behaviour

- ASLR means a leak from one connection is void on the next: leak and use the
  same connection.
- Confirm the remote libc/build matches your local assumption (a wrong libc
  offset is the most common "exploit suddenly fails" cause).
- Set a timeout and handle EOF; print raw bytes hex when a stage fails instead
  of guessing the protocol.

## 6. Pitfalls

- Exploiting before confirming the offset.
- Assuming `system("/bin/sh")` when seccomp blocks `execve` — check first.
- Forgetting `.recvuntil` alignment, or `sendline` versus `send` for raw reads.
- Losing the leaked value by opening a second connection.

## Publish as Fact

File hash/protections, the bug class with the responsible function and offset,
the crash control proof (register value), the leak path with its value, and a
path to the exploit script in `shared/`.
