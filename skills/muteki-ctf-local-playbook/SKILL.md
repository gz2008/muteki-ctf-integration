---
name: muteki-ctf-local-playbook
description: >
  Category-routed black-box CTF methodology playbook for the standard
  categories (web, pwn, reverse, crypto, forensics, misc). Use at the start of
  a CTF Step to choose one bounded first direction and the right tool, and when
  a direction stalls to pick the next falsifiable experiment. Read the matching
  references/<category>.md before a long tool run.
---

# CTF playbook (methodology, never answers)

This Skill carries method, not solutions. It says which observation separates
two hypotheses and which command produces that observation.

## Hard rules

1. Read the team graph first. Check the initial prompt, `shared/`, and open
   tmux windows before re-running anything.
2. Every claim cites real output from a command you ran in this Step. A guess,
   a remembered technique, or a plausible-looking value is not a Fact.
3. Drive ONE direction until it produces a recoverable artifact (a file, a
   value, a working primitive) or is ruled out. Breadth-first tool spam
   destroys the team's information budget.
4. Keep large blobs in files (`shared/`, current cwd); cite paths, not pastes.
5. Prefer the cheapest falsifiable test. A 3-second timing canary beats a
   10-minute automated scan for the same hypothesis.
6. A flag is submitted only as the exact bytes that appeared in real output.
   Never reconstruct a flag from a format hint.
7. When a bounded direction is excluded, record it with `mark-deadend`
   (tested scope + observed result) so no other Worker pays that cost again.

## Sixty-second triage

One command performs the whole inventory - types, entropy, embedded objects,
archive contents, protections, flagged strings - and prints the next commands
that are worth running for each detected type. Run it before choosing anything:

```bash
./toolbox/bin/ctf-triage .
```

When `./toolbox` is absent, look for `.tools/` in the working directory - the
same helpers are usually copied there as stdlib-only python:

```bash
python .tools/ctf-triage.py .
python .tools/ctf-net.py CAPTURE.pcap --out carved
python .tools/ctf-repair.py DAMAGED.png --write fixed.png
```

Stay inside the working directory: challenge directories are sometimes nested
inside the harness that grades them, and reading the harness invalidates the
result even when it makes the challenge easier. If neither `./toolbox` nor
`.tools/` exists, fall back to the manual commands in `references/<category>.md`.

Use `--json` when you want to feed the result to another step. The report never
guesses: a check it could not run is reported as unavailable rather than
assumed, so treat an absent fact as "not yet measured", not as "absent in the
file".

Then answer: what single observation would most reduce uncertainty? That is the
Step, not "explore the challenge".

| Observation | Category | Reference |
| --- | --- | --- |
| URL, port, source files, cookies, API doc | web | `references/web.md` |
| ELF/PE with an input protocol, `checksec` output | pwn | `references/pwn.md` |
| "Enter the key", crackme, packed or obfuscated binary | reverse | `references/reverse.md` |
| Parameters, modulus, key exchange, ciphertext-only | crypto | `references/crypto.md` |
| pcap, disk image, memory dump, image, audio, archive | forensics | `references/forensics.md` |
| Jail, esolang, encoding chain, checker script, service bot | misc | `references/misc.md` |

When the category is genuinely two-way, test the cheaper one to a decision
point (one request or one command) before switching. Do not pre-load two
references into context.

`references/category-prior.md`, when present, is generated from the repository
taxonomy for this challenge's category: it lists the cheapest falsifiable moves
first, the moves that need evidence before escalating, and the state that marks
completion. Treat it as vocabulary and ordering, never as evidence.

## Tool readiness

Never assume a tool exists. Two commands settle it, and they are cheap:

```bash
command -v sqlmap tshark pwntools vol3 r2 gdb 2>/dev/null
<tool> --help | head -20
```

Kali full Worker images also ship offline knowledge at
`/home/kali/knowledges` (PayloadsAllTheThings, HackTricks) and PoCs at
`/home/kali/pocs`; a targeted `rg` there is faster than browsing the web.
Missing dependency: report it as an environment fact instead of silently
changing approach. Do not install packages mid-Step unless the Step is blocked
without them.

When the challenge directory exposes an offline corpus (a local Worker mounts
it as `./toolbox`), search it before reaching for the web:

```bash
./toolbox/bin/ctf-corpus -c pwn "tcache.*poison"      # regex, you know the keyword
./toolbox/bin/ctf-index "how is house of einherjar set up"   # rank, you know the symptom
```

`ctf-corpus` lists its category aliases with `-l`; `ctf-index` covers the prose
corpora only and returns ranked passages with file paths. Both are read-only
lookups — cite the path and line you used as evidence, and never paste a
payload from the corpus as if it were an observation about the target.

## Quick starts

Each quick start is the first bounded experiment, not the whole category. Load
the reference file for the decision tree.

- **web**: fingerprint (`whatweb`, response headers, `robots.txt`), enumerate
  content (`ffuf`/`gobuster` with a small list first), then map every
  model-controlled input (param, header, cookie, path segment, file upload).
  Prove one injection class manually before handing it to an automated tool.
- **pwn**: `checksec`, `file`, `readelf -h`, `strings | rg -i 'flag|sh'`, then
  run it locally and capture the exact I/O protocol before writing any exploit.
- **reverse**: `file`, `strings -a -n 6`, identify language/packer, then decide
  static (r2/ghidra) versus dynamic (gdb/ltrace) versus symbolic (angr/z3).
- **crypto**: separate container/encoding from the actual cryptographic
  payload, identify the primitive, then attack the *documented* weakness —
  parameter reuse, small exponent, nonce reuse, ECB structure.
- **forensics**: identify the true container (`file`, `binwalk`), extract to
  files, then search the extraction tree for keys, credentials and
  flag-shaped strings.
- **misc**: identify the encoding layer by layer (`CyberChef magic` is one
  experiment, not an answer), or read the checker/jail source and enumerate
  what the input still permits.

## When a direction stalls

Escalate the class of experiment, not the volume:

1. Re-read the challenge text and the initial graph projection for a constraint
   you ignored (format hint, length, alphabet, protocol).
2. Re-check the last assumption with an independent tool (different parser,
   different decoder, hexdump by hand).
3. Narrow the search: pin versions, fix one variable, use known-plaintext at a
   named offset.
4. Run an ablation: change exactly one input and compare the response bytes.
5. Only then automate or brute force — with a stop condition and a log file.

Signs to stop and hand off: identical output for three different hypotheses,
a tool error treated as a negative result, or a direction whose next step costs
more than the remaining time budget.

## Handoff

Publish the increment, not the story: what was observed, when, in what context,
what still is not verified, and how a later Worker continues from here
(command, file path, session name, health check). Put the flag in
`submit-flag` and the reusable primitive in `submit-fact`, then `commit-step`.
