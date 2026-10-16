# Misc

## 1. Identify the layer stack

Most misc challenges are layers, not puzzles: encoding over encoding, or a
restricted interpreter. Remove one layer at a time and say which layer you
removed.

```bash
file ./artifact; xxd -l 256 ./artifact
python3 -c "import base64;print(base64.b64decode(open('c.txt').read()))"
```

Candidate layers: base16/32/58/64/85/91, hex, URL/HTML entities, gzip/zlib
wrapped text, Morse, Bacon, A1Z26, Braille, ROT, "keyboard shift", emoji or
symbol alphabets, tap code, book cipher, DNA codons, and esolangs
(Whitespace, Ook, Brainfuck, JSFuck, Piet, Malbolge).

Escalating from decoding to interpretation: if the text is a program in an
esoteric language, run the interpreter instead of decoding by hand.

If the bytes look random rather than encoded, stop guessing keys and derive the
pad from plaintext the format forces to be present:

```bash
ctf-xor artifact.bin                    # assume a common magic at offset 0
ctf-xor artifact.bin --known 504b0304   # e.g. you know a ZIP local header
```

A repeating 2-byte pad is common in game/CTF transports; a checksum match (PNG
chunk CRC, zlib, ZIP CRC) is what turns a candidate key into a fact.

## 2. Restricted interpreters (jails)

Work out what is blocked, then what is still reachable. Enumerate, do not guess:

```python
# Python jail: list the surviving names and the import machinery
print([n for n in dir(__builtins__) if not n.startswith('_')])
print(type(__import__('os').system))
```

Recovery patterns:

- Python: `__builtins__` via `().__class__.__base__.__subclasses__()`, reach
  `os.system`/`subprocess.Popen`/`open`, or `breakpoint()` / `help()` when
  audit hooks are absent. Filters on substrings are beaten by
  `getattr(__builtins__, 'ev'+'al')`, `%c` formatting, or unicode escapes —
  but confirm each bypass with a real run.
- Bash restricted shell: `${PATH:0:1}`, `$'\x2f'`, command substitution,
  `printf` to build strings, `read`/`exec` redirection, environment variables
  set by the wrapper.
- PHP: `preg_replace` with `/e` (legacy), `assert`, `create_function`,
  variable functions, `$GLOBALS`, object injection into magic methods.
- SQL jail: `information_schema` discovery, `LOAD_FILE`, stacked queries when
  the driver allows them.
- Rule: read the filter source if it is given. Never assume a filter's coverage.

## 3. Programming and service challenges

- Read the protocol by connecting once (`nc`), then write the solver; keep it in
  `shared/` so a later Worker can re-run it.
- Time limits: parallelise requests, precompute, and buffer output. Print raw
  bytes when a parse fails.
- Interview-style tasks (constrained puzzles, "answer N questions in T
  seconds"): solve in code, verify against the checker locally when a checker
  script is provided.

## 4. Files, formats and OSINT-adjacent data

- Barcodes/QR: `zbarimg`, then OCR (`tesseract`) for anything text-like. OCR
  fails on small text: upscale first (`magick in.png -resize 400% -colorspace
  Gray -threshold 50% big.png`) and OCR that. Two measured runs of the same
  string: ~11 px font gave `ftagl0cr_1ad5_1mag3sl`, 34 px gave the exact flag.
- Structured dumps: `jq`/`yq`/`sqlite3`/`csvkit` beat manual reading.
- Weird sizes/headers: `binwalk`, `truncate`/`dd` at the reported offset,
  `dd if=file bs=1 skip=N count=M`.
- Unicode weirdness: check for zero-width characters, homoglyphs, RTL overrides
  (`python3 -c "print([hex(ord(c)) for c in open('f').read()])"`).
- Blockchains: replay the challenge's transactions, read the contract storage,
  and confirm the state change rather than trusting the description.

## 5. Pitfalls

- Trying randomness: if a decode chain needs guessing, the intended hint is
  usually in the challenge text, a filename, or a header value.
- Hand-decoding a 5 kB blob instead of writing 10 lines of Python.
- Running an untrusted binary from the challenge outside the sandbox you were
  given, or on the host instead of the target.
- Assuming a jail escape that was never executed: run it, print the output.

## Publish as Fact

The layer or filter model you established, the exact commands and their output,
the artifact path in `shared/`, and what remains unverified in the chain.
