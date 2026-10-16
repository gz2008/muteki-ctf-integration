# Forensics

## 0. Inventory and carving first

```bash
file *; exiftool -a -u * | head -60            # metadata often carries the hint
binwalk -eM ./*.bin ./*.img 2>/dev/null; ls -R _*.extracted 2>/dev/null | head
foremost -i image.dd -o out; 7z l suspicious.zip
zsteg -a pic.png; pngcheck -v pic.png
```

Search the extracted tree for the payoff before going deeper:

```bash
rg -a -i 'flag|ctf|key|password|secret' . | head -30
```

## 1. Pcap / network forensics

Start with the analyser, which does the mechanical work described below in one
pass: reassembly in sequence order, frame detection (the repeated record magic
and its stride), automatic pad derivation from forced plaintext, and validation
of every carved object against its own checksum.

```bash
./toolbox/bin/ctf-net CAP --out carved/    # structure, pads, carving, honest verdict
```

It is designed to say "the pad is right and the IDAT is damaged at byte N"
rather than to produce a plausible file that does not open. Only write a parser
by hand when it reports no framing at all.

1. `file` + `capinfos` / `tshark -q -z io,phs` to confirm the capture type.
2. Conversations: `tshark -r CAP -q -z conv,tcp`.
3. Follow the brief's port (or the busiest stream):
   `tshark -r CAP -q -z follow,tcp,raw,N` and also `follow,tcp,ascii,N`.
4. Reassemble to a real file — do not stop at hex dumps: decode the hex/raw
   stream into `shared/stream0.bin`, then `file`/`strings`/`binwalk`.
5. Extract protocol objects instead of hand-carving when possible:
   `tshark -r CAP --export-objects http,out` (also `smb`, `tftp`, `imf`).
6. Custom/unknown protocols: parse length-prefixed frames in python3; carve
   embedded PE/ELF/ZIP/PNG by magic; write carved files under `shared/`.
   Frame boundaries usually repeat a magic (`07 32`) and a length field, and the
   record count is usually in the first frame - read the header layout off the
   first two frames before writing a parser.
7. Obfuscated payload inside the protocol: do not guess. Derive the pad from
   plaintext you already know or can predict:

   ```bash
   # strip the frame headers into transfer.bin, then:
   ctf-xor transfer.bin                     # tries common magics as known plaintext
   ctf-xor transfer.bin --known 89504e470d0a1a0a --write out.bin
   ```

   The pad falls straight out (`pad[i] = cipher[i] XOR known[i]`). A **2-byte
   repeating pad** is a common shape: with a NUL-padded field the raw filler
   becomes the key pair repeated (`e9 f9`, `6c 4c`), so the filler both reveals
   the pad and pins the alignment. Accept the pad only when it reproduces a
   checksum the format already carries - PNG chunk CRCs, zlib, ZIP CRCs - and
   check it against a chunk that is *not* the one you derived it from.

Specialised passes:

- DNS tunnel: `tshark -r CAP -Y dns -T fields -e dns.qry.name`, then decode the
  encoded labels (usually base32/base64/hex) in the right order.
- ICMP/payload smuggling: dump `icmp.data` fields and carve the payload.
- USB HID: `tshark -r CAP -Y 'usb.capdata' -T fields -e usb.capdata`, map key
  codes to characters (keyboard) or deltas (mouse).
- TLS: look for a key log or a supplied private key; without one, check whether
  the flag travels before the handshake (plain HTTP, FTP, DNS).
- Credentials: `tshark -r CAP -Y 'ftp || http.authorization || telnet' -T fields`.

Two failure modes here, and they are different in kind. Spraying single-byte XOR
over a payload you cannot verify is guessing, and it burns the budget - that is
forbidden. Deriving a pad from known plaintext and confirming it with the
format's own checksum is evidence, and it is expected. When a payload looks
random, confirm the reassembly and framing first, then ask what plaintext the
format *forces* to be there (magic, fixed header, CRC, padding), and derive.

A worked case: a 2015 CSAW capture carried a file transfer as 212-byte records
(`<u16 total><u16 cookie><u16 magic 0732><u16 count><u32 reserved>` + 200-byte
body) with a 2-byte alternating pad. Record 0 decoded byte-exact from the PNG
magic alone; the IDAT CRC then proved the rest of the transfer was still damaged,
which is what made the last mile a real question instead of a guess.

## 2. Memory images

```bash
vol3 -f mem.raw banners ; vol3 -f mem.raw windows.info
vol3 -f mem.raw windows.pslist | tail -20
vol3 -f mem.raw windows.cmdline windows.consoles windows.filescan | head -60
vol3 -f mem.raw windows.malfind ; vol3 -f mem.raw windows.netscan
```

Also worth two minutes: `strings -a mem.raw | rg -i 'flag\{|ctf\{'` and a
`filescan` + `dumpfiles` pass restricted to suspicious names. For Linux images
use `linux.pslist`, `linux.bash`, `linux.proc.Maps`.

## 3. Disk images

```bash
fdisk -l disk.img ; mmls disk.img
fls -r -o OFFSET disk.img | head -80 ; icat -o OFFSET disk.img INODE > out.bin
photorec disk.img          # deleted-file carving last resort
```

Then look at: deleted files, filesystem journal, `~/.bash_history`, cron,
`/etc/passwd|shadow`, browser SQLite history, SSH keys, and (Windows) registry
hives via `regipy` — registry run keys, USB history, userassist.

## 4. Stego and media

- PNG/JPEG: `zsteg -a`, `stegseek pic.jpg /usr/share/wordlists/rockyou.txt`
  (steghide), appended data after the EOF marker, EXIF/comments, chunk CRC
  mismatch, palette anomalies, bit-plane/channel separation (`magick`).
- Audio: spectrogram is usually the intended path
  (`sox in.wav -n spectrogram -o spec.png` or `audacity`), plus DTMF/SSTV via
  `multimon-ng`, and LSB in raw samples (compare with `soxi`).
- Video: frame extraction (`ffmpeg -i v.mp4 frames/%04d.png`), motion between
  frames, subtitle streams, unusual codec/data atoms.

## 5. Documents and archives

- Office: `olevba`, `msoffcrypto-tool`, unzip and read `word/document.xml`,
  look for macros and hidden sheets.
- PDF: `pdf-parser -a`, `pdfimages -all`, decompress streams (`qpdf --qdf`).
- Password-protected archive: `zip2john`/`rar2john` + `john`/`hashcat`; a
  short dictionary plus a mask is usually enough. Known-plaintext: `bkcrack`
  (`bkcrack -C archive.zip -c known.txt -p plain.txt`), which is the maintained
  descendant of pkcrack and runs on one known 12-byte plaintext region.
- Nested archives: iterate `binwalk -eM` until the recursion is stable, list
  every level before assuming it ends.

## 6. Logs and timelines

Access logs: find the anomalous request (`rg` on odd user agents, unusual paths,
HTTP 200 on a normally 403 route), reconstruct the session, and decode any
parameter that carries encoded data. Windows: `evtx_dump.py` for EVTX. Full
timeline when the question is "when": `log2timeline`/`psort`.

## 7. Pitfalls

- Overwriting the evidence: always write carved output to new files.
- Stopping at the first `binwalk` result while the flag was in the metadata.
- Reassembling only `follow,tcp,ascii` and losing binary bytes.
- Assuming an image is stego when its EXIF comment already answers the question.

## Publish as Fact

Which artifact, which tool and exact command, the stream/offset/inode, and the
extracted file path under `shared/` that a later Worker can re-read.
