# Web

## 1. Map the application before attacking it

```bash
whatweb -a3 http://TARGET/ ; curl -sS -D- -o/dev/null http://TARGET/
curl -sS http://TARGET/robots.txt http://TARGET/sitemap.xml | head -40
ffuf -u http://TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -mc all -fs 0
```

Record: tech stack, routes, parameters, auth model, session cookie format,
error page behaviour, whether responses differ per role. Read the frontend:
`view-source`, JS bundles (`rg -o '"/[a-zA-Z0-9_/.-]+"'`), comments, source
maps, `.git/`, `.svn/`, `.DS_Store`, `*.bak`, `*.swp`, `phpinfo.php`.

Then enumerate every input the model controls: query params, body (form/JSON),
headers (`X-Forwarded-For`, `Host`, `Referer`), cookies, path segments, upload
filenames, and any second-order storage (profiles, tickets, logs).

## 2. Choose the class from the observed behaviour

| Signal | Class | Cheapest decisive test |
| --- | --- | --- |
| Input reflected in the page | XSS | canary string, check the exact context (HTML/attr/JS/URL) |
| String/numeric into a query | SQLi | `'` then `''`, then boolean pair `AND 1=1` / `AND 1=2` |
| Numeric object id, another user's data visible | IDOR/BOLA | change the id, compare response bodies byte-wise |
| `{{7*7}}`, `${7*7}`, `<%= 7*7 %>` executed | SSTI | arithmetic canary, then identify the engine |
| Parameter used to fetch a URL | SSRF | loopback and internal-port probe, cloud metadata only if the range allows |
| XML body accepted | XXE | entity referencing a local file, then OOB if inline is blocked |
| Java `.rO0`/`AC ED`, PHP `O:`, pickle, .NET binary | Deserialization | build the gadget only after the type is confirmed |
| Upload accepted | File upload | content-type/extension/polyglot matrix, read-back path |
| Shell-ish parameter (`ping`, `convert`, `nslookup`) | Command injection | timing canary `; sleep 3` vs `&` vs `$(sleep 3)` |
| JWT in cookie/header | JWT | decode, try `alg=none`, then HS/RS confusion, then `kid` injection |
| Path traversal accepted | LFI/RFI | `../../etc/passwd`, then `php://filter/convert.base64-encode/resource=index.php` |
| Single-use token, limited stock, vote/claim | Race condition | 20 parallel requests in one batch, compare winners |

## 3. Manual proof before automation

Prove the primitive with `curl` first. sqlmap, ffuf and nuclei amplify a
confirmed finding; they do not create one, and an ambiguous tool "hit" wastes a
Worker.

```bash
curl -sS 'http://TARGET/item?id=1%27'            # error text = likely SQLi
curl -sS 'http://TARGET/item?id=1 AND 1=2'       # boolean difference
curl -sS -o /dev/null -w '%{time_total}\n' 'http://TARGET/x?f=;sleep 3'   # timing
```

Useful extensions of a confirmed primitive:

- SQLi: `ORDER BY n` for column count, then UNION with `NULL`s; only after the
  manual UNION works, run sqlmap with `--technique` narrowed.
- LFI: PHP filter chain generator for arbitrary-content includes, log poisoning
  (`access.log` via `User-Agent`), `/proc/self/environ`, session files.
- SSTI: fingerprint engine (Jinja2/Twig/Freemarker/Velocity) by syntax, then
  reach for RCE only if the target is in scope for it.
- SSRF: allowlist bypass with decimal/octal IPs, `@`-style URLs, redirects,
  DNS rebinding; distinguish "response returned" from "request delivered"
  (use an out-of-band listener you control).
- JWT: `hashcat -m 16500 jwt.txt wordlist` for weak HMAC secrets, `jwt_tool`
  for the structural attacks.
- Race: repeated parallel batches, not just one; report the actual interleaving.

## 4. Flag locations to check once you can read

Environment variables, `/flag`, `/flag.txt`, application config and `.env`,
database tables/columns dumped by the injection, admin-only routes, template
and source comments, upload directories, and any file read primitive (LFI,
SSRF-to-file, XXE, deserialization file read).

## 5. Pitfalls

- A `500` or `403` is evidence about one request, not proof the target is down
  or the route unreachable.
- **Never call a service dead without a direct measurement.** An HTTP client
  getting nothing back means the service is not speaking HTTP, which is not the
  same thing. Confirm liveness out of band, then read the raw banner:

  ```bash
  nc -vz HOST PORT                          # TCP reachability, the real test
  python3 -c 'import socket;s=socket.create_connection(("HOST",PORT),5);print(s.recv(4096))'
  ```

  A banner that describes a puzzle ("solve a sha1 sum ending in 24 bits set to
  one") is the protocol's first required step, not a broken service: the client
  must solve it before it may speak. Budget for it - a 24-bit search is seconds
  to a couple of minutes in a tight loop, not a reason to abandon the challenge.
  Concluding "the container died" from a failed HTTP request wastes the whole
  Step; report the exact symptom instead.
- Rate limiting and WAF blocks look like "no vulnerability"; compare raw and
  encoded payloads before concluding.
- A flag-shaped string on a public page is usually a decoy; confirm it through
  the intended primitive.
- Do not spend a Step on generic scanning after a specific primitive is
  confirmed — follow the primitive.

## Publish as Fact

Exact request (method, path, params, headers, body), the exact response slice,
status code, and the boundary of the primitive (which input, which privilege,
what still is untested).
