# Crypto

## 1. Separate the layers

Challenge text, parameters, and blobs are three different things. First answer:
is this an encoding chain, a classical cipher, or a modern primitive with a
misuse? Try the cheap automations once, then read the actual parameters.

```bash
file cipher.txt; head -c 200 cipher.txt | xxd | head
python3 - <<'PY'
import base64, binascii
data = open('cipher.txt','rb').read().strip()
for name, fn in (('b64', base64.b64decode), ('b32', base64.b32decode)):
    try: print(name, fn(data)[:60])
    except Exception as e: print(name, 'no', type(e).__name__)
PY
```

Encoding/classical layers: base16/32/58/64/85, hex, Morse, Bacon, A1Z26,
Braille, ROT/Atbash/Vigenere/Playfair/rail-fence (frequency analysis, Index of
Coincidence, Kasiski). Run the easy ones, but state which layer you removed —
"CyberChef magic said so" is not a verified fact.

## 2. RSA attack checklist (cheapest first)

1. Is `n` already factored? Offline: trial division, then `ecm` for small and
   medium factors (`printf '%s\n' N | ecm 20000`), then `sympy.factorint` or
   Sage when `n` is small. `factordb` is a network lookup - use it only if the
   environment has egress, and never as the first move.
2. Shared prime across two moduli: `gcd(n1, n2)`.
3. Small `e` with `m^e < n`: integer `e`-th root of the ciphertext.
4. `e = 3` with structured padding/message: Coppersmith small-root, or
   Franklin-Reiter for related messages.
5. Small `d`: Wiener (continued fractions), then Boneh-Durfee (lattice).
6. Common modulus, same message to several keys.
7. Partial key exposure (known high bits of `p`/`q`/`d`) -> Coppersmith.
8. Custom scheme in source: read it literally. Typical bugs are signing with
   the wrong exponent, reusing a nonce, or a missing fault check (Bellcore).

Tools: pycryptodome, sympy, gmpy2, sagemath, z3, `RsaCtfTool` for a second
opinion after you know which attack class fits.

```python
from Crypto.Util.number import long_to_bytes, inverse
from math import gcd
```

## 3. Block ciphers

| Observation | Attack |
| --- | --- |
| Two identical 16-byte plaintexts give identical ciphertext blocks | ECB; use the block structure (byte-at-a-time oracle, cut-and-paste) |
| Attacker controls plaintext and IV | CBC bit-flipping of the block before the target |
| Padding error distinguishable from decryption error | padding oracle (CBC); script it, one byte at a time |
| Same keystream across messages | CTR nonce reuse: XOR two ciphertexts to cancel the keystream |
| GCM nonce reused | recover the authentication key, then forge |
| Length-extension-friendly hash (MD5/SHA1/SHA256) with `secret||msg` | `ctf-hashpump --mac MAC --data MSG --append EXTRA` (tries the key lengths; verify against the service) |

## 4. Public key beyond RSA

- ECDSA nonce reuse or bias: with two signatures on the same `k`,
  `k = (z1 - z2) / (s1 - s2)`, then recover `d`; biased `k` needs a lattice
  (LLL/HNP in sage).
- ECC curve problems: singular curve, anomalous order (`#E = p`), small
  subgroup/Pohlig-Hellman, invalid-curve points, small subgroup confinement.
- DH/finite field: small subgroup, smooth-order modulus (Pohlig-Hellman),
  shared exponent between sessions.

## 5. PRNG and stream ciphers

- MT19937: 624 consecutive 32-bit outputs let you clone the state; Python's
  `random` and PHP's `mt_rand` variants differ in tempering/encoding.
- LCG: three outputs give the parameters; check for modulus wraparound.
- Timestamp/V8 seeds: brute force the small seed space first.
- Keystream reuse in any stream cipher: XOR the two ciphertexts and look for
  readable structure.

## 6. Pitfalls

- Attacking the math while the source code states the bug in one line.
- Using a public write-up's parameters on a challenge with different ones.
- Confusing "decryption produced printable bytes" with "the plaintext is
  correct" — verify with a known structure (header, padding, hash).

## Publish as Fact

The primitive and parameters used, the exact algebraic relation exploited, the
recovered key/plaintext, and the verification that proves the plaintext is the
intended one.
