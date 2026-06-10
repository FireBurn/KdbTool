# CMS stash file (`.sth`) format

The stash stores the key database's master password obfuscated/encrypted. It is
**fully portable** — not tied to the host that created it — so it can be decoded offline.

## v1 stash — 129 bytes (`-v1stash`)

```
buffer = password || 0x00 || random-non-zero-padding        (129 bytes total)
file   = buffer XOR 0xF5   (every byte)
```

Decode: XOR every byte with `0xF5`, then read up to the first `0x00`.

## v8 stash — 193 bytes (default)

```
file = A(32) || B(32) || CT(129)
  B   = SHA-256(0x01 || A)                 # integrity check
  KEY = SHA-256(A || B)
```

`CT` is the 129-byte v1 buffer (above) XORed with a keystream derived from `KEY` via HMAC-SHA-256:

```
# key conditioning
S = KEY
while S[8] != 0x03:  S = SHA-256(S)
repeat 64 times:     S = SHA-256(S)

# constants
STR = ASCII "13EC6D5C885056915AB35FAD2BDDF39F40D7C57B8B4D28F66B61B75F39144"
          + "6FDA96751174DBD9713D02E0B38732E763501DBBB85EC60E437929ED2AA8981B36B"   # 128 chars
FIB = 01 01 02 03 05 08

# keystream
seed  = HMAC-SHA-256(key = S,    msg = STR)
state = HMAC-SHA-256(key = seed, msg = FIB)
ks    = ""
while len(ks) < 129:
    ks    += HMAC-SHA-256(key = seed, msg = state)
    state  = ks || state          # feedback: keystream-so-far concatenated with state

payload   = CT XOR ks[:129]       # == the v1 buffer
plaintext = payload XOR 0xF5
password  = plaintext up to the first 0x00
```

Encoding reverses this: build the v1 buffer, pick a random `A`, compute `B`/`KEY`/keystream,
and emit `A || B || (buffer XOR keystream)`.

## Verification

* Stash files written by the reference tooling decode successfully, opening their companion
  `.kdb` databases.
* The reference tool's `-cert -list -stashed` accepts stash files produced by this implementation.
* `StashFileTest` round-trips passwords of every length (including the 32-byte block boundary
  and multi-block lengths) and decodes reference-tool output.
