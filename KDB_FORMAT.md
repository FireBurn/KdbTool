# CMS key database (`.kdb`) format

Two format versions exist, distinguished by the third magic byte. They differ only in the HMAC
algorithm (and therefore the header size); the record area is identical.

| Version | Magic | HMAC | MAC length (M) | Header size (0x30 + 2·M) | Written by |
|--------:|-------|------|---------------:|--------------------------:|------------|
| 6 | `37 48 06 02` | HMAC-SHA384 | 48 | 0x90 (144) | current releases |
| 4 | `37 48 04 02` | HMAC-SHA1 | 20 | 0x58 (88) | older releases (e.g. long-lived web/application server deployments) |

## Header (0x30 + 2·M bytes)

| Offset | Size | Field |
|-------:|-----:|-------|
| 0x00 | 4 | magic `37 48 vv 02` (vv = version, `04` or `06`) |
| 0x04 | 4 | reserved (0) |
| 0x08 | 8 | `"X509KEY\0"` |
| 0x10 | 4 | record **slot size** (default 0x1388 = 5000) |
| 0x14 | 4 | record **count** |
| 0x18 | 24 | random salt |
| 0x30 | M | `HMAC(password, header[0x00:0x30])` — password verifier |
| 0x30+M | M | `HMAC(password, header[0x00:0x30+M] ‖ allRecordBytes)` — integrity MAC |

For version 6 the MACs sit at 0x30 (48 bytes) and 0x60 (48 bytes); for version 4 at
0x30 (20 bytes) and 0x44 (20 bytes).

Verifying a password needs only the first MAC. The header is the same regardless of how many
certificates have a private key.

## Records

After the header come `count` fixed-size **slots** of `slotSize` bytes. Each slot:

```
[recordType:4]   = 1            (key record; key-pair-ness is in the DER, not here)
[recordNumber:4] = 1..n
[derLen:4]
[DER record]                    (see below)
[labelLen:4]                    (includes the trailing NUL)
[label bytes][NUL]
[flags:4 = 0]
[len:4 = 20][SHA1(SubjectPublicKeyInfo)]
[len:4 = 20][SHA1(certificate)]
... zero padding to slotSize
```

## Record DER

```
SEQUENCE {
  INTEGER         version (1)
  -- trusted certificate:
  [1] { Certificate }
  -- OR personal certificate:
  [2] { SEQUENCE { Certificate, EncryptedPrivateKeyInfo } }
  VisibleString   label
  BIT STRING      flags          -- 07 80 = trusted CA ; 06 C0 = personal
}
```

* **Certificate** — a standard DER X.509 certificate, stored in the clear. Listing, viewing and
  extracting certificates therefore need no password.
* **EncryptedPrivateKeyInfo** — a standard PKCS#8 structure. Files written by this tool use
  **PBES2** (PBKDF2-HMAC-SHA384 + AES-256-CBC, `PBEWithHmacSHA384AndAES_256` in JDK terms),
  encrypted directly with the database password. Version-4 files produced by older
  releases typically use legacy PKCS#12 PBE schemes instead; the JDK's
  `EncryptedPrivateKeyInfo`/`SecretKeyFactory` mechanism decrypts those transparently.

## Writing

1. Lay out `header[0x00:0x30]` (magic, slot size, record count, salt).
2. `header[0x30:0x30+M] = HMAC(pw, header[0x00:0x30])`.
3. Serialise all record slots, growing the slot size beyond the default if a record (e.g. a
   post-quantum key) does not fit; the slot size is declared in the header.
4. `header[0x30+M:0x30+2M] = HMAC(pw, header[0x00:0x30+M] ‖ records)`.
5. Concatenate header + record slots.

A database keeps its format version across read-modify-write cycles: a version-4 file stays
version 4 (HMAC-SHA1) so that the original tooling can still open it. Newly created databases
are version 6.

Changing the password re-encrypts every personal record's key (PBES2 under the new password) and
recomputes both MACs. Certificates created natively include `BasicConstraints`,
`SubjectKeyIdentifier` and `KeyUsage` extensions so they pass strict validation.
