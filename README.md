# KdbTool — Java CMS key-database tool

A 100% native-Java tool for the CMS key-database format. It reads and writes
the CMS key database (`.kdb`), stash (`.sth`), and certificates

Both the stash format ([STASH_FORMAT.md](STASH_FORMAT.md)) and the CMS KDB container
([KDB_FORMAT.md](KDB_FORMAT.md)) are fully interoperable with the standard reference
tooling: files written by this tool open, list, validate, and re-export in the reference
tool, and databases written by the reference tool are read here. Both container format
versions are supported: version 6 (HMAC-SHA384, current) and the older version 4
(HMAC-SHA1), with the version preserved when a database is modified.

## Build

```sh
javac -d build/classes $(find src/main/java -name '*.java')
jar --create --file kdbtool.jar --main-class uk.co.fireburn.kdbtool.cli.KdbTool -C build/classes .
```

Requires Java 8+ (8u161+ recommended, so AES-256 works without installing the JCE unlimited-strength
policy). No dependencies. Run via `./kdbtool <args>` or `java -jar kdbtool.jar <args>`.

## Commands

Key database:
```
-keydb -create   -db F.kdb -pw PW [-stash]
-keydb -changepw -db F.kdb -pw PW -new_pw PW [-stash]      # re-encrypts all keys
-keydb -convert  -db F.kdb (-pw PW|-stashed) -target F.p12 [-target_pw PW]
-keydb -delete   -db F.kdb
-keydb -info | -list
-keydb -stashpw  -db F.kdb -pw PW [-v1stash]
-keydb -getpw    -db F.kdb | -stashed F.sth                # recover the master password
-keydb -verifypw -db F.kdb (-pw PW | -stashed)
```

Certificates:
```
-cert -list | -details | -extract | -validate  -db F.kdb [-label L]
-cert -create   -db F.kdb -pw PW -label L -dn DN [-size 2048] [-expire DAYS]
-cert -add | -receive  -db F.kdb -pw PW -label L -file C.arm
-cert -delete | -rename  -db F.kdb -pw PW -label L [-new_label L]
-cert -import   -db F.kdb -pw PW -file SRC.p12 [-target_pw PW] [-label L]
-cert -export   -db F.kdb (-pw PW|-stashed) -label L -target C.p12 [-target_pw PW]
-cert -extractkey -db F.kdb (-pw PW|-stashed) -label L [-target K.pem]   # recover private key
-cert -sign     -db F.kdb -pw PW -label CA -file req.csr -target cert.pem
```

Certificate request:
```
-certreq -create -db F.kdb -pw PW -label L -dn DN -file req.csr
```

## Examples

```sh
# Recover the master password of a production key database
./kdbtool -keydb -getpw -db server_certs.kdb

# Full CA workflow, entirely in Java
./kdbtool -keydb  -create  -db ca.kdb -pw secret -stash
./kdbtool -cert   -create  -db ca.kdb -pw secret -label rootca -dn "CN=My Root CA,O=Acme"
./kdbtool -certreq -create -db ca.kdb -pw secret -label server -dn "CN=server.acme.com" -file s.csr
./kdbtool -cert   -sign    -db ca.kdb -pw secret -label rootca -file s.csr -target s.pem
./kdbtool -cert   -receive -db ca.kdb -pw secret -file s.pem
```

## How it works

* **Stash (`.sth`)** — v1 is `XOR 0xF5`; v8 is `salt | SHA256(0x01|salt) | XOR(payload, keystream)`
  where the keystream is an HMAC-SHA256 chain (see STASH_FORMAT.md). The recoverable password is
  here; the `.kdb` only stores a salted hash.
* **KDB (`.kdb`)** — a 144-byte header (two HMAC-SHA384 MACs over the header/records) followed by
  fixed-size record slots. Each record is DER-encoded ASN.1 holding a clear-text X.509 certificate
  and, for personal entries, a PKCS#8 `EncryptedPrivateKeyInfo` (PBES2: PBKDF2-HMAC-SHA384 +
  AES-256-CBC). See KDB_FORMAT.md.
