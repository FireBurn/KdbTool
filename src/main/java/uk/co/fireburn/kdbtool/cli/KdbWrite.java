package uk.co.fireburn.kdbtool.cli;

import uk.co.fireburn.kdbtool.kdb.KdbKeyDatabase;
import uk.co.fireburn.kdbtool.kdb.KdbRecord;
import uk.co.fireburn.kdbtool.kdb.Pbes2;
import uk.co.fireburn.kdbtool.stash.StashFile;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.util.ListIterator;

/** Native write-side key-database operations (create / changepw). */
final class KdbWrite {
    private KdbWrite() {}

    static int create(Args a) throws Exception {
        Path db = Paths.get(a.required("-db"));
        char[] pw = passwordForCreate(a);
        if (Files.exists(db) && !a.has("-f")) {
            throw new IllegalArgumentException(db + " already exists (use -f to overwrite)");
        }
        KdbKeyDatabase.create().write(db, pw);
        System.out.println("Key database " + db + " created.");
        if (a.has("-stash")) {
            Path sth = StashPaths.derive(db.toString());
            Files.write(sth, StashFile.encode(new String(pw)));
            System.out.println("The password has been stashed in " + sth);
        }
        return 0;
    }

    static int changePw(Args a) throws Exception {
        Path db = Paths.get(a.required("-db"));
        byte[] raw = Files.readAllBytes(db);
        char[] oldPw = KdbCommands.password(a, db);
        if (!KdbKeyDatabase.verify(raw, oldPw)) {
            System.out.println("The password is incorrect.");
            return 1;
        }
        char[] newPw = a.required("-new_pw").toCharArray();
        KdbKeyDatabase kdb = KdbKeyDatabase.read(raw);
        rekeyAll(kdb, oldPw, newPw);
        kdb.write(db, newPw);
        // The companion request database (.rdb) shares the master password; re-key it too so
        // -certreq operations keep working after a password change (matches the reference tool).
        Path rdbPath = Paths.get(db.toString().endsWith(".kdb")
            ? db.toString().substring(0, db.toString().length() - 4) + ".rdb"
            : db + ".rdb");
        if (Files.exists(rdbPath)) {
            byte[] rdbRaw = Files.readAllBytes(rdbPath);
            if (KdbKeyDatabase.verify(rdbRaw, oldPw)) {
                KdbKeyDatabase rdb = KdbKeyDatabase.read(rdbRaw);
                rekeyAll(rdb, oldPw, newPw);
                rdb.write(rdbPath, newPw);
            }
        }
        System.out.println("The database password has been changed.");
        if (a.has("-stash")) {
            Path sth = StashPaths.derive(db.toString());
            Files.write(sth, StashFile.encode(new String(newPw)));
            System.out.println("The password has been stashed in " + sth);
        }
        return 0;
    }

    /** Re-encrypts every key-bearing record (secret, request, personal) from oldPw to newPw. */
    private static void rekeyAll(KdbKeyDatabase kdb, char[] oldPw, char[] newPw) throws Exception {
        ListIterator<KdbRecord> it = kdb.records().listIterator();
        while (it.hasNext()) {
            KdbRecord r = it.next();
            if (r.isSecretKey()) {
                byte[] secretRaw = Pbes2.decryptBytes(r.encryptedKeyDer(), oldPw);
                it.set(KdbRecord.secretKeyRecord(r.label(), Pbes2.encryptBytes(secretRaw, newPw)));
            } else if (r.isRequest() && r.hasPrivateKey()) {
                PrivateKey key = r.privateKey(oldPw);
                it.set(KdbRecord.requestRecord(r.label(), r.csrDer(), Pbes2.encrypt(key, newPw)));
            } else if (r.hasPrivateKey() && r.certificate() != null) {
                PrivateKey key = r.privateKey(oldPw);
                it.set(KdbRecord.personalRecord(r.label(), r.certificate(), Pbes2.encrypt(key, newPw)));
            }
        }
    }

    /** Converts the whole database to a PKCS#12 file (all certs and personal keys). */
    static int convert(Args a) throws Exception {
        Path dbPath = Paths.get(a.required("-db"));
        byte[] raw = Files.readAllBytes(dbPath);
        char[] pw = KdbCommands.password(a, dbPath);
        if (!KdbKeyDatabase.verify(raw, pw)) throw new IllegalArgumentException("password incorrect");
        Path target = Paths.get(a.required("-target"));
        char[] tpw = a.value("-target_pw") != null ? a.value("-target_pw").toCharArray() : pw;
        KdbKeyDatabase db = KdbKeyDatabase.read(raw);
        java.security.KeyStore p12 = java.security.KeyStore.getInstance("PKCS12");
        p12.load(null, null);
        for (KdbRecord r : db.records()) {
            if (r.certificate() == null) continue;
            if (r.hasPrivateKey()) {
                p12.setKeyEntry(r.label(), r.privateKey(pw), tpw,
                    r.certificates().toArray(new java.security.cert.Certificate[0]));
            } else {
                p12.setCertificateEntry(r.label(), r.certificate());
            }
        }
        try (java.io.OutputStream o = Files.newOutputStream(target)) { p12.store(o, tpw); }
        System.out.println("Converted " + dbPath + " to PKCS#12 " + target);
        return 0;
    }

    /** Deletes a key database and its companion files. */
    static int deleteDb(Args a) throws Exception {
        Path db = Paths.get(a.required("-db"));
        String base = db.toString();
        if (base.endsWith(".kdb")) base = base.substring(0, base.length() - 4);
        int n = 0;
        for (String ext : new String[]{".kdb", ".sth", ".rdb", ".crl"}) {
            if (Files.deleteIfExists(Paths.get(base + ext))) n++;
        }
        System.out.println("Deleted key database " + db + " (" + n + " file(s))");
        return 0;
    }

    private static char[] passwordForCreate(Args a) {
        String pw = a.value("-pw");
        if (pw != null) return pw.toCharArray();
        if (System.console() != null) return System.console().readPassword("Enter database password: ");
        throw new IllegalArgumentException("-pw required");
    }
}
