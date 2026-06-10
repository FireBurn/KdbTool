package uk.co.fireburn.kdbtool.cli;

import uk.co.fireburn.kdbtool.kdb.KdbKeyDatabase;
import uk.co.fireburn.kdbtool.kdb.KdbRecord;
import uk.co.fireburn.kdbtool.stash.StashFile;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

/** Native (binary-free) implementations of the read-side {@code -cert} / {@code -keydb} commands. */
final class KdbCommands {

    private KdbCommands() {}

    static int list(Args a) throws Exception {
        KdbKeyDatabase db = KdbKeyDatabase.read(Paths.get(a.required("-db")));
        if (db.records().isEmpty()) {
            System.out.println("No certificates were found.");
            return 0;
        }
        System.out.println("Certificates found");
        System.out.println("* default, - personal, ! trusted, # secret key");
        for (KdbRecord r : db.records()) {
            String mark = r.hasPrivateKey() ? "-" : "!";
            System.out.println("\t" + mark + "\t" + r.label());
        }
        return 0;
    }

    static int details(Args a) throws Exception {
        KdbKeyDatabase db = KdbKeyDatabase.read(Paths.get(a.required("-db")));
        KdbRecord r = requireRecord(db, a.required("-label"));
        X509Certificate c = r.certificate();
        if (c == null) {
            System.out.println("Label: " + r.label() + " (no parseable certificate)");
            return 0;
        }
        System.out.println("Label: " + r.label());
        System.out.println("Key Size: " + keySize(c));
        System.out.println("Version: X509 V" + c.getVersion());
        System.out.println("Serial Number: " + c.getSerialNumber().toString(16));
        System.out.println("Issued by: " + c.getIssuerX500Principal().getName());
        System.out.println("Subject: " + c.getSubjectX500Principal().getName());
        System.out.println("Valid: From: " + c.getNotBefore() + " To: " + c.getNotAfter());
        System.out.println("Signature Algorithm: " + c.getSigAlgName());
        System.out.println("Fingerprint (SHA1): " + fingerprint(c, "SHA-1"));
        System.out.println("Fingerprint (SHA256): " + fingerprint(c, "SHA-256"));
        System.out.println("Has private key: " + r.hasPrivateKey());
        if (a.has("-showOID") || a.has("-detail")) {
            for (Certificate extra : r.certificates()) {
                System.out.println("  chain cert: "
                    + ((X509Certificate) extra).getSubjectX500Principal().getName());
            }
        }
        return 0;
    }

    static int extract(Args a) throws Exception {
        KdbKeyDatabase db = KdbKeyDatabase.read(Paths.get(a.required("-db")));
        KdbRecord r = requireRecord(db, a.required("-label"));
        X509Certificate c = r.certificate();
        if (c == null) throw new IllegalArgumentException("no certificate for label " + r.label());
        Path target = Paths.get(a.required("-target"));
        String fmt = a.value("-format", "ascii");
        if (fmt.equalsIgnoreCase("binary")) {
            Files.write(target, c.getEncoded());
        } else {
            Files.write(target, pem("CERTIFICATE", c.getEncoded()).getBytes(StandardCharsets.US_ASCII));
        }
        System.out.println("Certificate extracted to " + target + " (" + fmt + ")");
        return 0;
    }

    /** Export a personal certificate + key, or a trusted cert, to a PKCS#12 file (JDK-native). */
    static int export(Args a) throws Exception {
        Path dbPath = Paths.get(a.required("-db"));
        KdbKeyDatabase db = KdbKeyDatabase.read(dbPath);
        KdbRecord r = requireRecord(db, a.required("-label"));
        char[] pw = password(a, dbPath);
        char[] targetPw = a.value("-target_pw") != null
            ? a.value("-target_pw").toCharArray() : pw;
        Path target = Paths.get(a.required("-target"));

        KeyStore p12 = KeyStore.getInstance("PKCS12");
        p12.load(null, null);
        if (r.hasPrivateKey()) {
            PrivateKey key = r.privateKey(pw);
            Certificate[] chain = r.certificates().toArray(new Certificate[0]);
            p12.setKeyEntry(r.label(), key, targetPw, chain);
        } else {
            p12.setCertificateEntry(r.label(), r.certificate());
        }
        try (OutputStream out = Files.newOutputStream(target)) {
            p12.store(out, targetPw);
        }
        System.out.println("Exported '" + r.label() + "' to PKCS#12 file " + target);
        return 0;
    }

    /** Recover and print the private key in PEM (PKCS#8) — beyond what the reference tool offers. */
    static int extractKey(Args a) throws Exception {
        Path dbPath = Paths.get(a.required("-db"));
        KdbKeyDatabase db = KdbKeyDatabase.read(dbPath);
        KdbRecord r = requireRecord(db, a.required("-label"));
        PrivateKey key = r.privateKey(password(a, dbPath));
        String out = pem("PRIVATE KEY", key.getEncoded());
        if (a.value("-target") != null) {
            Files.write(Paths.get(a.value("-target")), out.getBytes(StandardCharsets.US_ASCII));
            System.out.println("Private key written to " + a.value("-target"));
        } else {
            System.out.print(out);
        }
        return 0;
    }

    /** Validates a certificate: checks validity dates and builds a chain to a root in the database. */
    static int validate(Args a) throws Exception {
        KdbKeyDatabase db = KdbKeyDatabase.read(Paths.get(a.required("-db")));
        KdbRecord r = requireRecord(db, a.required("-label"));
        X509Certificate c = r.certificate();
        if (c == null) throw new IllegalArgumentException("no certificate for label " + r.label());
        try {
            c.checkValidity();
        } catch (Exception e) {
            System.out.println("INVALID: " + e.getMessage());
            return 1;
        }
        // try to find an issuer in the database
        X509Certificate cur = c;
        int depth = 0;
        StringBuilder chain = new StringBuilder();
        while (depth++ < 10) {
            chain.append("  ").append(cur.getSubjectX500Principal().getName()).append('\n');
            if (cur.getSubjectX500Principal().equals(cur.getIssuerX500Principal())) break; // self-signed root
            X509Certificate issuer = null;
            for (KdbRecord o : db.records()) {
                X509Certificate oc = o.certificate();
                if (oc != null && oc.getSubjectX500Principal().equals(cur.getIssuerX500Principal())) {
                    issuer = oc; break;
                }
            }
            if (issuer == null) {
                System.out.println("Certificate is valid; issuer not found in database (incomplete chain).");
                System.out.print(chain);
                return 0;
            }
            try { cur.verify(issuer.getPublicKey()); } catch (Exception e) {
                System.out.println("INVALID: signature does not verify against issuer");
                return 1;
            }
            cur = issuer;
        }
        System.out.println("Certificate '" + r.label() + "' is valid. Chain:");
        System.out.print(chain);
        return 0;
    }

    static int info(Args a) throws Exception {
        Path dbPath = Paths.get(a.required("-db"));
        KdbKeyDatabase db = KdbKeyDatabase.read(dbPath);
        Path sth = StashPaths.derive(dbPath.toString());
        System.out.println("Key database  : " + dbPath);
        System.out.println("Format        : CMS version "
            + (db.version() == KdbKeyDatabase.Version.V4 ? "4 (HMAC-SHA1)" : "6 (HMAC-SHA384)"));
        System.out.println("Record slot   : " + db.slotSize() + " bytes");
        System.out.println("Records       : " + db.records().size());
        int personal = 0;
        for (KdbRecord r : db.records()) if (r.hasPrivateKey()) personal++;
        System.out.println("Personal certs: " + personal);
        System.out.println("Stash file    : " + (Files.exists(sth) ? sth + " (present)" : "none"));
        return 0;
    }

    // --------------------------------------------------------------- helpers

    private static KdbRecord requireRecord(KdbKeyDatabase db, String label) {
        KdbRecord r = db.find(label);
        if (r == null) throw new IllegalArgumentException("label not found: " + label);
        return r;
    }

    static char[] password(Args a, Path dbPath) throws Exception {
        String pw = a.value("-pw");
        if (pw != null) return pw.toCharArray();
        if (a.has("-stashed")) {
            Path sth = StashPaths.derive(dbPath.toString());
            return StashFile.decodeFile(sth).toCharArray();
        }
        if (System.console() != null) return System.console().readPassword("Enter database password: ");
        throw new IllegalArgumentException("password required (-pw or -stashed)");
    }

    private static int keySize(X509Certificate c) {
        try {
            java.security.PublicKey k = c.getPublicKey();
            if (k instanceof java.security.interfaces.RSAPublicKey) {
                return ((java.security.interfaces.RSAPublicKey) k).getModulus().bitLength();
            }
            if (k instanceof java.security.interfaces.ECPublicKey) {
                return ((java.security.interfaces.ECPublicKey) k).getParams().getCurve().getField().getFieldSize();
            }
        } catch (Exception ignore) {}
        return 0;
    }

    private static String fingerprint(X509Certificate c, String alg) throws Exception {
        byte[] h = java.security.MessageDigest.getInstance(alg).digest(c.getEncoded());
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < h.length; i++) {
            if (i > 0) s.append(':');
            s.append(String.format("%02X", h[i]));
        }
        return s.toString();
    }

    private static String pem(String type, byte[] der) {
        String b64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + b64 + "\n-----END " + type + "-----\n";
    }
}
