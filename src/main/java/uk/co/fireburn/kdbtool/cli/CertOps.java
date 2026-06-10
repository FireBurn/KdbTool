package uk.co.fireburn.kdbtool.cli;

import uk.co.fireburn.kdbtool.kdb.KdbKeyDatabase;
import uk.co.fireburn.kdbtool.kdb.KdbRecord;
import uk.co.fireburn.kdbtool.kdb.Pbes2;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

/** Native write-side {@code -cert} operations: add, delete, import (PKCS#12), receive. */
final class CertOps {
    private CertOps() {}

    static int add(Args a) throws Exception {
        Path dbPath = Paths.get(a.required("-db"));
        byte[] raw = Files.readAllBytes(dbPath);
        char[] pw = KdbCommands.password(a, dbPath);
        requirePw(raw, pw);
        X509Certificate cert = readCert(Paths.get(a.required("-file")));
        String label = a.value("-label", cert.getSubjectX500Principal().getName());
        KdbKeyDatabase db = KdbKeyDatabase.read(raw);
        db.add(KdbRecord.caRecord(label, cert));
        db.write(dbPath, pw);
        System.out.println("Certificate added to " + dbPath + " under label '" + label + "'");
        return 0;
    }

    static int delete(Args a) throws Exception {
        Path dbPath = Paths.get(a.required("-db"));
        byte[] raw = Files.readAllBytes(dbPath);
        char[] pw = KdbCommands.password(a, dbPath);
        requirePw(raw, pw);
        KdbKeyDatabase db = KdbKeyDatabase.read(raw);
        String label = a.required("-label");
        if (!db.remove(label)) throw new IllegalArgumentException("label not found: " + label);
        db.write(dbPath, pw);
        System.out.println("Deleted '" + label + "' from " + dbPath);
        return 0;
    }

    /** Creates a self-signed personal certificate (key generated natively). */
    static int create(Args a) throws Exception {
        Path dbPath = Paths.get(a.required("-db"));
        byte[] raw = Files.readAllBytes(dbPath);
        char[] pw = KdbCommands.password(a, dbPath);
        requirePw(raw, pw);
        String label = a.required("-label");
        String dn = a.required("-dn");
        int size = Integer.parseInt(a.value("-size", "2048"));
        int days = Integer.parseInt(a.value("-expire", "365"));
        String sigAlg = a.value("-sigalg", "SHA256withRSA");

        java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("RSA");
        kpg.initialize(size);
        java.security.KeyPair kp = kpg.generateKeyPair();
        X509Certificate cert = uk.co.fireburn.kdbtool.kdb.X509Builder.selfSigned(dn, kp, days, sigAlg);
        byte[] enc = Pbes2.encrypt(kp.getPrivate(), pw);

        KdbKeyDatabase db = KdbKeyDatabase.read(raw);
        db.add(KdbRecord.personalRecord(label, cert, enc));
        db.write(dbPath, pw);
        System.out.println("Self-signed certificate '" + label + "' created in " + dbPath);
        return 0;
    }

    /** Receives a signed certificate: matches it to a pending request (.rdb) or personal key. */
    static int receive(Args a) throws Exception {
        Path dbPath = Paths.get(a.required("-db"));
        byte[] raw = Files.readAllBytes(dbPath);
        char[] pw = KdbCommands.password(a, dbPath);
        requirePw(raw, pw);
        X509Certificate cert = readCert(Paths.get(a.required("-file")));
        byte[] certKey = cert.getPublicKey().getEncoded();
        KdbKeyDatabase db = KdbKeyDatabase.read(raw);

        // 1) match an existing personal record by public key
        for (KdbRecord r : db.records()) {
            if (r.hasPrivateKey() && r.certificate() != null
                && java.util.Arrays.equals(r.certificate().getPublicKey().getEncoded(), certKey)) {
                db.remove(r.label());
                db.add(KdbRecord.personalRecord(r.label(), cert, r.encryptedKeyDer()));
                db.write(dbPath, pw);
                System.out.println("Certificate received into personal record '" + r.label() + "'");
                return 0;
            }
        }
        // 2) match a pending request in the .rdb
        Path rdbPath = Paths.get(dbPath.toString().replaceAll("\\.kdb$", "") + ".rdb");
        if (Files.exists(rdbPath)) {
            KdbKeyDatabase rdb = KdbKeyDatabase.read(Files.readAllBytes(rdbPath));
            for (KdbRecord r : rdb.records()) {
                if (!r.isRequest()) continue;
                byte[] reqKey = csrPublicKey(r.csrDer());
                if (java.util.Arrays.equals(reqKey, certKey)) {
                    db.add(KdbRecord.personalRecord(r.label(), cert, r.encryptedKeyDer()));
                    db.write(dbPath, pw);
                    rdb.remove(r.label());
                    rdb.write(rdbPath, pw);
                    System.out.println("Certificate received into personal record '" + r.label()
                        + "' (request consumed)");
                    return 0;
                }
            }
        }
        return add(a); // no matching key: treat as trusted-cert add
    }

    private static byte[] csrPublicKey(byte[] csrDer) {
        uk.co.fireburn.kdbtool.asn1.Der.Node cri = uk.co.fireburn.kdbtool.asn1.Der.parse(csrDer).children().get(0);
        return cri.children().get(2).der(); // SubjectPublicKeyInfo
    }

    /** Signs a PKCS#10 request with a CA key from the database, producing a certificate. */
    static int sign(Args a) throws Exception {
        Path dbPath = Paths.get(a.required("-db"));
        byte[] raw = Files.readAllBytes(dbPath);
        char[] pw = KdbCommands.password(a, dbPath);
        requirePw(raw, pw);
        KdbKeyDatabase db = KdbKeyDatabase.read(raw);
        KdbRecord ca = db.find(a.required("-label"));
        if (ca == null || !ca.hasPrivateKey()) {
            throw new IllegalArgumentException("CA label not found or has no private key");
        }
        byte[] csr = pemOrDer(Files.readAllBytes(Paths.get(a.required("-file"))));
        // CertificationRequest ::= SEQ { cri SEQ { ver, subject, SPKI, [0] }, sigAlg, sig }
        uk.co.fireburn.kdbtool.asn1.Der.Node req = uk.co.fireburn.kdbtool.asn1.Der.parse(csr);
        uk.co.fireburn.kdbtool.asn1.Der.Node cri = req.children().get(0);
        byte[] subjectDer = cri.children().get(1).der();
        byte[] spki = cri.children().get(2).der();
        java.security.PublicKey subjectKey = java.security.KeyFactory
            .getInstance(keyAlg(spki))
            .generatePublic(new java.security.spec.X509EncodedKeySpec(spki));
        String subjectDn = new javax.security.auth.x500.X500Principal(subjectDer).getName();
        int days = Integer.parseInt(a.value("-expire", "365"));
        String sigAlg = a.value("-sigalg", "SHA256withRSA");
        X509Certificate signed = uk.co.fireburn.kdbtool.kdb.X509Builder.sign(
            subjectDn, subjectKey, ca.certificate(), ca.privateKey(pw), days, sigAlg);
        Path target = Paths.get(a.required("-target"));
        Files.write(target, ("-----BEGIN CERTIFICATE-----\n"
            + java.util.Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(signed.getEncoded())
            + "\n-----END CERTIFICATE-----\n").getBytes());
        System.out.println("Signed certificate written to " + target);
        return 0;
    }

    private static String keyAlg(byte[] spki) {
        // OID inside SPKI's AlgorithmIdentifier: RSA = ...010101 ; EC = ...ce3d0201
        String h = bytesToHex(spki);
        if (h.contains("2a864886f70d010101")) return "RSA";
        if (h.contains("2a8648ce3d0201")) return "EC";
        return "RSA";
    }
    private static byte[] pemOrDer(byte[] data) {
        String s = new String(data, java.nio.charset.StandardCharsets.US_ASCII);
        if (s.contains("-----BEGIN")) {
            String b64 = s.replaceAll("-----[^-]+-----", "").replaceAll("\\s", "");
            return java.util.Base64.getDecoder().decode(b64);
        }
        return data;
    }
    private static String bytesToHex(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02x", x));
        return s.toString();
    }

    static int rename(Args a) throws Exception {
        Path dbPath = Paths.get(a.required("-db"));
        byte[] raw = Files.readAllBytes(dbPath);
        char[] pw = KdbCommands.password(a, dbPath);
        requirePw(raw, pw);
        String oldL = a.required("-label");
        String newL = a.required("-new_label");
        KdbKeyDatabase db = KdbKeyDatabase.read(raw);
        KdbRecord r = db.find(oldL);
        if (r == null) throw new IllegalArgumentException("label not found: " + oldL);
        db.remove(oldL);
        if (r.hasPrivateKey()) {
            db.add(KdbRecord.personalRecord(newL, r.certificate(), r.encryptedKeyDer()));
        } else {
            db.add(KdbRecord.caRecord(newL, r.certificate()));
        }
        db.write(dbPath, pw);
        System.out.println("Renamed '" + oldL + "' to '" + newL + "'");
        return 0;
    }

    /** Imports all entries from a PKCS#12 file into the key database. */
    static int importP12(Args a) throws Exception {
        Path dbPath = Paths.get(a.required("-db"));
        byte[] raw = Files.readAllBytes(dbPath);
        char[] dbPw = KdbCommands.password(a, dbPath);
        requirePw(raw, dbPw);
        Path src = Paths.get(a.required("-file"));
        char[] srcPw = (a.value("-target_pw") != null ? a.value("-target_pw") : new String(dbPw)).toCharArray();

        KeyStore p12 = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(src)) { p12.load(in, srcPw); }
        KdbKeyDatabase db = KdbKeyDatabase.read(raw);
        int n = 0;
        for (Enumeration<String> e = p12.aliases(); e.hasMoreElements();) {
            String alias = e.nextElement();
            String label = a.value("-label", alias);
            if (p12.isKeyEntry(alias)) {
                PrivateKey key = (PrivateKey) p12.getKey(alias, srcPw);
                Certificate[] chain = p12.getCertificateChain(alias);
                X509Certificate cert = (X509Certificate) chain[0];
                byte[] enc = Pbes2.encrypt(key, dbPw);
                db.add(KdbRecord.personalRecord(label, cert, enc));
                n++;
                // Store each signer in the chain as a separate trusted-certificate record,
                // the way gskcapicmd does, so the signing chain survives the import.
                for (int i = 1; i < chain.length; i++) {
                    if (!(chain[i] instanceof X509Certificate)) {
                        continue;
                    }
                    X509Certificate ca = (X509Certificate) chain[i];
                    if (containsCertificate(db, ca)) {
                        continue;
                    }
                    db.add(KdbRecord.caRecord(uniqueLabel(db, signerLabel(ca)), ca));
                    n++;
                }
            } else {
                db.add(KdbRecord.caRecord(label, (X509Certificate) p12.getCertificate(alias)));
                n++;
            }
        }
        db.write(dbPath, dbPw);
        System.out.println("Imported " + n + " entr" + (n == 1 ? "y" : "ies") + " into " + dbPath);
        return 0;
    }

    private static void requirePw(byte[] raw, char[] pw) {
        if (!KdbKeyDatabase.verify(raw, pw)) {
            throw new IllegalArgumentException("the database password is incorrect");
        }
    }

    private static X509Certificate readCert(Path file) throws Exception {
        byte[] data = Files.readAllBytes(file);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(data));
    }

    /** True if a certificate equal to {@code cert} is already stored under any label. */
    private static boolean containsCertificate(KdbKeyDatabase db, X509Certificate cert) {
        for (KdbRecord record : db.records()) {
            for (X509Certificate existing : record.certificates()) {
                if (existing.equals(cert)) {
                    return true;
                }
            }
        }
        return false;
    }

    /** Derives a signer label from a certificate's subject CN, falling back to the full DN. */
    private static String signerLabel(X509Certificate cert) {
        String dn = cert.getSubjectX500Principal().getName();
        try {
            for (javax.naming.ldap.Rdn rdn : new javax.naming.ldap.LdapName(dn).getRdns()) {
                if ("CN".equalsIgnoreCase(rdn.getType())) {
                    String cn = String.valueOf(rdn.getValue()).trim();
                    if (!cn.isEmpty()) {
                        return cn;
                    }
                }
            }
        } catch (javax.naming.InvalidNameException e) {
            // fall through to the raw DN
        }
        return dn.isEmpty() ? "signer" : dn;
    }

    /** Makes {@code base} unique among existing labels by appending " (n)" on collision. */
    private static String uniqueLabel(KdbKeyDatabase db, String base) {
        if (db.find(base) == null) {
            return base;
        }
        for (int n = 2; ; n++) {
            String candidate = base + " (" + n + ")";
            if (db.find(candidate) == null) {
                return candidate;
            }
        }
    }
}
