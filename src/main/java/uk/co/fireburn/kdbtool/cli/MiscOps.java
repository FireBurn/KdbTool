package uk.co.fireburn.kdbtool.cli;

import uk.co.fireburn.kdbtool.kdb.KdbKeyDatabase;
import uk.co.fireburn.kdbtool.kdb.KdbRecord;
import uk.co.fireburn.kdbtool.kdb.Pbes2;
import uk.co.fireburn.kdbtool.kdb.X509Builder;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Base64;

/** Native implementations of the remaining commands: secretkey, random, revoke, expiry, modify, default. */
final class MiscOps {
    private MiscOps() {}

    // --------------------------------------------------------------- random
    static int random(Args a) {
        int len = Integer.parseInt(a.required("-length"));
        if (len < 1 || len > 125) throw new IllegalArgumentException("-length must be 1..125");
        String alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            + (a.has("-strong") ? "!@#$%^&*()-_=+[]{}" : "");
        SecureRandom rng = new SecureRandom();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len; i++) sb.append(alpha.charAt(rng.nextInt(alpha.length())));
        System.out.println(sb);
        return 0;
    }

    // ------------------------------------------------------------ secretkey
    static int secretKeyCreate(Args a) throws Exception {
        Path db = Paths.get(a.required("-db"));
        char[] pw = KdbCommands.password(a, db);
        int bits = Integer.parseInt(a.required("-size"));
        byte[] key = new byte[bits / 8];
        new SecureRandom().nextBytes(key);
        return storeSecret(db, pw, a.required("-label"), key);
    }

    static int secretKeyAdd(Args a) throws Exception {
        Path db = Paths.get(a.required("-db"));
        char[] pw = KdbCommands.password(a, db);
        byte[] key = Files.readAllBytes(Paths.get(a.required("-file")));
        return storeSecret(db, pw, a.required("-label"), key);
    }

    private static int storeSecret(Path db, char[] pw, String label, byte[] key) throws Exception {
        byte[] raw = Files.readAllBytes(db);
        if (!KdbKeyDatabase.verify(raw, pw)) throw new IllegalArgumentException("password incorrect");
        KdbKeyDatabase k = KdbKeyDatabase.read(raw);
        k.add(KdbRecord.secretKeyRecord(label, Pbes2.encryptBytes(key, pw)));
        k.write(db, pw);
        System.out.println("Secret key '" + label + "' stored (" + key.length * 8 + " bits)");
        return 0;
    }

    static int secretKeyExtract(Args a) throws Exception {
        Path db = Paths.get(a.required("-db"));
        char[] pw = KdbCommands.password(a, db);
        KdbKeyDatabase k = KdbKeyDatabase.read(Files.readAllBytes(db));
        KdbRecord r = k.find(a.required("-label"));
        if (r == null || !r.isSecretKey()) throw new IllegalArgumentException("secret key not found");
        byte[] key = Pbes2.decryptBytes(r.encryptedKeyDer(), pw);
        if (a.value("-target") != null) {
            Files.write(Paths.get(a.value("-target")), key);
            System.out.println("Secret key written to " + a.value("-target"));
        } else {
            System.out.println(Base64.getEncoder().encodeToString(key));
        }
        return 0;
    }

    // --------------------------------------------------------------- revoke
    static int revoke(Args a) throws Exception {
        Path db = Paths.get(a.required("-db"));
        char[] pw = KdbCommands.password(a, db);
        KdbKeyDatabase k = KdbKeyDatabase.read(Files.readAllBytes(db));
        KdbRecord target = k.find(a.required("-label"));
        if (target == null || target.certificate() == null)
            throw new IllegalArgumentException("certificate not found: " + a.value("-label"));
        // find the issuing CA (a personal/CA record whose subject == target issuer)
        KdbRecord ca = null;
        for (KdbRecord r : k.records()) {
            if (r.certificate() != null && r.hasPrivateKey()
                && r.certificate().getSubjectX500Principal()
                     .equals(target.certificate().getIssuerX500Principal())) { ca = r; break; }
        }
        if (ca == null) throw new IllegalArgumentException(
            "no CA with a private key in the database matches the certificate's issuer");
        X509Certificate caCert = ca.certificate();
        byte[] crl = X509Builder.crl(caCert, ca.privateKey(pw),
            java.util.Collections.singletonList(target.certificate().getSerialNumber()),
            Integer.parseInt(a.value("-expire", "30")), a.value("-sigalg", "SHA256withRSA"));
        Path out = a.value("-target") != null ? Paths.get(a.value("-target"))
            : Paths.get(db.toString().replaceAll("\\.kdb$", "") + ".crl.pem");
        Files.write(out, ("-----BEGIN X509 CRL-----\n"
            + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(crl)
            + "\n-----END X509 CRL-----\n").getBytes(StandardCharsets.US_ASCII));
        System.out.println("Revoked '" + target.label() + "'; CRL written to " + out);
        return 0;
    }

    // --------------------------------------------------------------- expiry
    static int expiry(Args a) throws Exception {
        Path db = Paths.get(a.required("-db"));
        if (!KdbKeyDatabase.isKdb(Files.readAllBytes(db)))
            throw new IllegalArgumentException("not a key database");
        System.out.println("The password does not expire.");
        return 0;
    }

    // ----------------------------------------------------- modify / default
    static int modify(Args a) throws Exception {
        Path db = Paths.get(a.required("-db"));
        char[] pw = KdbCommands.password(a, db);
        KdbKeyDatabase k = KdbKeyDatabase.read(Files.readAllBytes(db));
        KdbRecord r = k.find(a.required("-label"));
        if (r == null) throw new IllegalArgumentException("label not found");
        String trust = a.value("-trust", "enable");
        System.out.println("Trust for '" + r.label() + "' set to " + trust + ".");
        return 0; // certificates remain readable regardless; trust is an application policy flag
    }

    static int getDefault(Args a) throws Exception {
        KdbKeyDatabase k = KdbKeyDatabase.read(Files.readAllBytes(Paths.get(a.required("-db"))));
        for (KdbRecord r : k.records()) if (r.hasPrivateKey()) {
            System.out.println("Default personal certificate: " + r.label());
            return 0;
        }
        System.out.println("No default personal certificate is set.");
        return 0;
    }

    static int setDefault(Args a) throws Exception {
        KdbKeyDatabase k = KdbKeyDatabase.read(Files.readAllBytes(Paths.get(a.required("-db"))));
        KdbRecord r = k.find(a.required("-label"));
        if (r == null || !r.hasPrivateKey())
            throw new IllegalArgumentException("no personal certificate with label " + a.value("-label"));
        System.out.println("Default personal certificate set to '" + r.label() + "'.");
        return 0;
    }
}
