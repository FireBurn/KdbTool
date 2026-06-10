package uk.co.fireburn.kdbtool.cli;

import uk.co.fireburn.kdbtool.asn1.Der;
import uk.co.fireburn.kdbtool.kdb.KdbKeyDatabase;
import uk.co.fireburn.kdbtool.kdb.KdbRecord;
import uk.co.fireburn.kdbtool.kdb.Pbes2;
import uk.co.fireburn.kdbtool.kdb.X509Builder;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

/** Native {@code -certreq} operations, backed by the request database ({@code .rdb}). */
final class ReqOps {
    private ReqOps() {}

    private static Path rdb(String db) {
        return Paths.get(db.endsWith(".kdb") ? db.substring(0, db.length() - 4) + ".rdb" : db + ".rdb");
    }

    private static KdbKeyDatabase openOrCreate(Path rdb, char[] pw) throws Exception {
        if (Files.exists(rdb)) {
            byte[] raw = Files.readAllBytes(rdb);
            if (!KdbKeyDatabase.verify(raw, pw)) throw new IllegalArgumentException("password incorrect");
            return KdbKeyDatabase.read(raw);
        }
        return KdbKeyDatabase.create(KdbKeyDatabase.Kind.RDB);
    }

    static int create(Args a) throws Exception {
        String db = a.required("-db");
        char[] pw = KdbCommands.password(a, Paths.get(db));
        String label = a.required("-label");
        String dn = a.required("-dn");
        int size = Integer.parseInt(a.value("-size", "2048"));
        String sigAlg = a.value("-sigalg", "SHA256withRSA");
        Path file = Paths.get(a.required("-file"));

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(size);
        KeyPair kp = kpg.generateKeyPair();
        byte[] csr = X509Builder.csr(dn, kp, sigAlg);
        Files.write(file, pem("NEW CERTIFICATE REQUEST", csr).getBytes());

        Path rdbPath = rdb(db);
        KdbKeyDatabase rdb = openOrCreate(rdbPath, pw);
        rdb.add(KdbRecord.requestRecord(label, csr, Pbes2.encrypt(kp.getPrivate(), pw)));
        rdb.write(rdbPath, pw);
        System.out.println("Certificate request created under label '" + label
            + "' and written to " + file);
        return 0;
    }

    static int list(Args a) throws Exception {
        KdbKeyDatabase rdb = readRdb(a);
        if (rdb == null || rdb.records().isEmpty()) {
            System.out.println("No certificate requests were found");
            return 0;
        }
        System.out.println("Certificate requests found");
        for (KdbRecord r : rdb.records()) System.out.println("\t" + r.label());
        return 0;
    }

    static int details(Args a) throws Exception {
        KdbRecord r = require(a);
        Der.Node csr = Der.parse(r.csrDer());
        Der.Node cri = csr.children().get(0);
        byte[] subject = cri.children().get(1).der();
        System.out.println("Label: " + r.label());
        System.out.println("Subject: " + new javax.security.auth.x500.X500Principal(subject).getName());
        System.out.println("PKCS#10 request size: " + r.csrDer().length + " bytes");
        return 0;
    }

    static int extract(Args a) throws Exception {
        KdbRecord r = require(a);
        Path target = Paths.get(a.required("-target"));
        Files.write(target, pem("NEW CERTIFICATE REQUEST", r.csrDer()).getBytes());
        System.out.println("Certificate request extracted to " + target);
        return 0;
    }

    static int delete(Args a) throws Exception {
        String db = a.required("-db");
        char[] pw = KdbCommands.password(a, Paths.get(db));
        Path rdbPath = rdb(db);
        byte[] raw = Files.readAllBytes(rdbPath);
        if (!KdbKeyDatabase.verify(raw, pw)) throw new IllegalArgumentException("password incorrect");
        KdbKeyDatabase rdb = KdbKeyDatabase.read(raw);
        String label = a.required("-label");
        if (!rdb.remove(label)) throw new IllegalArgumentException("request not found: " + label);
        rdb.write(rdbPath, pw);
        System.out.println("Deleted certificate request '" + label + "'");
        return 0;
    }

    static int recreate(Args a) throws Exception {
        KdbRecord r = require(a);
        Path target = Paths.get(a.required("-file"));
        Files.write(target, pem("NEW CERTIFICATE REQUEST", r.csrDer()).getBytes());
        System.out.println("Recreated certificate request for '" + r.label() + "' to " + target);
        return 0;
    }

    // --------------------------------------------------------------- helpers

    private static KdbKeyDatabase readRdb(Args a) throws Exception {
        Path rdbPath = rdb(a.required("-db"));
        if (!Files.exists(rdbPath)) return null;
        return KdbKeyDatabase.read(Files.readAllBytes(rdbPath));
    }

    private static KdbRecord require(Args a) throws Exception {
        KdbKeyDatabase rdb = readRdb(a);
        if (rdb == null) throw new IllegalArgumentException("no request database");
        KdbRecord r = rdb.find(a.required("-label"));
        if (r == null || !r.isRequest()) throw new IllegalArgumentException("request not found: " + a.value("-label"));
        return r;
    }

    private static String pem(String type, byte[] der) {
        return "-----BEGIN " + type + "-----\n"
            + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(der)
            + "\n-----END " + type + "-----\n";
    }
}
