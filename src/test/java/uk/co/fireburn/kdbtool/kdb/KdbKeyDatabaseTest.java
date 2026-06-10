package uk.co.fireburn.kdbtool.kdb;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import org.junit.Test;

/** Round-trip tests for the native CMS key-database engine (no native binary needed). */
public class KdbKeyDatabaseTest {

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        return g.generateKeyPair();
    }

    @Test
    public void emptyDatabaseRoundTripsAndVerifies() {
        KdbKeyDatabase db = KdbKeyDatabase.create();
        byte[] bytes = db.serialize("secret".toCharArray());
        assertTrue(KdbKeyDatabase.isKdb(bytes));
        assertTrue(KdbKeyDatabase.verify(bytes, "secret".toCharArray()));
        assertFalse(KdbKeyDatabase.verify(bytes, "wrong".toCharArray()));
        assertEquals(0, KdbKeyDatabase.read(bytes).records().size());
    }

    @Test
    public void caCertificateRoundTrips() throws Exception {
        KeyPair kp = rsa();
        X509Certificate cert = X509Builder.selfSigned("CN=Root,O=T", kp, 365, "SHA256withRSA");
        KdbKeyDatabase db = KdbKeyDatabase.create();
        db.add(KdbRecord.caRecord("root", cert));
        byte[] bytes = db.serialize("pw".toCharArray());

        KdbKeyDatabase back = KdbKeyDatabase.read(bytes);
        assertEquals(1, back.records().size());
        KdbRecord r = back.find("root");
        assertNotNull(r);
        assertFalse(r.hasPrivateKey());
        assertEquals(cert.getSubjectX500Principal(), r.certificate().getSubjectX500Principal());
    }

    @Test
    public void personalCertificateAndKeyRoundTrip() throws Exception {
        KeyPair kp = rsa();
        X509Certificate cert = X509Builder.selfSigned("CN=me", kp, 365, "SHA256withRSA");
        byte[] enc = Pbes2.encrypt(kp.getPrivate(), "pw".toCharArray());
        KdbKeyDatabase db = KdbKeyDatabase.create();
        db.add(KdbRecord.personalRecord("me", cert, enc));
        byte[] bytes = db.serialize("pw".toCharArray());

        KdbRecord r = KdbKeyDatabase.read(bytes).find("me");
        assertTrue(r.hasPrivateKey());
        PrivateKey recovered = r.privateKey("pw".toCharArray());
        assertEquals(kp.getPrivate(), recovered);
    }

    @Test
    public void emptyPasswordRoundTripsAndVerifies() {
        KdbKeyDatabase db = KdbKeyDatabase.create();
        byte[] bytes = db.serialize(new char[0]);
        assertTrue(KdbKeyDatabase.verify(bytes, new char[0]));
        assertFalse(KdbKeyDatabase.verify(bytes, "secret".toCharArray()));
        assertEquals(0, KdbKeyDatabase.read(bytes).records().size());
    }

    @Test
    public void version4DatabaseRoundTripsAndVerifies() throws Exception {
        KeyPair kp = rsa();
        X509Certificate cert = X509Builder.selfSigned("CN=Root,O=T", kp, 365, "SHA256withRSA");
        KdbKeyDatabase db = KdbKeyDatabase.create().version(KdbKeyDatabase.Version.V4);
        db.add(KdbRecord.caRecord("root", cert));
        byte[] bytes = db.serialize("secret".toCharArray());

        // v4 header: magic 37 48 04, salt(24) + 2 * HMAC-SHA1(20) = 0x58 bytes before the records
        assertEquals(0x04, bytes[2]);
        assertEquals(0x58 + db.slotSize(), bytes.length);
        assertTrue(KdbKeyDatabase.isKdb(bytes));
        assertTrue(KdbKeyDatabase.isKeyDatabase(bytes));
        assertTrue(KdbKeyDatabase.verify(bytes, "secret".toCharArray()));
        assertFalse(KdbKeyDatabase.verify(bytes, "wrong".toCharArray()));

        KdbKeyDatabase back = KdbKeyDatabase.read(bytes);
        assertEquals(KdbKeyDatabase.Version.V4, back.version());
        assertEquals(cert.getSubjectX500Principal(),
            back.find("root").certificate().getSubjectX500Principal());

        // version survives a read-modify-write cycle
        assertEquals(0x04, back.serialize("secret".toCharArray())[2]);
    }

    @Test
    public void slotSizeGrowsForOversizedRecords() throws Exception {
        KeyPair kp = rsa();
        X509Certificate cert = X509Builder.selfSigned("CN=big", kp, 365, "SHA256withRSA");
        // an artificially long label pushes the record past the 5000-byte default slot
        String label = new String(new char[KdbKeyDatabase.DEFAULT_SLOT_SIZE]).replace('\0', 'x');
        KdbKeyDatabase db = KdbKeyDatabase.create();
        db.add(KdbRecord.caRecord(label, cert));
        byte[] bytes = db.serialize("pw".toCharArray());

        KdbKeyDatabase back = KdbKeyDatabase.read(bytes);
        assertTrue(back.slotSize() > KdbKeyDatabase.DEFAULT_SLOT_SIZE);
        assertEquals(label, back.records().get(0).label());
    }

    @Test
    public void changingPasswordReEncryptsKeys() throws Exception {
        KeyPair kp = rsa();
        X509Certificate cert = X509Builder.selfSigned("CN=me", kp, 365, "SHA256withRSA");
        KdbKeyDatabase db = KdbKeyDatabase.create();
        db.add(KdbRecord.personalRecord("me", cert, Pbes2.encrypt(kp.getPrivate(), "old".toCharArray())));
        byte[] v1 = db.serialize("old".toCharArray());

        // simulate changepw: re-encrypt under new password, re-sign header
        KdbKeyDatabase reread = KdbKeyDatabase.read(v1);
        KdbRecord r = reread.find("me");
        byte[] newEnc = Pbes2.encrypt(r.privateKey("old".toCharArray()), "new".toCharArray());
        reread.remove("me");
        reread.add(KdbRecord.personalRecord("me", r.certificate(), newEnc));
        byte[] v2 = reread.serialize("new".toCharArray());

        assertTrue(KdbKeyDatabase.verify(v2, "new".toCharArray()));
        assertFalse(KdbKeyDatabase.verify(v2, "old".toCharArray()));
        assertEquals(kp.getPrivate(),
            KdbKeyDatabase.read(v2).find("me").privateKey("new".toCharArray()));
    }
}
