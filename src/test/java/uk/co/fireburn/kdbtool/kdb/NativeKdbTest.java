package uk.co.fireburn.kdbtool.kdb;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

import uk.co.fireburn.kdbtool.stash.StashFile;

/**
 * Compatibility tests against key databases produced by the native GSKit tooling. The fixtures in
 * test/resources/testdata were generated with gskcapicmd (key store password "password"):
 *   mixed.kdb   - RSA key pair, EC (P-256) key pair and two trusted CA certificates
 *   chained.kdb - a server key pair plus its issuing intermediate and root CA certificates
 */
public class NativeKdbTest {

    private static final char[] PASSWORD = "password".toCharArray();

    private static KdbKeyDatabase load(String name) throws Exception {
        try (InputStream in = NativeKdbTest.class.getResourceAsStream("/testdata/" + name)) {
            assertNotNull("missing test fixture " + name, in);
            return KdbKeyDatabase.read(readAll(in));
        }
    }

    private static byte[] readAll(InputStream in) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) != -1) {
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    private static Map<String, KdbRecord> byLabel(KdbKeyDatabase db) {
        Map<String, KdbRecord> map = new HashMap<>();
        for (KdbRecord r : db.records()) {
            map.put(r.label(), r);
        }
        return map;
    }

    @Test
    public void readsEntryStructureOfNativeKdb() throws Exception {
        Map<String, KdbRecord> records = byLabel(load("mixed.kdb"));

        assertEquals(4, records.size());
        assertTrue(records.get("rsa-keypair").hasPrivateKey());
        assertTrue(records.get("ec-keypair").hasPrivateKey());
        assertFalse(records.get("trusted-root-ca").hasPrivateKey());
        assertFalse(records.get("trusted-intermediate-ca").hasPrivateKey());
    }

    @Test
    public void recoversRsaAndEcPrivateKeysFromNativeKdb() throws Exception {
        Map<String, KdbRecord> records = byLabel(load("mixed.kdb"));

        PrivateKey rsa = records.get("rsa-keypair").privateKey(PASSWORD);
        assertEquals("RSA", rsa.getAlgorithm());
        assertEquals("RSA", records.get("rsa-keypair").certificate().getPublicKey().getAlgorithm());

        PrivateKey ec = records.get("ec-keypair").privateKey(PASSWORD);
        assertEquals("EC", ec.getAlgorithm());
        assertEquals("EC", records.get("ec-keypair").certificate().getPublicKey().getAlgorithm());
    }

    @Test
    public void trustedCaCertificatesAreReadCorrectly() throws Exception {
        Map<String, KdbRecord> records = byLabel(load("mixed.kdb"));

        X509Certificate root = records.get("trusted-root-ca").certificate();
        assertTrue(root.getSubjectX500Principal().getName().contains("Example Root CA"));
        // A CA certificate carries basic constraints (getBasicConstraints() != -1)
        assertTrue(root.getBasicConstraints() != -1);
    }

    @Test
    public void readsCertificateChainLinkageFromNativeKdb() throws Exception {
        Map<String, KdbRecord> records = byLabel(load("chained.kdb"));

        X509Certificate leaf = records.get("server-cert").certificate();
        X509Certificate intermediate = records.get("intermediate-ca").certificate();
        X509Certificate root = records.get("root-ca").certificate();

        assertEquals(intermediate.getSubjectX500Principal(), leaf.getIssuerX500Principal());
        assertEquals(root.getSubjectX500Principal(), intermediate.getIssuerX500Principal());
        assertEquals(root.getSubjectX500Principal(), root.getIssuerX500Principal());

        assertTrue(records.get("server-cert").hasPrivateKey());
        assertNotNull(records.get("server-cert").privateKey(PASSWORD));
    }

    @Test
    public void stashFileYieldsTheKeyStorePassword() throws Exception {
        try (InputStream in = NativeKdbTest.class.getResourceAsStream("/testdata/mixed.sth")) {
            assertNotNull(in);
            assertEquals("password", StashFile.decode(readAll(in)));
        }
    }

    @Test
    public void verifiesNativeKdbPassword() throws Exception {
        try (InputStream in = NativeKdbTest.class.getResourceAsStream("/testdata/mixed.kdb")) {
            byte[] raw = readAll(in);
            assertTrue(KdbKeyDatabase.verify(raw, PASSWORD));
            assertFalse(KdbKeyDatabase.verify(raw, "wrong".toCharArray()));
        }
    }
}
