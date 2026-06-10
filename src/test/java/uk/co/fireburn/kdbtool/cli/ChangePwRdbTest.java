package uk.co.fireburn.kdbtool.cli;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import uk.co.fireburn.kdbtool.kdb.KdbKeyDatabase;
import uk.co.fireburn.kdbtool.kdb.KdbRecord;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import org.junit.Test;

/**
 * Regression test: {@code -keydb -changepw} must re-key the companion request database (.rdb)
 * as well as the .kdb, so {@code -certreq} keeps working after a password change.
 */
public class ChangePwRdbTest {

    @Test
    public void changePwReKeysCompanionRequestDatabase() throws Exception {
        Path dir = Files.createTempDirectory("kdbtest");
        Path kdb = dir.resolve("ca.kdb");
        Path rdb = dir.resolve("ca.rdb");
        Path csr = dir.resolve("r.csr");
        try {
            run("-keydb", "-create", "-db", kdb.toString(), "-pw", "old");
            // certreq -create writes the encrypted request key into ca.rdb under "old"
            run("-certreq", "-create", "-db", kdb.toString(), "-pw", "old",
                "-label", "req1", "-dn", "CN=a", "-file", csr.toString(), "-size", "2048");
            assertTrue("request db should exist", Files.exists(rdb));
            PrivateKey before = requestKey(rdb, "old", "req1");

            run("-keydb", "-changepw", "-db", kdb.toString(), "-pw", "old", "-new_pw", "new");

            // both databases now open under the new password only
            assertTrue(KdbKeyDatabase.verify(Files.readAllBytes(kdb), "new".toCharArray()));
            assertTrue(KdbKeyDatabase.verify(Files.readAllBytes(rdb), "new".toCharArray()));
            // and the request's private key survives the re-encryption unchanged
            assertEquals(before, requestKey(rdb, "new", "req1"));
        } finally {
            deleteTree(dir);
        }
    }

    private static PrivateKey requestKey(Path rdb, String pw, String label) throws Exception {
        KdbRecord r = KdbKeyDatabase.read(Files.readAllBytes(rdb)).find(label);
        assertNotNull("request '" + label + "' present", r);
        assertTrue(r.isRequest());
        return r.privateKey(pw.toCharArray());
    }

    private static void run(String... argv) throws Exception {
        Args a = new Args(argv);
        if (argv[0].equals("-certreq")) { ReqOps.create(a); return; }
        switch (argv[1]) {
            case "-create":   KdbWrite.create(a); break;
            case "-changepw": KdbWrite.changePw(a); break;
            default: throw new IllegalArgumentException("unhandled: " + argv[1]);
        }
    }

    private static void deleteTree(Path dir) throws IOException {
        try (java.util.stream.Stream<Path> s = Files.walk(dir)) {
            s.sorted(java.util.Comparator.reverseOrder()).forEach(p -> {
                try { Files.deleteIfExists(p); } catch (IOException ignore) {}
            });
        }
    }
}
