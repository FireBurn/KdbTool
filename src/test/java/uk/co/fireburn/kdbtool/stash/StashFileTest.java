package uk.co.fireburn.kdbtool.stash;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * Verifies the stash decoder against real reference vectors
 * and confirms encode/decode round-trips for both formats.
 */
public class StashFileTest {

    /** A default v8 stash (193 bytes) for the password {@code password01}. */
    private static final byte[] V8_PASSWORD01 = hex(
        "869407d1f491d1dc7cc54d81eb0454fe25bc15ee7678d3d4ce9187cc34d4edba"
      + "dde2d1760571cd60ee06205e9b61389038ee3811db1a593768091924152d6808"
      + "f1b000458917d1d67b9991dbb91e1b701b928bb5f3c72bdb1408dc9c5aa8702f"
      + "4fac3b7aaa94f965ea9c6c0a4c085f7312b358c5a50f9c6a87247373de14db98"
      + "0c31153e92aa788605c9a966ec682c8140b84fa71164d57578e36053908ac2bc"
      + "f2bad52b8fdc6c06868e84dec4e78803b922fd803749f2fe8ffe049d5473314b"
      + "0b");

    /** {@code ... -v1stash} (legacy v1, 129 bytes). */
    private static final byte[] V1_PASSWORD01 = hex(
        "85948686829a8791c5c4f544936ce0e050c7fc8a973b5853563dfe11e1928cd7"
      + "28ef002676e4613f294286ebcb128007b36fe297cd81c126f7df969064c39ca0"
      + "1c9fd8e4bf11a4530a56949f0b10297331f3bf08e3f95c6d41d472834b235e35"
      + "a7daa6eeb9ad4e514e827f4712984daf4bc94890d1d84feb1ab1930f77c07303"
      + "7b");

    @Test
    public void decodesV8Stash() {
        assertEquals("password01", StashFile.decode(V8_PASSWORD01));
        assertEquals(StashFile.Version.V8, StashFile.versionOf(V8_PASSWORD01));
    }

    @Test
    public void decodesV1Stash() {
        assertEquals("password01", StashFile.decode(V1_PASSWORD01));
        assertEquals(StashFile.Version.V1, StashFile.versionOf(V1_PASSWORD01));
    }

    @Test
    public void roundTripsV8ForVariousLengths() {
        for (String pw : new String[] {
                "", "A", "AB", "short", "password01",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",          // exactly 32 (block boundary)
                "abcdefghij0123456789ABCDEFGHIJklmnopqrst",  // > 32, spans blocks
                "p@ss w0rd!#$%^&*()_+-=[]{}|;:,.<>?" }) {
            byte[] s = StashFile.encode(pw, StashFile.Version.V8);
            assertEquals(193, s.length);
            assertEquals("v8 round-trip for length " + pw.length(), pw, StashFile.decode(s));
        }
    }

    @Test
    public void roundTripsV1() {
        byte[] s = StashFile.encode("password01", StashFile.Version.V1);
        assertEquals(129, s.length);
        assertEquals("password01", StashFile.decode(s));
    }

    @Test
    public void encodeProducesDistinctButValidStashes() {
        byte[] s1 = StashFile.encode("hello", StashFile.Version.V8);
        byte[] s2 = StashFile.encode("hello", StashFile.Version.V8);
        assertTrue("random salt should differ", !java.util.Arrays.equals(s1, s2));
        assertEquals("hello", StashFile.decode(s1));
        assertEquals("hello", StashFile.decode(s2));
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsTamperedV8() {
        byte[] bad = V8_PASSWORD01.clone();
        bad[0] ^= 0x01; // breaks B = SHA256(0x01 || A)
        StashFile.decode(bad);
    }

    private static byte[] hex(String h) {
        byte[] out = new byte[h.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(h.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }
}
