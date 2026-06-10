package uk.co.fireburn.kdbtool.kdb;

import uk.co.fireburn.kdbtool.asn1.Der;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Encrypts a private key as a PKCS#8 {@code EncryptedPrivateKeyInfo} using PBES2
 * (PBKDF2-HMAC-SHA384 + AES-256-CBC) — the scheme the CMS key-database format uses for private keys.
 *
 * <p>Decryption is done from PBES2 primitives (PBKDF2 + AES/CBC) rather than via
 * {@link javax.crypto.EncryptedPrivateKeyInfo}'s convenience methods. On JDK 8 the convenience path
 * resolves the algorithm by the name the JDK derives from the DER, which for PBES2 is the bare OID
 * {@code 1.2.840.113549.1.5.13} — no provider registers a service under that name until JDK 9 added
 * a generic "PBES2" implementation. Decomposing into PBKDF2 + AES keeps it working on JDK 8+.
 */
public final class Pbes2 {
    private static final String ALG = "PBEWithHmacSHA384AndAES_256";
    /** OID 1.2.840.113549.1.5.13 = id-PBES2. */
    private static final byte[] PBES2_OID =
        {0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x05, 0x0d};

    // PBKDF2 PRF OIDs (1.2.840.113549.2.x), by hex of the OID content bytes.
    private static final String PRF_PREFIX = "2a864886f70d02";

    private Pbes2() {}

    /** DER of an EncryptedPrivateKeyInfo wrapping {@code key}, encrypted with {@code password}. */
    public static byte[] encrypt(PrivateKey key, char[] password) throws Exception {
        return encryptBytes(key.getEncoded(), password);
    }

    /** PBES2-encrypts arbitrary bytes, returning an EncryptedPrivateKeyInfo-shaped DER. */
    public static byte[] encryptBytes(byte[] plaintext, char[] password) throws Exception {
        SecretKeyFactory skf = SecretKeyFactory.getInstance(ALG);
        SecretKey sk = skf.generateSecret(new PBEKeySpec(password));
        Cipher c = Cipher.getInstance(ALG);
        c.init(Cipher.ENCRYPT_MODE, sk);
        byte[] enc = c.doFinal(plaintext);
        byte[] algId = Der.sequence(Der.encode(0x06, PBES2_OID), c.getParameters().getEncoded());
        return Der.sequence(algId, Der.encode(0x04, enc));
    }

    /** Decrypts an EncryptedPrivateKeyInfo-shaped DER back to its plaintext bytes. */
    public static byte[] decryptBytes(byte[] epkiDer, char[] password) throws Exception {
        // EncryptedPrivateKeyInfo ::= SEQUENCE { encryptionAlgorithm AlgorithmIdentifier, encryptedData OCTET STRING }
        List<Der.Node> epki = Der.parse(epkiDer).children();
        byte[] encryptedData = epki.get(1).content();

        // encryptionAlgorithm ::= SEQUENCE { OID id-PBES2, PBES2-params }
        // PBES2-params ::= SEQUENCE { keyDerivationFunc AlgorithmIdentifier, encryptionScheme AlgorithmIdentifier }
        List<Der.Node> algId = epki.get(0).children();
        if (!hex(algId.get(0).content()).equals(hex(PBES2_OID))) {
            throw new java.security.NoSuchAlgorithmException("not a PBES2 EncryptedPrivateKeyInfo");
        }
        List<Der.Node> pbes2Params = algId.get(1).children();
        List<Der.Node> kdf = pbes2Params.get(0).children();           // PBKDF2 AlgorithmIdentifier
        List<Der.Node> scheme = pbes2Params.get(1).children();        // encryptionScheme AlgorithmIdentifier

        // PBKDF2-params ::= SEQUENCE { salt OCTET STRING, iterationCount INTEGER,
        //                              keyLength INTEGER OPTIONAL, prf AlgorithmIdentifier DEFAULT hmacSHA1 }
        List<Der.Node> kdfParams = kdf.get(1).children();
        byte[] salt = kdfParams.get(0).content();
        int iterations = new BigInteger(1, kdfParams.get(1).content()).intValue();
        Integer keyLengthBits = null;
        String prf = "PBKDF2WithHmacSHA1"; // PBKDF2 default PRF
        for (int i = 2; i < kdfParams.size(); i++) {
            Der.Node n = kdfParams.get(i);
            if (n.tag == 0x02) {
                keyLengthBits = new BigInteger(1, n.content()).intValue() * 8;
            } else if (n.tag == 0x30) {
                prf = prfName(n.children().get(0).content());
            }
        }

        // encryptionScheme ::= SEQUENCE { OID aesXXX-CBC, iv OCTET STRING }
        byte[] iv = scheme.get(1).content();
        if (keyLengthBits == null) keyLengthBits = aesKeyBits(scheme.get(0).content());

        SecretKeyFactory skf = SecretKeyFactory.getInstance(prf);
        byte[] keyBytes = skf.generateSecret(
            new PBEKeySpec(password, salt, iterations, keyLengthBits)).getEncoded();
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, "AES"), new IvParameterSpec(iv));
        return c.doFinal(encryptedData);
    }

    /** Maps a PBKDF2 PRF OID to its JDK {@code PBKDF2WithHmacSHA*} factory name. */
    private static String prfName(byte[] oid) throws java.security.NoSuchAlgorithmException {
        String h = hex(oid);
        if (!h.startsWith(PRF_PREFIX)) {
            throw new java.security.NoSuchAlgorithmException("unsupported PBKDF2 PRF OID");
        }
        switch (h.substring(PRF_PREFIX.length())) {
            case "07": return "PBKDF2WithHmacSHA1";
            case "08": return "PBKDF2WithHmacSHA224";
            case "09": return "PBKDF2WithHmacSHA256";
            case "0a": return "PBKDF2WithHmacSHA384";
            case "0b": return "PBKDF2WithHmacSHA512";
            default: throw new java.security.NoSuchAlgorithmException("unsupported PBKDF2 PRF OID " + h);
        }
    }

    /** AES key size in bits from an aesXXX-CBC OID (2.16.840.1.101.3.4.1.{2,22,42}). */
    private static int aesKeyBits(byte[] oid) throws java.security.NoSuchAlgorithmException {
        String h = hex(oid);
        if (h.endsWith("02")) return 128;
        if (h.endsWith("16")) return 192;
        if (h.endsWith("2a")) return 256;
        throw new java.security.NoSuchAlgorithmException("unsupported AES-CBC OID " + h);
    }

    private static String hex(byte[] b) {
        StringBuilder s = new StringBuilder(b.length * 2);
        for (byte x : b) s.append(String.format("%02x", x));
        return s.toString();
    }
}
