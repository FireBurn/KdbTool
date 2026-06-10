package uk.co.fireburn.kdbtool.cli;

import uk.co.fireburn.kdbtool.kdb.KdbKeyDatabase;
import uk.co.fireburn.kdbtool.stash.StashFile;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Native Java tool for the CMS key-database ({@code .kdb}) and stash ({@code .sth}) formats.
 *
 * <p>Every supported operation runs with no native binaries and no third-party libraries — only
 * the JDK. Files written here are fully interoperable with the standard reference tooling.
 */
public final class KdbTool {

    public static void main(String[] argv) {
        try {
            System.exit(dispatch(argv));
        } catch (IllegalArgumentException e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(2);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        }
    }

    private static int dispatch(String[] argv) throws Exception {
        if (argv.length == 0 || isHelp(argv[0])) { usage(); return argv.length == 0 ? 1 : 0; }
        Args a = new Args(argv);
        // Global modifiers may precede the object; honour FIPS/locale/trace/prompt as no-ops.
        String object = argv[0];
        int oi = 0;
        while (oi < argv.length && isGlobal(argv[oi])) {
            oi += hasValue(argv[oi]) ? 2 : 1;
        }
        if (oi >= argv.length) return 0; // only global modifiers given
        object = argv[oi];
        String action = oi + 1 < argv.length ? argv[oi + 1] : "";

        switch (object) {
            case "-version":
                System.out.println("kdbtool (native Java CMS key-database tool) 1.0.0");
                return 0;
            case "-random":
                return MiscOps.random(a);
            case "-secretkey":
                switch (action) {
                    case "-create":  return MiscOps.secretKeyCreate(a);
                    case "-add":     return MiscOps.secretKeyAdd(a);
                    case "-extract": return MiscOps.secretKeyExtract(a);
                    default:         return notNative(argv);
                }
            case "decode": case "-getpw":
                return getPw(a);
            case "-keydb":
                switch (action) {
                    case "-getpw":   return getPw(a);
                    case "-stashpw": return stashPw(a);
                    case "-info":    return KdbCommands.info(a);
                    case "-list":    return keydbListTypes();
                    case "-verifypw":return verifyPw(a);
                    case "-create":  return KdbWrite.create(a);
                    case "-changepw":return KdbWrite.changePw(a);
                    case "-convert": return KdbWrite.convert(a);
                    case "-delete":  return KdbWrite.deleteDb(a);
                    case "-expiry":  return MiscOps.expiry(a);
                    default:         return notNative(argv);
                }
            case "-cert":
                switch (action) {
                    case "-list":     return KdbCommands.list(a);
                    case "-details":  return KdbCommands.details(a);
                    case "-extract":  return KdbCommands.extract(a);
                    case "-export":   return KdbCommands.export(a);
                    case "-extractkey": return KdbCommands.extractKey(a);
                    case "-validate": return KdbCommands.validate(a);
                    case "-add":      return CertOps.add(a);
                    case "-delete":   return CertOps.delete(a);
                    case "-import":   return CertOps.importP12(a);
                    case "-receive":  return CertOps.receive(a);
                    case "-create":   return CertOps.create(a);
                    case "-rename":   return CertOps.rename(a);
                    case "-sign":     return CertOps.sign(a);
                    case "-revoke":   return MiscOps.revoke(a);
                    case "-modify":   return MiscOps.modify(a);
                    case "-getdefault": return MiscOps.getDefault(a);
                    case "-setdefault": return MiscOps.setDefault(a);
                    default:          return notNative(argv);
                }
            case "-certreq":
                switch (action) {
                    case "-create":   return ReqOps.create(a);
                    case "-list":     return ReqOps.list(a);
                    case "-details":  return ReqOps.details(a);
                    case "-extract":  return ReqOps.extract(a);
                    case "-delete":   return ReqOps.delete(a);
                    case "-recreate": return ReqOps.recreate(a);
                    default:          return notNative(argv);
                }
            default:
                return notNative(argv);
        }
    }

    private static boolean isGlobal(String s) {
        return s.equals("-fips") || s.equals("-locale") || s.equals("-trace") || s.equals("-prompt");
    }
    private static boolean hasValue(String s) {
        return s.equals("-locale") || s.equals("-trace");
    }

    // ------------------------------------------------------- native commands

    private static int getPw(Args a) throws Exception {
        Path stash;
        String stashed = a.value("-stashed");
        String db = a.value("-db");
        if (stashed != null) stash = Paths.get(stashed);
        else if (db != null) stash = StashPaths.derive(db);
        else {
            String last = a.raw.get(a.raw.size() - 1);
            stash = last.endsWith(".sth") ? Paths.get(last) : StashPaths.derive(last);
        }
        if (!Files.exists(stash)) {
            throw new IllegalArgumentException("stash file not found: " + stash
                + (db != null ? " (the .kdb itself stores only a salted hash; the recoverable "
                              + "password lives in its .sth)" : ""));
        }
        byte[] data = Files.readAllBytes(stash);
        System.out.println(StashFile.decode(data));
        System.err.println("(decoded " + StashFile.versionOf(data) + " stash: " + stash + ")");
        return 0;
    }

    private static int stashPw(Args a) throws Exception {
        String db = a.required("-db");
        String pw = a.value("-pw");
        if (pw == null && System.console() != null) {
            pw = new String(System.console().readPassword("Enter the database password: "));
        }
        if (pw == null) throw new IllegalArgumentException("-pw required");
        StashFile.Version v = a.has("-v1stash") ? StashFile.Version.V1 : StashFile.Version.V8;
        Path stash = StashPaths.derive(db);
        Files.write(stash, StashFile.encode(pw, v));
        try {
            Files.setPosixFilePermissions(stash,
                java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        } catch (Exception ignore) {}
        System.out.println("The password has been stashed in " + stash + " (" + v + ")");
        return 0;
    }

    private static int verifyPw(Args a) throws Exception {
        Path dbPath = Paths.get(a.required("-db"));
        char[] pw = KdbCommands.password(a, dbPath);
        boolean ok = KdbKeyDatabase.verify(Files.readAllBytes(dbPath), pw);
        System.out.println(ok ? "Password is correct." : "Password is INCORRECT.");
        return ok ? 0 : 1;
    }

    private static int keydbListTypes() {
        System.out.println("cms");
        System.out.println("kdb");
        System.out.println("p12");
        System.out.println("pkcs12");
        return 0;
    }

    private static int notNative(String[] argv) {
        throw new IllegalArgumentException(
            "command not implemented: " + String.join(" ", argv)
          + "\nThis is a pure-Java tool (no native binaries). Supported commands: see --help.");
    }

    private static boolean isHelp(String s) {
        return s.equals("-h") || s.equals("--help") || s.equals("-help") || s.equals("help");
    }

    private static void usage() {
        System.out.println(
            "kdbtool — pure-Java CMS key-database tool (no native binaries, no dependencies)\n\n"
          + "Key database:\n"
          + "  -keydb -create   -db F.kdb -pw PW [-stash]\n"
          + "  -keydb -changepw -db F.kdb -pw PW -new_pw PW [-stash]\n"
          + "  -keydb -convert  -db F.kdb (-pw PW|-stashed) -target F.p12 [-target_pw PW]\n"
          + "  -keydb -delete   -db F.kdb\n"
          + "  -keydb -info | -list\n"
          + "  -keydb -stashpw  -db F.kdb -pw PW [-v1stash]\n"
          + "  -keydb -getpw    -db F.kdb | -stashed F.sth        (recover master password)\n"
          + "  -keydb -verifypw -db F.kdb (-pw PW | -stashed)\n"
          + "Certificates:\n"
          + "  -cert -list|-details|-extract|-validate -db F.kdb [-label L]\n"
          + "  -cert -create  -db F.kdb -pw PW -label L -dn DN [-size 2048] [-expire days]\n"
          + "  -cert -add|-receive -db F.kdb -pw PW -label L -file C.arm\n"
          + "  -cert -delete|-rename -db F.kdb -pw PW -label L [-new_label L]\n"
          + "  -cert -import  -db F.kdb -pw PW -file SRC.p12 [-target_pw PW] [-label L]\n"
          + "  -cert -export  -db F.kdb (-pw PW|-stashed) -label L -target C.p12 [-target_pw PW]\n"
          + "  -cert -extractkey -db F.kdb (-pw PW|-stashed) -label L [-target K.pem]\n"
          + "  -cert -sign    -db F.kdb -pw PW -label CA -file req.csr -target cert.pem\n"
          + "Certificate request:\n"
          + "  -certreq -create -db F.kdb -pw PW -label L -dn DN -file req.csr\n");
    }
}
