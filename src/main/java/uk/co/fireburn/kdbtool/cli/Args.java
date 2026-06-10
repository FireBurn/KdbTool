package uk.co.fireburn.kdbtool.cli;

import java.util.ArrayList;
import java.util.List;

/** Tiny CLI-style argument accessor over the raw argv list. */
final class Args {
    final List<String> raw;

    Args(String[] argv) { this.raw = new ArrayList<>(java.util.Arrays.asList(argv)); }

    boolean has(String flag) { return raw.contains(flag); }

    /** Value following {@code flag}, or null. A following token starting with '-' is not a value. */
    String value(String flag) {
        int i = raw.indexOf(flag);
        if (i >= 0 && i + 1 < raw.size()) {
            String v = raw.get(i + 1);
            if (!v.equals("-") && !(v.startsWith("-") && v.length() > 1 && !Character.isDigit(v.charAt(1)))) {
                return v;
            }
            // still return values like "-1"? key-database flags don't need that nuance
            return v.startsWith("-") ? null : v;
        }
        return null;
    }

    String value(String flag, String dflt) {
        String v = value(flag);
        return v != null ? v : dflt;
    }

    String required(String flag) {
        String v = value(flag);
        if (v == null) throw new IllegalArgumentException("missing required parameter " + flag);
        return v;
    }
}
