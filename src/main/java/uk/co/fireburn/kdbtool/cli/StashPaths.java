package uk.co.fireburn.kdbtool.cli;

import java.nio.file.Path;
import java.nio.file.Paths;

/** Maps a key-database path to its companion stash (.sth) path, by convention. */
final class StashPaths {
    private StashPaths() {}

    static Path derive(String db) {
        if (db.endsWith(".kdb")) {
            return Paths.get(db.substring(0, db.length() - 4) + ".sth");
        }
        return Paths.get(db + ".sth");
    }
}
