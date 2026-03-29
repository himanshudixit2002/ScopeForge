#!/usr/bin/env python3
"""Take a consistent online SQLite backup without copying a live WAL file."""
import argparse
import os
from pathlib import Path
import sqlite3


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--database", type=Path, default=Path(os.getenv("SCOPEFORGE_DB", "data/scopeforge.sqlite3")))
    args = parser.parse_args()
    source = args.database.resolve(strict=True)
    destination = args.destination.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Refuse overwriting an existing backup or the live database.
    fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    try:
        with sqlite3.connect(f"{source.as_uri()}?mode=ro", uri=True) as reader:
            with sqlite3.connect(destination) as writer:
                reader.backup(writer)
                result = writer.execute("PRAGMA integrity_check").fetchone()[0]
                if result != "ok":
                    raise RuntimeError(f"Backup integrity check failed: {result}")
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    print(f"Verified backup created: {destination}")


if __name__ == "__main__":
    main()
