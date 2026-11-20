"""What the relay keeps, in SQLite: the installs it registered and the exact names they own.

    installs   name, the SHA-256 of its secret, created, last seen
    names      an exact name (<id>.id.decentai) and the install it is bound to, for good

A secret is 256 random bits, so one round of SHA-256 is enough to keep
it from being read back out of the file. No row is ever deleted: a name,
once given, is never given again. An install is turned away by emptying
its secret's hash.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import string
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS installs (
    name        TEXT PRIMARY KEY,
    secret_hash TEXT NOT NULL,
    created     INTEGER NOT NULL,
    last_seen   INTEGER
);
CREATE TABLE IF NOT EXISTS names (
    host    TEXT PRIMARY KEY,
    install TEXT NOT NULL REFERENCES installs(name),
    bound   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS names_by_install ON names (install);
"""


class StoreError(RuntimeError):
    """The store could not do what was asked."""


class Store:
    ALPHABET = string.ascii_lowercase + string.digits
    NAME_LENGTH = 10

    def __init__(self, path: str | Path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        # Autocommit; a change of more than one row says BEGIN itself.
        self.db = sqlite3.connect(str(path), isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript(SCHEMA)

    def close(self) -> None:
        self.db.close()

    @staticmethod
    def digest(secret: str) -> str:
        return hashlib.sha256(secret.encode("utf-8")).hexdigest()

    # -- installs --------------------------------------------------------
    def register(self) -> tuple[str, str]:
        """A new install: a name never given before, and its secret."""
        secret = secrets.token_urlsafe(32)
        for _ in range(100):
            name = "".join(secrets.choice(self.ALPHABET) for _ in range(self.NAME_LENGTH))
            try:
                self.db.execute(
                    "INSERT INTO installs (name, secret_hash, created) VALUES (?, ?, ?)",
                    (name, self.digest(secret), int(time.time())))
            except sqlite3.IntegrityError:
                continue
            return name, secret
        raise StoreError("no free name was found")

    def check(self, name: str, secret: str) -> bool:
        """Whether the secret is the install's."""
        row = self.db.execute("SELECT secret_hash FROM installs WHERE name = ?", (name,)).fetchone()
        stored = row[0] if row else ""
        # Compared even when there is no such install, so that the time
        # taken does not say which names exist.
        matches = hmac.compare_digest(stored or "-" * 64, self.digest(secret))
        return bool(row) and bool(stored) and matches

    def exists(self, name: str) -> bool:
        return self.db.execute("SELECT 1 FROM installs WHERE name = ?", (name,)).fetchone() is not None

    def seen(self, name: str) -> None:
        self.db.execute("UPDATE installs SET last_seen = ? WHERE name = ?", (int(time.time()), name))

    # -- exact names -----------------------------------------------------
    def owner(self, host: str) -> str:
        """The install an exact name is bound to, or ''."""
        row = self.db.execute("SELECT install FROM names WHERE host = ?", (host,)).fetchone()
        return row[0] if row else ""

    def hosts(self, name: str) -> list[str]:
        """The exact names an install owns."""
        return [row[0] for row in self.db.execute(
            "SELECT host FROM names WHERE install = ? ORDER BY host", (name,))]

    def bind(self, name: str, hosts: list[str]) -> str:
        """Binds each exact name not yet bound to the install, all or none.
        Returns '' when every name is the install's now, or the first name
        that another install owns (and then nothing is bound)."""
        self.db.execute("BEGIN IMMEDIATE")
        try:
            for host in hosts:
                owner = self.owner(host)
                if owner and owner != name:
                    self.db.execute("ROLLBACK")
                    return host
            now = int(time.time())
            for host in hosts:
                self.db.execute("INSERT OR IGNORE INTO names (host, install, bound) VALUES (?, ?, ?)",
                                (host, name, now))
            self.db.execute("COMMIT")
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise
        return ""
