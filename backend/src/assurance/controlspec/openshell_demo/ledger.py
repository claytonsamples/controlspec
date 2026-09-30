"""SQLite append-only synthetic records; host administrators remain trusted."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from assurance.contracts.canonical import canonical_json, sha256_digest


class Ledger:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        if self.path == ":memory:":
            raise ValueError("durable demo ledger requires a file path")
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self.transaction() as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1):
                raise ValueError("unsupported demo ledger version")
            connection.execute("""CREATE TABLE IF NOT EXISTS events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                scope TEXT NOT NULL, action_id TEXT NOT NULL, kind TEXT NOT NULL,
                payload TEXT NOT NULL, previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL
            )""")
            connection.execute(
                "CREATE INDEX IF NOT EXISTS action_events ON events(scope,action_id)"
            )
            connection.execute("""CREATE TRIGGER IF NOT EXISTS immutable_update
                BEFORE UPDATE ON events
                BEGIN SELECT RAISE(ABORT, 'append-only events'); END""")
            connection.execute("""CREATE TRIGGER IF NOT EXISTS immutable_delete
                BEFORE DELETE ON events
                BEGIN SELECT RAISE(ABORT, 'append-only events'); END""")
            connection.execute("PRAGMA user_version=1")
        if not self.verify():
            raise ValueError("demo ledger chain verification failed")

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def append(
        connection: sqlite3.Connection,
        scope: str,
        action_id: str,
        kind: str,
        payload: dict[str, Any],
    ) -> str:
        prior = connection.execute(
            "SELECT event_hash FROM events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous = prior[0] if prior else "sha256:" + "0" * 64
        envelope = {
            "scope": scope,
            "action_id": action_id,
            "kind": kind,
            "payload": payload,
            "previous_hash": previous,
        }
        digest = sha256_digest(canonical_json(envelope))
        connection.execute(
            "INSERT INTO events(scope,action_id,kind,payload,previous_hash,event_hash) "
            "VALUES(?,?,?,?,?,?)",
            (scope, action_id, kind, canonical_json(payload).decode(), previous, digest),
        )
        return digest

    @staticmethod
    def latest(
        connection: sqlite3.Connection, scope: str, action_id: str, kind: str
    ) -> dict[str, Any] | None:
        row = connection.execute(
            "SELECT payload FROM events WHERE scope=? AND action_id=? AND kind=? "
            "ORDER BY sequence DESC LIMIT 1",
            (scope, action_id, kind),
        ).fetchone()
        return json.loads(row[0]) if row else None

    def events(self) -> list[dict[str, Any]]:
        with self.transaction() as connection:
            return [
                dict(row) | {"payload": json.loads(row["payload"])}
                for row in connection.execute("SELECT * FROM events ORDER BY sequence")
            ]

    def verify(self) -> bool:
        previous = "sha256:" + "0" * 64
        for record in self.events():
            envelope = {
                key: record[key]
                for key in ("scope", "action_id", "kind", "payload", "previous_hash")
            }
            if record["previous_hash"] != previous or (
                sha256_digest(canonical_json(envelope)) != record["event_hash"]
            ):
                return False
            previous = record["event_hash"]
        return True
