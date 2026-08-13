"""Database and human-readable emergency backup services.

Nothing is opened, created, or contacted while BACKUP_ENABLED is false.
The public entry point is intentionally independent from Flask so a future
scheduler, Render job, or CLI can call it without coupling backup policy to
web requests.
"""

from __future__ import annotations

import csv
import sqlite3
from datetime import datetime
from pathlib import Path


IMPORTANT_TABLES = (
    "stores", "products", "product_categories", "units", "users", "orders",
    "order_items", "unexpected_items", "transaction_corrections", "audit_events",
    "admin_recovery_tokens",
)


def enabled(value) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


class SQLiteBackupService:
    def __init__(self, database: str, storage_path: str):
        self.database = Path(database)
        self.storage_path = Path(storage_path)

    def run(self) -> Path:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        destination = self.storage_path / stamp
        destination.mkdir(parents=True, exist_ok=False)
        backup_file = destination / "pita_tanom.sqlite3"
        source = sqlite3.connect(f"file:{self.database}?mode=ro", uri=True)
        target = sqlite3.connect(backup_file)
        try:
            source.backup(target)
            result = target.execute("PRAGMA integrity_check").fetchone()[0]
            if result != "ok":
                raise RuntimeError(f"SQLite backup integrity check failed: {result}")
            self._write_csv(source, destination / "csv")
        finally:
            target.close()
            source.close()
        return destination

    @staticmethod
    def _write_csv(connection: sqlite3.Connection, csv_path: Path) -> None:
        csv_path.mkdir(parents=True, exist_ok=False)
        existing = {
            row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        for table in IMPORTANT_TABLES:
            if table not in existing:
                continue
            cursor = connection.execute(f'SELECT * FROM "{table}" ORDER BY rowid')
            with (csv_path / f"{table}.csv").open("w", encoding="utf-8-sig", newline="") as file:
                writer = csv.writer(file)
                writer.writerow(column[0] for column in cursor.description)
                writer.writerows(cursor)


def run_backup(config):
    """Run the configured backend, returning None immediately when disabled."""
    if not enabled(config.get("BACKUP_ENABLED", False)):
        return None
    backend = config.get("BACKUP_BACKEND", "sqlite")
    if backend == "sqlite":
        return SQLiteBackupService(
            config["DATABASE"], config["BACKUP_STORAGE_PATH"]
        ).run()
    raise NotImplementedError(
        f"Backup backend {backend!r} is not configured; use a PostgreSQL-specific service."
    )
