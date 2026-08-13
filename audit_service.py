"""Structured evidence storage for important business operations."""

from __future__ import annotations

import html
import json
import re
from datetime import datetime
from pathlib import Path

from backup_service import enabled


def record_audit(db, config, *, user, event_type, environment, store=None,
                 order=None, product_name=None, quantity_minor=None,
                 before=None, after=None, approval_status=None) -> bool:
    """Persist searchable evidence and an optional reproducible HTML snapshot.

    The flag is checked before serialization, filesystem access, or SQL, which
    makes the disabled path a true no-op.
    """
    if not enabled(config.get("AUDIT_SNAPSHOT_ENABLED", False)):
        return False

    occurred_at = datetime.now()
    store_id = store["id"] if store else None
    store_name = store["name"] if store else None
    order_id = order["id"] if order else None
    order_number = order["order_number"] if order else None
    before_json = json.dumps(before, ensure_ascii=False, sort_keys=True) if before is not None else None
    after_json = json.dumps(after, ensure_ascii=False, sort_keys=True) if after is not None else None
    cursor = db.execute(
        """INSERT INTO audit_events
           (occurred_at, user_id, user_login_id, store_id, store_name, order_id,
            order_number, event_type, product_name, quantity_minor, before_json,
            after_json, approval_status, environment)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (occurred_at.strftime("%Y-%m-%d %H:%M:%S"), user["id"], user["login_id"],
         store_id, store_name, order_id, order_number, event_type, product_name,
         quantity_minor, before_json, after_json, approval_status, environment),
    )
    def safe_component(value):
        cleaned = re.sub(r"[^0-9A-Za-z._\-\u3040-\u30ff\u3400-\u9fff]", "_", value or "unknown")
        return cleaned[:80] or "unknown"

    category = safe_component(event_type.split("_", 1)[0])
    base = Path(config["AUDIT_STORAGE_PATH"])
    path = base / safe_component(store_name or "store-unknown") / occurred_at.strftime("%Y") / occurred_at.strftime("%m") / category
    path.mkdir(parents=True, exist_ok=True)
    snapshot = path / f"{occurred_at.strftime('%Y%m%d_%H%M%S_%f')}_{cursor.lastrowid}.html"
    fields = {
        "日時": occurred_at.isoformat(timespec="seconds"), "操作ユーザー": user["login_id"],
        "店舗": store_name, "取引番号": order_number, "操作種類": event_type,
        "商品": product_name, "数量": None if quantity_minor is None else f"{quantity_minor / 100:.2f}",
        "変更前": before, "変更後": after, "承認状態": approval_status,
    }
    body = "".join(
        f"<dt>{html.escape(str(key))}</dt><dd>{html.escape(json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value or ''))}</dd>"
        for key, value in fields.items()
    )
    snapshot.write_text(
        "<!doctype html><meta charset='utf-8'><title>PITA audit</title><h1>操作証跡</h1><dl>" + body + "</dl>",
        encoding="utf-8",
    )
    db.execute("UPDATE audit_events SET snapshot_path = ? WHERE id = ?", (str(snapshot), cursor.lastrowid))
    return True
