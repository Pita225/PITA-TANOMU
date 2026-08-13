import os
import re
import secrets
import sqlite3
import uuid
import csv
import hashlib
import io
import json
from datetime import date, datetime, timedelta
from decimal import Decimal, InvalidOperation
from functools import wraps
from pathlib import Path

from flask import (
    Flask, abort, current_app, flash, g, redirect, render_template, request,
    send_from_directory, session, url_for, Response
)
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from audit_service import record_audit
from backup_service import enabled as feature_enabled, run_backup


BASE_DIR = Path(__file__).resolve().parent
SECRET_KEY_FILE = BASE_DIR / ".secret_key"
ENVIRONMENT_LABELS = {"production": "本番", "training": "トレーニング"}
TRAINING_STORE_NAMES = ("トレーニング店舗A", "トレーニング店舗B")
ADMIN_RECOVERY_SALT = "pita-admin-recovery-v1"
ADMIN_RECOVERY_MAX_AGE = 15 * 60


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=load_or_create_secret_key(),
        DATABASE=os.environ.get("PITA_DATABASE", str(BASE_DIR / "pita_tanom.db")),
        UPLOAD_FOLDER=str(BASE_DIR / "static" / "uploads"),
        MAX_CONTENT_LENGTH=5 * 1024 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        BACKUP_ENABLED=os.environ.get("BACKUP_ENABLED", "false"),
        BACKUP_BACKEND=os.environ.get("BACKUP_BACKEND", "sqlite"),
        BACKUP_STORAGE_PATH=os.environ.get("BACKUP_STORAGE_PATH", str(BASE_DIR / "backups")),
        AUDIT_SNAPSHOT_ENABLED=os.environ.get("AUDIT_SNAPSHOT_ENABLED", "false"),
        AUDIT_STORAGE_PATH=os.environ.get("AUDIT_STORAGE_PATH", str(BASE_DIR / "audit_snapshots")),
    )
    if test_config:
        app.config.update(test_config)

    @app.teardown_appcontext
    def close_db(_error=None):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    @app.errorhandler(413)
    def upload_too_large(_error):
        flash("画像が大きすぎます。5MB以下の画像を選択してください。", "error")
        return redirect(url_for("product_management"))

    @app.template_filter("yen")
    def yen(value):
        return f"¥{int(value):,}" if value is not None else "―"

    @app.template_filter("quantity")
    def quantity(value):
        if value is None:
            return ""
        number = Decimal(str(value)).quantize(Decimal("0.01"))
        return format(number, "f").rstrip("0").rstrip(".")

    @app.template_filter("correction_value")
    def correction_value(value):
        try:
            snapshot = json.loads(value) if isinstance(value, str) else value
        except (TypeError, json.JSONDecodeError):
            return value
        quantity_text = "未確定" if snapshot.get("quantity") is None else (
            f"{quantity(snapshot['quantity'])}{snapshot.get('unit', '')}"
        )
        price = snapshot.get("unit_price")
        price_text = "単価未設定" if price is None else f"単価 ¥{int(price):,}"
        return f"{snapshot.get('product_name', '―')} / {quantity_text} / {price_text}"

    @app.template_filter("environment_label")
    def environment_label(value):
        return ENVIRONMENT_LABELS.get(value, value)

    @app.context_processor
    def permission_context():
        return {
            "system_admin": is_admin(),
            "environment_operator": is_environment_operator(),
            "training_reviewer": is_training_reviewer(),
            "training_mode": bool(getattr(g, "training_mode", False)),
            "business_admin": is_environment_operator(),
        }

    @app.before_request
    def load_logged_in_user():
        user_id = session.get("user_id")
        session_version = session.get("session_version")
        g.user = None
        if user_id:
            user = get_db().execute(
                """SELECT u.*, s.name AS store_name, s.environment AS store_environment,
                          s.is_active AS store_is_active,
                          s.is_deleted AS store_is_deleted
                   FROM users u LEFT JOIN stores s ON s.id = u.store_id
                   WHERE u.id = ?""", (user_id,)
            ).fetchone()
            # Deployment before session versioning issued cookies with only user_id.
            # They belong to the initial generation and may be upgraded only while
            # the DB is still on that generation. A recovery/reset increments the
            # DB value, so dormant legacy cookies cannot bypass invalidation later.
            if session_version is None and user and user["session_version"] == 1:
                session_version = 1
                session["session_version"] = session_version
            valid = (
                user
                and user["is_active"]
                and isinstance(session_version, int)
                and session_version == user["session_version"]
            )
            if valid and user["role"] == "store":
                valid = user["store_is_active"] and not user["store_is_deleted"]
            if valid:
                g.user = user
            else:
                session.clear()

        if g.user and is_admin() and request.args.get("environment") in ENVIRONMENT_LABELS:
            session["view_environment"] = request.args["environment"]
        g.training_mode = bool(g.user) and (
            is_training_reviewer()
            or (g.user["role"] == "store" and g.user["store_environment"] == "training")
            or (is_admin() and session.get("view_environment") == "training")
        )

        allowed = {"login", "setup", "admin_recovery", "static"}
        if request.endpoint in allowed:
            return None
        admin_exists = get_db().execute(
            "SELECT 1 FROM users WHERE role = 'admin' AND is_training_reviewer = 0 LIMIT 1"
        ).fetchone()
        if admin_exists is None:
            return redirect(url_for("setup"))
        if g.user is None:
            return redirect(url_for("login"))
        return None

    @app.route("/setup", methods=["GET", "POST"])
    def setup():
        db = get_db()
        if db.execute("SELECT 1 FROM users WHERE role = 'admin' AND is_training_reviewer = 0 LIMIT 1").fetchone():
            return redirect(url_for("index") if g.user else url_for("login"))
        if request.method == "POST":
            login_id = normalize_login_id(request.form.get("login_id"))
            password = request.form.get("password", "")
            confirmation = request.form.get("password_confirmation", "")
            error = validate_credentials(login_id, password)
            if password != confirmation:
                error = "確認用パスワードが一致しません。"
            if error:
                flash(error, "error")
            else:
                cursor = db.execute(
                    """INSERT INTO users (login_id, password_hash, role)
                       VALUES (?, ?, 'admin')""",
                    (login_id, generate_password_hash(password)),
                )
                db.commit()
                session.clear()
                session["user_id"] = cursor.lastrowid
                session["session_version"] = 1
                return redirect(url_for("index"))
        return render_template("setup.html")

    @app.route("/admin-recovery", methods=["GET", "POST"])
    def admin_recovery():
        """SECRET_KEYで署名された短期トークンだけを使って通常管理者を復旧する。"""
        if request.method == "POST":
            token = request.form.get("recovery_token", "").strip()
            serializer = URLSafeTimedSerializer(
                current_app.config["SECRET_KEY"], salt=ADMIN_RECOVERY_SALT
            )
            try:
                payload = serializer.loads(token, max_age=ADMIN_RECOVERY_MAX_AGE)
            except (BadSignature, SignatureExpired):
                flash("復旧トークンが無効または期限切れです。", "error")
                return render_template("admin_recovery.html"), 400

            valid_payload = isinstance(payload, dict)
            login_id = payload.get("login_id") if valid_payload else None
            password_hash = payload.get("password_hash") if valid_payload else None
            valid_hash = isinstance(password_hash, str) and password_hash.startswith(
                ("scrypt:", "pbkdf2:")
            ) and len(password_hash) <= 512
            if (
                not valid_payload
                or payload.get("purpose") != "admin-recovery"
                or validate_login_id(login_id)
                or not valid_hash
            ):
                flash("復旧トークンが無効または期限切れです。", "error")
                return render_template("admin_recovery.html"), 400

            db = get_db()
            admins = db.execute(
                """SELECT id FROM users
                   WHERE role = 'admin' AND is_training_reviewer = 0 ORDER BY id"""
            ).fetchall()
            if len(admins) != 1:
                flash("通常管理者を一意に特定できないため復旧できません。", "error")
                return render_template("admin_recovery.html"), 409
            admin_id = admins[0]["id"]
            duplicate = db.execute(
                "SELECT 1 FROM users WHERE login_id = ? AND id <> ?",
                (login_id, admin_id),
            ).fetchone()
            if duplicate:
                flash("指定されたログインIDはすでに使用されています。", "error")
                return render_template("admin_recovery.html"), 409
            token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
            if db.execute(
                "SELECT 1 FROM admin_recovery_tokens WHERE token_hash = ?", (token_hash,)
            ).fetchone():
                flash("この復旧トークンはすでに使用済みです。", "error")
                return render_template("admin_recovery.html"), 400
            try:
                db.execute(
                    """UPDATE users
                       SET login_id = ?, password_hash = ?, is_active = 1,
                           session_version = session_version + 1
                       WHERE id = ?""",
                    (login_id, password_hash, admin_id),
                )
                db.execute(
                    "INSERT INTO admin_recovery_tokens (token_hash) VALUES (?)",
                    (token_hash,),
                )
                db.commit()
            except sqlite3.IntegrityError:
                db.rollback()
                flash("この復旧トークンはすでに使用済みです。", "error")
                return render_template("admin_recovery.html"), 400
            session.clear()
            flash("管理者ログインIDとパスワードを再設定しました。", "success")
            return redirect(url_for("login"))
        return render_template("admin_recovery.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if get_db().execute("SELECT 1 FROM users WHERE role = 'admin' AND is_training_reviewer = 0 LIMIT 1").fetchone() is None:
            return redirect(url_for("setup"))
        if g.user:
            return redirect(url_for("index"))
        if request.method == "POST":
            login_id = normalize_login_id(request.form.get("login_id"))
            user = get_db().execute(
                """SELECT u.*, s.is_active AS store_is_active,
                          s.is_deleted AS store_is_deleted
                   FROM users u LEFT JOIN stores s ON s.id = u.store_id
                   WHERE u.login_id = ?""", (login_id,)
            ).fetchone()
            valid = user and user["is_active"] and check_password_hash(
                user["password_hash"], request.form.get("password", "")
            )
            if valid and user["role"] == "store":
                valid = user["store_is_active"] and not user["store_is_deleted"]
            if not valid:
                flash("ログインIDまたはパスワードを確認してください。", "error")
            else:
                session.clear()
                session["user_id"] = user["id"]
                session["session_version"] = user["session_version"]
                return redirect(url_for("index"))
        return render_template("login.html")

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.cli.command("backup")
    def backup_command():
        destination = run_backup(current_app.config)
        print(destination if destination else "BACKUP_ENABLED=false: no backup created")

    @app.get("/")
    def index():
        db = get_db()
        if is_environment_operator():
            selected_environment = report_scope_environment(request.args.get("environment"))
            stores = db.execute(
                """SELECT * FROM stores
                   WHERE is_active = 1 AND is_deleted = 0 AND environment = ?
                   ORDER BY name, id""", (selected_environment,)
            ).fetchall()
            scoped_store_id = None
        else:
            selected_environment = report_scope_environment(None)
            stores = db.execute(
                """SELECT * FROM stores
                   WHERE is_active = 1 AND is_deleted = 0 AND id <> ?
                     AND environment = (SELECT environment FROM stores WHERE id = ?)
                   ORDER BY name, id""",
                (g.user["store_id"], g.user["store_id"]),
            ).fetchall()
            scoped_store_id = g.user["store_id"]
        set_request_environment(selected_environment)
        return render_template(
            "index.html", stores=stores,
            counts=dashboard_counts(scoped_store_id, selected_environment),
            selected_environment=selected_environment,
            environments=ENVIRONMENT_LABELS,
        )

    @app.get("/product-images/<path:filename>")
    def product_image(filename):
        return send_from_directory(current_app.config["UPLOAD_FOLDER"], filename)

    @app.get("/status/<category>")
    def status_list(category):
        if category not in {"orders", "receipts", "approved", "pending"}:
            abort(404)
        db = get_db()
        scoped_store_id = None if is_environment_operator() else g.user["store_id"]
        selected_environment = report_scope_environment(request.args.get("environment"))
        set_request_environment(selected_environment)
        counts = dashboard_counts(scoped_store_id, selected_environment)
        if category == "pending" and scoped_store_id is not None:
            return redirect(url_for("index"))
        if category == "pending":
            return render_template(
                "status_list.html", category=category, counts=counts,
                tasks=pending_tasks(scoped_store_id, selected_environment), orders=[],
                selected_environment=selected_environment,
                selected_scope_label=ENVIRONMENT_LABELS[selected_environment],
            )

        conditions = {
            "orders": "1 = 1",
            "receipts": "o.receipt_reported_at IS NOT NULL",
            "approved": """o.status = 'received' AND NOT EXISTS (
                SELECT 1 FROM unexpected_items ux WHERE ux.order_id = o.id
                AND ux.status IN ('return_pending', 'returned', 'accept_pending'))""",
        }
        if scoped_store_id is None:
            store_ids = store_ids_for_environment(selected_environment)
            placeholders = ",".join("?" for _ in store_ids)
            scope_sql = (
                f" AND o.from_store_id IN ({placeholders})"
                f" AND o.to_store_id IN ({placeholders})"
            )
            params = tuple(store_ids + store_ids)
        elif category == "orders":
            scope_sql = " AND o.from_store_id = ?"
            params = (scoped_store_id,)
        elif category == "receipts":
            conditions["receipts"] = """NOT (o.status = 'received' AND NOT EXISTS (
                SELECT 1 FROM unexpected_items ux WHERE ux.order_id = o.id
                AND ux.status IN ('return_pending', 'returned', 'accept_pending')))"""
            scope_sql = " AND o.to_store_id = ?"
            params = (scoped_store_id,)
        else:
            scope_sql = " AND (o.from_store_id = ? OR o.to_store_id = ?)"
            params = (scoped_store_id, scoped_store_id)
        orders = db.execute(
            f"""SELECT o.*, f.name AS from_store_name, t.name AS to_store_name,
                       COUNT(oi.id) AS item_count,
                       SUM(CASE WHEN oi.unit_price IS NOT NULL
                           THEN oi.quantity * oi.unit_price ELSE 0 END) AS total
                FROM orders o
                JOIN stores f ON f.id = o.from_store_id
                JOIN stores t ON t.id = o.to_store_id
                JOIN order_items oi ON oi.order_id = o.id
                WHERE {conditions[category]} {scope_sql}
                GROUP BY o.id ORDER BY o.created_at DESC, o.id DESC""",
            params,
        ).fetchall()
        if scoped_store_id is not None:
            orders = decorate_store_orders(orders, scoped_store_id, category)
        return render_template(
            "status_list.html", category=category, counts=counts,
            orders=orders, tasks=[], selected_environment=selected_environment,
            selected_scope_label=ENVIRONMENT_LABELS[selected_environment],
        )

    @app.post("/order/start")
    def start_order():
        from_id = request.form.get("from_store_id", type=int) if is_environment_operator() else g.user["store_id"]
        to_id = request.form.get("to_store_id", type=int)
        required_environment = "training" if is_training_reviewer() else None
        if not valid_store_pair(from_id, to_id, required_environment):
            flash("発注元と発注先には、同じ環境・区分の別々の店舗を選んでください。", "error")
            return redirect(url_for("index"))
        session["order_context"] = {"from_store_id": from_id, "to_store_id": to_id}
        session.pop("cart", None)
        return redirect(url_for("products"))

    @app.get("/products")
    def products():
        context = current_order_context()
        if context is None or (not is_environment_operator() and context.get("from_store_id") != g.user["store_id"]) or not valid_store_pair(
            context.get("from_store_id"), context.get("to_store_id"),
            "training" if is_training_reviewer() else None,
        ):
            session.pop("order_context", None)
            session.pop("cart", None)
            flash("最初に発注元と発注先を選んでください。", "error")
            return redirect(url_for("index"))
        db = get_db()
        stores = load_context_stores(context)
        environment = stores["from_store"]["environment"]
        product_rows = orderable_products(environment)
        major_categories = db.execute(
            """SELECT * FROM product_categories
               WHERE level = 1 AND is_active = 1 AND is_deleted = 0
                 AND environment = ? ORDER BY name, id""", (environment,)
        ).fetchall()
        subcategories = db.execute(
            """SELECT c.* FROM product_categories c
               JOIN product_categories p ON p.id = c.parent_id
               WHERE c.level = 2 AND c.is_active = 1 AND c.is_deleted = 0
                 AND p.is_active = 1 AND p.is_deleted = 0
                 AND c.environment = ? AND p.environment = ? ORDER BY c.name, c.id""",
            (environment, environment),
        ).fetchall()
        set_request_environment(stores["from_store"]["environment"])
        return render_template(
            "products.html", products=product_rows, major_categories=major_categories,
            subcategories=subcategories, **stores
        )

    @app.post("/cart")
    def update_cart():
        context = current_order_context()
        if context is None or (not is_environment_operator() and context.get("from_store_id") != g.user["store_id"]):
            session.pop("order_context", None)
            session.pop("cart", None)
            return redirect(url_for("index"))

        products_by_id = {row["id"]: row for row in orderable_products()}
        cart = []
        invalid = False
        for product_id, product in products_by_id.items():
            raw = request.form.get(f"quantity_{product_id}", "").strip()
            if not raw and product["source_product_id"]:
                raw = request.form.get(f"quantity_{product['source_product_id']}", "").strip()
            if not raw:
                continue
            try:
                amount, _minor = parse_quantity(raw, product["decimal_places"])
            except InvalidOperation:
                invalid = True
                continue
            cart.append({"product_id": product_id, "quantity": str(amount.normalize())})

        if invalid:
            flash("数量は0より大きい数値で入力してください。", "error")
            return redirect(url_for("products"))
        if not cart:
            flash("発注する商品の数量を1つ以上入力してください。", "error")
            return redirect(url_for("products"))
        session["cart"] = cart
        return redirect(url_for("cart"))

    @app.get("/cart")
    def cart():
        context = current_order_context()
        items = build_cart_items(session.get("cart", []))
        if context is None or not items or (
            not is_environment_operator() and context.get("from_store_id") != g.user["store_id"]
        ):
            flash("カートが空です。", "error")
            return redirect(url_for("index"))
        stores = load_context_stores(context)
        set_request_environment(stores["from_store"]["environment"])
        total = sum(item["subtotal"] for item in items if item["subtotal"] is not None)
        priced_count = sum(item["unit_price"] is not None for item in items)
        return render_template(
            "cart.html", items=items, total=total,
            all_priced=priced_count == len(items), **stores
        )

    @app.post("/order/submit")
    def submit_order():
        context = current_order_context()
        items = build_cart_items(session.get("cart", []))
        if context is None or not items or (
            not is_environment_operator() and context.get("from_store_id") != g.user["store_id"]
        ) or not valid_store_pair(
            context.get("from_store_id"), context.get("to_store_id"),
            "training" if is_training_reviewer() else None,
        ):
            flash("発注内容を確認できませんでした。最初からやり直してください。", "error")
            return redirect(url_for("index"))

        db = get_db()
        try:
            cursor = db.execute(
                "INSERT INTO orders (from_store_id, to_store_id) VALUES (?, ?)",
                (context["from_store_id"], context["to_store_id"]),
            )
            order_id = cursor.lastrowid
            order_number = f"ORD-{order_id:06d}"
            db.execute("UPDATE orders SET order_number = ? WHERE id = ?", (order_number, order_id))
            db.executemany(
                """INSERT INTO order_items
                   (order_id, product_id, product_name, unit, quantity, quantity_minor,
                    quantity_decimal_places, unit_price, major_category_name, subcategory_name)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [(
                    order_id, item["product_id"], item["name"], item["unit"],
                    float(item["quantity"]), item["quantity_minor"],
                    item["decimal_places"], item["unit_price"],
                    item["major_name"], item["subcategory_name"]
                ) for item in items],
            )
            saved_order = fetch_order(order_id)
            for item in items:
                audit_operation(
                    "order_confirmed", saved_order,
                    store_id=context["from_store_id"], product_name=item["name"],
                    quantity_minor=item["quantity_minor"],
                    after={"quantity_minor": item["quantity_minor"], "unit": item["unit"]},
                    approval_status="ordered",
                )
            db.commit()
        except sqlite3.Error:
            db.rollback()
            raise

        session.pop("cart", None)
        session.pop("order_context", None)
        return redirect(url_for("order_complete", order_id=order_id))

    @app.get("/order/<int:order_id>/complete")
    def order_complete(order_id):
        order = fetch_order(order_id)
        if order is None:
            abort(404)
        if not can_access_order(order):
            abort(403)
        set_request_environment_for_order(order)
        return render_template("complete.html", order=order)

    @app.get("/received")
    def received():
        db = get_db()
        store_id = report_scope_store_id(request.args.get("store_id", type=int))
        selected_environment = report_scope_environment(
            request.args.get("environment"), store_id
        )
        store_id = normalize_report_store_id(store_id, selected_environment)
        set_request_environment(selected_environment)
        stores = db.execute(
            """SELECT * FROM stores WHERE is_deleted = 0 AND environment = ?
               ORDER BY is_active DESC, name, id""", (selected_environment,)
        ).fetchall() if is_environment_operator() else []
        selected_store = None
        orders = []
        if store_id:
            selected_store = db.execute(
                "SELECT * FROM stores WHERE id = ? AND is_deleted = 0", (store_id,)
            ).fetchone()
            if selected_store:
                store_column = "o.to_store_id" if is_environment_operator() else "o.from_store_id"
                orders = db.execute(
                    f"""SELECT o.*, f.name AS from_store_name, t.name AS to_store_name,
                              COUNT(oi.id) AS item_count,
                              SUM(CASE WHEN oi.unit_price IS NOT NULL
                                  THEN oi.quantity * oi.unit_price ELSE 0 END) AS total
                       FROM orders o
                       JOIN stores f ON f.id = o.from_store_id
                       JOIN stores t ON t.id = o.to_store_id
                       JOIN order_items oi ON oi.order_id = o.id
                       WHERE {store_column} = ?
                       GROUP BY o.id ORDER BY o.created_at DESC, o.id DESC""",
                    (store_id,),
                ).fetchall()
        return render_template(
            "received.html", stores=stores, selected_store=selected_store, orders=orders
        )

    @app.get("/received/<int:order_id>")
    def received_detail(order_id):
        order = fetch_order(order_id)
        if order is None:
            abort(404)
        if not can_access_order(order):
            abort(403)
        set_request_environment_for_order(order)
        db = get_db()
        items = db.execute(
            "SELECT * FROM order_items WHERE order_id = ? ORDER BY id", (order_id,)
        ).fetchall()
        unexpected_items = db.execute(
            "SELECT * FROM unexpected_items WHERE order_id = ? ORDER BY id", (order_id,)
        ).fetchall()
        total = sum(
            item["quantity"] * item["unit_price"]
            for item in items if item["unit_price"] is not None
        )
        all_priced = all(item["unit_price"] is not None for item in items)
        return render_template(
            "received_detail.html", order=order, items=items,
            unexpected_items=unexpected_items, total=total, all_priced=all_priced,
            can_sender_action=is_environment_operator() or g.user["store_id"] == order["from_store_id"],
        )

    @app.post("/received/<int:order_id>/approve")
    def approve_receipt_difference(order_id):
        db = get_db()
        order = fetch_order(order_id)
        if order is None:
            abort(404)
        set_request_environment_for_order(order)
        require_order_role(order, "from_store_id")
        if order["status"] != "pending_sender_approval":
            flash("この発注には承認待ちの受取差異がありません。", "error")
            return redirect(url_for("received_detail", order_id=order_id))
        try:
            db.execute(
                """UPDATE order_items SET final_received_quantity = received_quantity,
                          final_received_quantity_minor = received_quantity_minor
                   WHERE order_id = ? AND final_received_quantity IS NULL""",
                (order_id,),
            )
            db.execute(
                """UPDATE unexpected_items
                   SET status = 'accepted', final_received_quantity = arrived_quantity,
                       final_received_quantity_minor = arrived_quantity_minor,
                       updated_at = datetime('now', 'localtime')
                   WHERE order_id = ? AND status = 'accept_pending'""",
                (order_id,),
            )
            db.execute(
                """UPDATE orders SET status = 'received',
                       sender_approved_at = datetime('now', 'localtime'),
                       received_at = datetime('now', 'localtime')
                   WHERE id = ?""",
                (order_id,),
            )
            audit_operation(
                "approval_confirmed", order, store_id=order["from_store_id"],
                after={"status": "received"}, approval_status="received",
            )
            db.commit()
        except sqlite3.Error:
            db.rollback()
            raise
        flash("数量差異・注文外商品の受取を承認しました。", "success")
        return redirect(url_for("received_detail", order_id=order_id))

    @app.post("/received/<int:order_id>/unexpected/<int:item_id>/complete-return")
    def complete_unexpected_return(order_id, item_id):
        db = get_db()
        item = db.execute(
            "SELECT * FROM unexpected_items WHERE id = ? AND order_id = ?",
            (item_id, order_id),
        ).fetchone()
        if item is None:
            abort(404)
        order = fetch_order(order_id)
        if order is None:
            abort(404)
        set_request_environment_for_order(order)
        require_order_role(order, "from_store_id")
        if item["status"] != "returned":
            flash("返品済みの商品だけ返品完了にできます。", "error")
        else:
            db.execute(
                """UPDATE unexpected_items SET status = 'return_complete',
                       updated_at = datetime('now', 'localtime') WHERE id = ?""",
                (item_id,),
            )
            audit_operation(
                "return_completed", order, store_id=order["from_store_id"],
                product_name=item["product_name"], quantity_minor=item["arrived_quantity_minor"],
                before={"status": "returned"}, after={"status": "return_complete"},
                approval_status="return_complete",
            )
            db.commit()
            flash(f"「{item['product_name']}」の返品を確認しました。", "success")
        return redirect(url_for("received_detail", order_id=order_id))

    @app.get("/receipts")
    def receipts():
        db = get_db()
        store_id = report_scope_store_id(request.args.get("store_id", type=int))
        selected_environment = report_scope_environment(
            request.args.get("environment"), store_id
        )
        store_id = normalize_report_store_id(store_id, selected_environment)
        set_request_environment(selected_environment)
        stores = db.execute(
            """SELECT * FROM stores WHERE is_deleted = 0 AND environment = ?
               ORDER BY is_active DESC, name, id""", (selected_environment,)
        ).fetchall() if is_environment_operator() else []
        selected_store = None
        orders = []
        if store_id:
            selected_store = db.execute(
                "SELECT * FROM stores WHERE id = ? AND is_deleted = 0", (store_id,)
            ).fetchone()
            if selected_store:
                store_column = "o.from_store_id" if is_environment_operator() else "o.to_store_id"
                orders = db.execute(
                    f"""SELECT o.*, f.name AS from_store_name, t.name AS to_store_name,
                              COUNT(oi.id) AS item_count,
                              SUM(CASE WHEN oi.unit_price IS NOT NULL
                                  THEN oi.quantity * oi.unit_price ELSE 0 END) AS total
                       FROM orders o
                       JOIN stores f ON f.id = o.from_store_id
                       JOIN stores t ON t.id = o.to_store_id
                       JOIN order_items oi ON oi.order_id = o.id
                       WHERE {store_column} = ?
                       GROUP BY o.id
                       ORDER BY CASE o.status WHEN 'ordered' THEN 0 ELSE 1 END,
                                o.created_at DESC, o.id DESC""",
                    (store_id,),
                ).fetchall()
        return render_template(
            "receipts.html", stores=stores, selected_store=selected_store, orders=orders
        )

    @app.route("/receipts/<int:order_id>", methods=["GET", "POST"])
    def receipt_detail(order_id):
        db = get_db()
        order = fetch_order(order_id)
        if order is None:
            abort(404)
        if not can_access_order(order):
            abort(403)
        set_request_environment_for_order(order)
        items = db.execute(
            "SELECT * FROM order_items WHERE order_id = ? ORDER BY id", (order_id,)
        ).fetchall()
        unexpected_items = db.execute(
            "SELECT * FROM unexpected_items WHERE order_id = ? ORDER BY id", (order_id,)
        ).fetchall()
        products = orderable_products()

        if request.method == "POST":
            require_order_role(order, "to_store_id")
            if order["status"] != "ordered":
                flash("この発注はすでに受取報告済みです。", "error")
                return redirect(url_for("receipt_detail", order_id=order_id))

            received_values = []
            approval_required = False
            for item in items:
                raw = request.form.get(f"received_quantity_{item['id']}", "").strip()
                try:
                    amount, amount_minor = parse_quantity(
                        raw, item["quantity_decimal_places"], allow_zero=True
                    )
                except InvalidOperation:
                    flash("届いた数量は0以上の数値で入力してください。", "error")
                    return redirect(url_for("receipt_detail", order_id=order_id))
                is_match = amount_minor == item["quantity_minor"]
                approval_required = approval_required or not is_match
                final_quantity = float(amount) if is_match else None
                final_minor = amount_minor if is_match else None
                received_values.append((
                    float(amount), amount_minor, final_quantity, final_minor,
                    item["id"], order_id
                ))

            ordered_product_ids = {item["product_id"] for item in items}
            product_map = {product["id"]: product for product in products}
            product_map.update({
                product["source_product_id"]: product for product in products
                if product["source_product_id"]
            })
            extra_values = []
            seen_extra_products = set()
            extra_keys = sorted(
                key for key in request.form if key.startswith("unexpected_product_")
            )
            for key in extra_keys:
                suffix = key.removeprefix("unexpected_product_")
                product_id = request.form.get(key, type=int)
                raw_quantity = request.form.get(f"unexpected_quantity_{suffix}", "").strip()
                decision = request.form.get(f"unexpected_decision_{suffix}", "")
                if not product_id and not raw_quantity:
                    continue
                product = product_map.get(product_id)
                if (
                    product is None or product_id in ordered_product_ids
                    or product_id in seen_extra_products or decision not in {"return", "accept"}
                ):
                    flash("注文外商品と対応方法を正しく選択してください。", "error")
                    return redirect(url_for("receipt_detail", order_id=order_id))
                try:
                    amount, amount_minor = parse_quantity(
                        raw_quantity, product["decimal_places"]
                    )
                except InvalidOperation:
                    flash("注文外商品の数量は0より大きい数値で入力してください。", "error")
                    return redirect(url_for("receipt_detail", order_id=order_id))
                seen_extra_products.add(product_id)
                status = "return_pending" if decision == "return" else "accept_pending"
                final_quantity = 0 if decision == "return" else None
                approval_required = approval_required or decision == "accept"
                extra_values.append((
                    order_id, product_id, product["name"], product["unit"],
                    float(amount), amount_minor, product["decimal_places"], decision,
                    status, final_quantity, 0 if decision == "return" else None,
                    product["unit_price"],
                    product["major_name"], product["subcategory_name"],
                ))

            try:
                db.executemany(
                    """UPDATE order_items
                       SET received_quantity = ?, received_quantity_minor = ?,
                           final_received_quantity = ?, final_received_quantity_minor = ?
                       WHERE id = ? AND order_id = ?""",
                    received_values,
                )
                if extra_values:
                    db.executemany(
                        """INSERT INTO unexpected_items
                           (order_id, product_id, product_name, unit, arrived_quantity,
                            arrived_quantity_minor, quantity_decimal_places, decision,
                            status, final_received_quantity, final_received_quantity_minor, unit_price,
                            major_category_name, subcategory_name)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        extra_values,
                    )
                new_status = "pending_sender_approval" if approval_required else "received"
                db.execute(
                    """UPDATE orders SET status = ?,
                       receipt_reported_at = datetime('now', 'localtime'),
                       received_at = CASE WHEN ? = 'received'
                           THEN datetime('now', 'localtime') ELSE NULL END
                       WHERE id = ?""",
                    (new_status, new_status, order_id),
                )
                for item, values in zip(items, received_values):
                    received_minor = values[1]
                    event_type = "receipt_confirmed" if received_minor == item["quantity_minor"] else "quantity_difference"
                    audit_operation(
                        event_type, order, store_id=order["to_store_id"],
                        product_name=item["product_name"], quantity_minor=received_minor,
                        before={"ordered_quantity_minor": item["quantity_minor"]},
                        after={"received_quantity_minor": received_minor},
                        approval_status=new_status,
                    )
                for values in extra_values:
                    audit_operation(
                        "unexpected_item", order, store_id=order["to_store_id"],
                        product_name=values[2], quantity_minor=values[5],
                        after={"decision": values[7], "quantity_minor": values[5]},
                        approval_status=new_status,
                    )
                db.commit()
            except sqlite3.Error:
                db.rollback()
                raise
            if approval_required:
                flash("差異を記録し、送付元店舗へ確認依頼を送りました。", "success")
            else:
                flash(f"{order['order_number']}を受取承認しました。", "success")
            return redirect(url_for("receipt_detail", order_id=order_id))

        return render_template(
            "receipt_detail.html", order=order, items=items,
            unexpected_items=unexpected_items, products=products,
            ordered_product_ids={item["product_id"] for item in items},
            can_receive_action=is_environment_operator() or g.user["store_id"] == order["to_store_id"],
        )

    @app.post("/receipts/<int:order_id>/unexpected/<int:item_id>/returned")
    def mark_unexpected_returned(order_id, item_id):
        db = get_db()
        item = db.execute(
            "SELECT * FROM unexpected_items WHERE id = ? AND order_id = ?",
            (item_id, order_id),
        ).fetchone()
        if item is None:
            abort(404)
        order = fetch_order(order_id)
        if order is None:
            abort(404)
        set_request_environment_for_order(order)
        require_order_role(order, "to_store_id")
        if item["status"] != "return_pending":
            flash("返品予定の商品だけ返品済みにできます。", "error")
        else:
            db.execute(
                """UPDATE unexpected_items SET status = 'returned',
                       updated_at = datetime('now', 'localtime') WHERE id = ?""",
                (item_id,),
            )
            audit_operation(
                "return_confirmed", order, store_id=order["to_store_id"],
                product_name=item["product_name"], quantity_minor=item["arrived_quantity_minor"],
                before={"status": "return_pending"}, after={"status": "returned"},
                approval_status="returned",
            )
            db.commit()
            flash(f"「{item['product_name']}」を返品済みにしました。", "success")
        return redirect(url_for("receipt_detail", order_id=order_id))

    @app.get("/reports")
    def reports():
        month, start_date, end_date = parse_month(request.args.get("month"))
        scope_store_id = report_scope_store_id(request.args.get("store_id", type=int))
        scope_environment = report_scope_environment(
            request.args.get("environment"), scope_store_id
        )
        scope_store_id = normalize_report_store_id(scope_store_id, scope_environment)
        set_request_environment(scope_environment)
        lines = transaction_lines(start_date, end_date, environment=scope_environment)
        db = get_db()
        if is_environment_operator():
            if scope_store_id:
                stores = db.execute(
                    "SELECT * FROM stores WHERE id = ? AND is_deleted = 0", (scope_store_id,)
                ).fetchall()
            else:
                store_ids = store_ids_for_environment(scope_environment)
                placeholders = ",".join("?" for _ in store_ids)
                stores = db.execute(
                    f"""SELECT * FROM stores
                        WHERE is_deleted = 0 AND id IN ({placeholders}) ORDER BY id""",
                    store_ids,
                ).fetchall()
            store_options = db.execute(
                """SELECT * FROM stores
                   WHERE is_deleted = 0 AND environment = ? ORDER BY id""",
                (scope_environment,),
            ).fetchall()
        else:
            stores = db.execute("SELECT * FROM stores WHERE id = ?", (scope_store_id,)).fetchall()
            store_options = []

        summaries = []
        for store in stores:
            issued = [line for line in lines if line["from_store_id"] == store["id"]]
            received = [line for line in lines if line["to_store_id"] == store["id"]]
            summaries.append({
                "store": store,
                "issue_amount": sum(line["ordered_amount"] for line in issued),
                "receipt_amount": sum(line["final_amount"] or 0 for line in received),
                "issue_count": len({line["order_id"] for line in issued}),
                "receipt_count": len({line["order_id"] for line in received}),
            })
        visible_lines = lines if scope_store_id is None else [
            line for line in lines
            if scope_store_id in {line["from_store_id"], line["to_store_id"]}
        ]
        product_summary = aggregate_products(visible_lines)
        return render_template(
            "reports.html", month=month, summaries=summaries,
            product_summary=product_summary, store_options=store_options,
            selected_store_id=scope_store_id,
            selected_environment=scope_environment, environments=ENVIRONMENT_LABELS,
            month_start=start_date.isoformat(),
            month_end=(end_date - timedelta(days=1)).isoformat(),
        )

    @app.get("/reports/store/<int:store_id>")
    def report_store(store_id):
        require_report_store(store_id)
        month, start_date, end_date = parse_month(request.args.get("month"))
        store = get_db().execute(
            "SELECT * FROM stores WHERE id = ? AND is_deleted = 0", (store_id,)
        ).fetchone()
        if store is None:
            abort(404)
        set_request_environment(store["environment"])
        lines = transaction_lines(start_date, end_date, store_id)
        issued = aggregate_counterparty_products(lines, store_id, "orders")
        received = aggregate_counterparty_products(lines, store_id, "receipts")
        return render_template(
            "report_store.html", month=month, store=store,
            issued=issued, received=received,
        )

    @app.get("/reports/daily")
    def report_daily():
        report_date = parse_report_date(request.args.get("date"))
        scope_store_id = report_scope_store_id(request.args.get("store_id", type=int))
        scope_environment = report_scope_environment(
            request.args.get("environment"), scope_store_id
        )
        scope_store_id = normalize_report_store_id(scope_store_id, scope_environment)
        set_request_environment(scope_environment)
        lines = transaction_lines(
            report_date, report_date + timedelta(days=1), scope_store_id,
            scope_environment,
        )
        store_options = []
        if is_environment_operator():
            store_options = get_db().execute(
                """SELECT * FROM stores
                   WHERE is_deleted = 0 AND environment = ? ORDER BY id""",
                (scope_environment,),
            ).fetchall()
        return render_template(
            "report_daily.html", report_date=report_date.isoformat(), lines=lines,
            product_summary=aggregate_products(lines), store_options=store_options,
            selected_store_id=scope_store_id, selected_environment=scope_environment,
            environments=ENVIRONMENT_LABELS,
        )

    @app.route("/reports/correct/<line_type>/<int:line_id>", methods=["GET", "POST"])
    @business_admin_required
    def correct_transaction(line_type, line_id):
        if line_type not in {"order_item", "unexpected_item"}:
            abort(404)
        line = find_transaction_line(line_type, line_id)
        if line is None:
            abort(404)
        if is_training_reviewer() and line["environment"] != "training":
            abort(403)
        set_request_environment(line["environment"])
        db = get_db()
        if request.method == "POST":
            reason = " ".join(request.form.get("reason", "").split())
            product_id = request.form.get("product_id", type=int)
            raw_quantity = request.form.get("quantity", "").strip()
            raw_price = request.form.get("unit_price", "").replace(",", "").strip()
            product = db.execute(
                """SELECT p.*, major.name AS major_name, sub.name AS subcategory_name,
                          u.decimal_places
                   FROM products p
                   JOIN product_categories major ON major.id = p.major_category_id
                   JOIN product_categories sub ON sub.id = p.subcategory_id
                   JOIN units u ON u.id = p.unit_id
                   WHERE p.id = ? AND p.is_deleted = 0 AND p.environment = ?""",
                (product_id, line["environment"])
            ).fetchone()
            error = None
            try:
                quantity_value, quantity_minor = parse_quantity(
                    raw_quantity, product["decimal_places"] if product else 2,
                    allow_zero=True,
                )
            except InvalidOperation:
                error = "最終数量は0以上の数値で入力してください。"
                quantity_value = Decimal("0")
                quantity_minor = 0
            unit_price = None
            if raw_price:
                try:
                    unit_price = int(raw_price)
                    if unit_price < 0 or unit_price > 100_000_000:
                        raise ValueError
                except ValueError:
                    error = error or "単価は0～100,000,000円の整数で入力してください。"
            if product is None:
                error = error or "有効な商品を選択してください。"
            if not reason:
                error = error or "訂正理由を入力してください。"
            if error:
                flash(error, "error")
            else:
                before = correction_snapshot(line)
                after = {
                    "product_id": product["id"], "product_name": product["name"],
                    "major_category_name": product["major_name"],
                    "subcategory_name": product["subcategory_name"],
                    "unit": product["unit"], "quantity": float(quantity_value),
                    "unit_price": unit_price,
                }
                db.execute(
                    """INSERT INTO transaction_corrections
                       (order_id, line_type, line_id, corrected_product_id,
                        corrected_product_name, corrected_major_category_name,
                        corrected_subcategory_name, corrected_unit, corrected_quantity,
                        corrected_quantity_minor, corrected_unit_price, reason,
                        before_json, after_json, admin_user_id)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (line["order_id"], line_type, line_id, product["id"], product["name"],
                     product["major_name"], product["subcategory_name"], product["unit"],
                     float(quantity_value), quantity_minor, unit_price, reason,
                     json.dumps(before, ensure_ascii=False), json.dumps(after, ensure_ascii=False),
                     g.user["id"]),
                )
                audit_operation(
                    "correction", fetch_order(line["order_id"]),
                    product_name=product["name"], quantity_minor=quantity_minor,
                    before=before, after=after, approval_status="corrected",
                )
                db.commit()
                flash("最終確定値を訂正し、訂正履歴を保存しました。", "success")
                return redirect(url_for(
                    "report_daily", date=line["date"], store_id=request.args.get("store_id")
                ))
        products = db.execute(
            """SELECT p.*, major.name AS major_name, sub.name AS subcategory_name,
                      u.decimal_places
               FROM products p JOIN product_categories major ON major.id = p.major_category_id
               JOIN product_categories sub ON sub.id = p.subcategory_id
               JOIN units u ON u.id = p.unit_id
               WHERE p.is_deleted = 0 AND p.environment = ?
               ORDER BY major.name, sub.name, p.name""", (line["environment"],)
        ).fetchall()
        history = correction_history(line_type, line_id)
        return render_template(
            "correction_form.html", line=line, products=products, history=history
        )

    @app.get("/reports/corrections")
    @business_admin_required
    def report_corrections():
        environment = report_scope_environment(request.args.get("environment"))
        set_request_environment(environment)
        rows = get_db().execute(
            """SELECT c.*, u.login_id AS admin_login_id, o.order_number,
                      f.name AS from_store_name, t.name AS to_store_name
               FROM transaction_corrections c
               JOIN users u ON u.id = c.admin_user_id
               JOIN orders o ON o.id = c.order_id
               JOIN stores f ON f.id = o.from_store_id
               JOIN stores t ON t.id = o.to_store_id
               WHERE f.environment = ? AND t.environment = ?
               ORDER BY c.created_at DESC, c.id DESC"""
        , (environment, environment)).fetchall()
        return render_template(
            "correction_history.html", corrections=rows,
            selected_environment=environment, environments=ENVIRONMENT_LABELS,
        )

    @app.get("/reports/csv")
    def report_csv():
        direction = request.args.get("direction", "orders")
        if direction not in {"orders", "receipts"}:
            abort(400)
        start_date = parse_report_date(request.args.get("start_date"))
        end_inclusive = parse_report_date(request.args.get("end_date"), start_date)
        if end_inclusive < start_date:
            abort(400)
        scope_store_id = report_scope_store_id(request.args.get("store_id", type=int))
        scope_environment = report_scope_environment(
            request.args.get("environment"), scope_store_id
        )
        scope_store_id = normalize_report_store_id(scope_store_id, scope_environment)
        lines = transaction_lines(
            start_date, end_inclusive + timedelta(days=1),
            environment=scope_environment,
        )
        if scope_store_id:
            key = "from_store_id" if direction == "orders" else "to_store_id"
            lines = [line for line in lines if line[key] == scope_store_id]
        output = io.StringIO()
        writer = csv.writer(output, lineterminator="\r\n")
        writer.writerow([
            "日付", "時刻", "発注番号", "発注元店舗", "発注先店舗", "大分類", "中分類",
            "商品名", "発注数量", "最終数量", "単位", "単価", "発注金額", "最終金額",
            "状態", "訂正あり／なし",
        ])
        for line in lines:
            writer.writerow([
                line["date"], line["time"], line["order_number"],
                line["from_store_name"], line["to_store_name"], line["major_category_name"],
                line["subcategory_name"], line["product_name"], line["ordered_quantity"],
                "" if line["final_quantity"] is None else line["final_quantity"], line["unit"],
                "" if line["unit_price"] is None else line["unit_price"],
                line["ordered_amount"], "" if line["final_amount"] is None else line["final_amount"],
                line["status_label"], "あり" if line["corrected"] else "なし",
            ])
        csv_bytes = ("\ufeff" + output.getvalue()).encode("utf-8")
        filename = f"pita_{direction}_{start_date.isoformat()}_{end_inclusive.isoformat()}.csv"
        return Response(
            csv_bytes, mimetype="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.get("/product-management")
    @business_admin_required
    def product_management():
        environment = master_environment()
        set_request_environment(environment)
        products = get_db().execute(
            """SELECT p.*, major.name AS major_name, sub.name AS subcategory_name,
                      u.name AS unit_name
               FROM products p
               LEFT JOIN product_categories major ON major.id = p.major_category_id
               LEFT JOIN product_categories sub ON sub.id = p.subcategory_id
               LEFT JOIN units u ON u.id = p.unit_id
               WHERE p.is_deleted = 0 AND p.environment = ?
               ORDER BY p.is_active DESC, major.name, sub.name, p.display_order, p.id""",
            (environment,),
        ).fetchall()
        return render_template("product_management.html", products=products)

    @app.route("/product-management/new", methods=["GET", "POST"])
    @business_admin_required
    def new_product():
        if request.method == "POST":
            return save_product_form()
        return render_product_form()

    @app.route("/product-management/<int:product_id>/edit", methods=["GET", "POST"])
    @business_admin_required
    def edit_product(product_id):
        product = get_db().execute(
            "SELECT * FROM products WHERE id = ? AND is_deleted = 0 AND environment = ?",
            (product_id, master_environment())
        ).fetchone()
        if product is None:
            abort(404)
        if request.method == "POST":
            return save_product_form(product)
        return render_product_form(product)

    @app.post("/product-management/<int:product_id>/toggle")
    @business_admin_required
    def toggle_product(product_id):
        db = get_db()
        product = db.execute(
            "SELECT * FROM products WHERE id = ? AND is_deleted = 0 AND environment = ?",
            (product_id, master_environment())
        ).fetchone()
        if product is None:
            abort(404)
        new_status = 0 if product["is_active"] else 1
        db.execute("UPDATE products SET is_active = ? WHERE id = ?", (new_status, product_id))
        db.commit()
        flash(f"「{product['name']}」を{'再開' if new_status else '停止'}しました。", "success")
        return redirect(url_for("product_management"))

    @app.post("/product-management/<int:product_id>/delete")
    @business_admin_required
    def delete_product(product_id):
        db = get_db()
        product = db.execute(
            "SELECT * FROM products WHERE id = ? AND is_deleted = 0 AND environment = ?",
            (product_id, master_environment())
        ).fetchone()
        if product is None:
            abort(404)
        db.execute(
            "UPDATE products SET is_active = 0, is_deleted = 1 WHERE id = ?", (product_id,)
        )
        db.commit()
        flash(f"「{product['name']}」を削除しました。過去の発注履歴は保持されます。", "success")
        return redirect(url_for("product_management"))

    @app.get("/categories")
    @business_admin_required
    def categories():
        db = get_db()
        environment = master_environment()
        set_request_environment(environment)
        majors = db.execute(
            """SELECT * FROM product_categories
               WHERE level = 1 AND is_deleted = 0 AND environment = ? ORDER BY id""",
            (environment,),
        ).fetchall()
        subs = db.execute(
            """SELECT c.*, p.name AS parent_name FROM product_categories c
               JOIN product_categories p ON p.id = c.parent_id
               WHERE c.level = 2 AND c.is_deleted = 0 AND c.environment = ?
                 AND p.environment = ? ORDER BY p.id, c.id""",
            (environment, environment),
        ).fetchall()
        return render_template("categories.html", majors=majors, subcategories=subs)

    @app.post("/categories/add")
    @business_admin_required
    def add_category():
        db = get_db()
        environment = master_environment()
        name = normalize_master_name(request.form.get("name"))
        level = request.form.get("level", type=int)
        parent_id = request.form.get("parent_id", type=int) if level == 2 else None
        error = validate_category(db, name, level, parent_id, environment=environment)
        if error:
            flash(error, "error")
        else:
            db.execute(
                "INSERT INTO product_categories (name, level, parent_id, environment) VALUES (?, ?, ?, ?)",
                (name, level, parent_id, environment),
            )
            db.commit()
            flash(f"分類「{name}」を追加しました。", "success")
        return redirect(url_for("categories"))

    @app.route("/categories/<int:category_id>/edit", methods=["GET", "POST"])
    @business_admin_required
    def edit_category(category_id):
        db = get_db()
        category = db.execute(
            "SELECT * FROM product_categories WHERE id = ? AND is_deleted = 0 AND environment = ?",
            (category_id, master_environment()),
        ).fetchone()
        if category is None:
            abort(404)
        if request.method == "POST":
            name = normalize_master_name(request.form.get("name"))
            error = validate_category(
                db, name, category["level"], category["parent_id"], category_id,
                category["environment"]
            )
            if error:
                flash(error, "error")
            else:
                db.execute("UPDATE product_categories SET name = ? WHERE id = ?", (name, category_id))
                db.commit()
                flash(f"分類名を「{name}」に変更しました。", "success")
                return redirect(url_for("categories"))
        return render_template("master_edit.html", item=category, master_name="分類", back_endpoint="categories")

    @app.post("/categories/<int:category_id>/toggle")
    @business_admin_required
    def toggle_category(category_id):
        db = get_db()
        category = db.execute(
            "SELECT * FROM product_categories WHERE id = ? AND is_deleted = 0 AND environment = ?",
            (category_id, master_environment()),
        ).fetchone()
        if category is None:
            abort(404)
        new_status = 0 if category["is_active"] else 1
        db.execute("UPDATE product_categories SET is_active = ? WHERE id = ?", (new_status, category_id))
        db.commit()
        flash(f"分類「{category['name']}」を{'再開' if new_status else '停止'}しました。", "success")
        return redirect(url_for("categories"))

    @app.post("/categories/<int:category_id>/delete")
    @business_admin_required
    def delete_category(category_id):
        db = get_db()
        category = db.execute(
            "SELECT * FROM product_categories WHERE id = ? AND is_deleted = 0 AND environment = ?",
            (category_id, master_environment()),
        ).fetchone()
        if category is None:
            abort(404)
        product_column = "major_category_id" if category["level"] == 1 else "subcategory_id"
        used = db.execute(
            f"SELECT 1 FROM products WHERE {product_column} = ? AND is_deleted = 0 LIMIT 1",
            (category_id,),
        ).fetchone()
        children = None
        if category["level"] == 1:
            children = db.execute(
                """SELECT 1 FROM product_categories
                   WHERE parent_id = ? AND is_deleted = 0 LIMIT 1""", (category_id,)
            ).fetchone()
        if used or children:
            flash("使用中の分類は削除できません。商品または中分類を変更・削除してください。", "error")
        else:
            db.execute(
                "UPDATE product_categories SET is_active = 0, is_deleted = 1 WHERE id = ?",
                (category_id,),
            )
            db.commit()
            flash(f"分類「{category['name']}」を削除しました。", "success")
        return redirect(url_for("categories"))

    @app.get("/units")
    @business_admin_required
    def units():
        environment = master_environment()
        set_request_environment(environment)
        rows = get_db().execute(
            "SELECT * FROM units WHERE is_deleted = 0 AND environment = ? ORDER BY id",
            (environment,),
        ).fetchall()
        return render_template("units.html", units=rows)

    @app.post("/units/add")
    @business_admin_required
    def add_unit():
        db = get_db()
        environment = master_environment()
        name = normalize_master_name(request.form.get("name"))
        decimal_places = request.form.get("decimal_places", type=int)
        if decimal_places is None:
            decimal_places = 0
        if not name:
            flash("単位名を入力してください。", "error")
        elif len(name) > 20:
            flash("単位名は20文字以内で入力してください。", "error")
        elif decimal_places not in {0, 1, 2}:
            flash("小数桁数は0～2を選択してください。", "error")
        elif db.execute("SELECT 1 FROM units WHERE name = ? AND environment = ?", (name, environment)).fetchone():
            flash("同じ単位がすでに登録されています。", "error")
        else:
            db.execute("INSERT INTO units (name, environment, decimal_places) VALUES (?, ?, ?)", (name, environment, decimal_places))
            db.commit()
            flash(f"単位「{name}」を追加しました。", "success")
        return redirect(url_for("units"))

    @app.route("/units/<int:unit_id>/edit", methods=["GET", "POST"])
    @business_admin_required
    def edit_unit(unit_id):
        db = get_db()
        unit = db.execute("SELECT * FROM units WHERE id = ? AND is_deleted = 0 AND environment = ?", (unit_id, master_environment())).fetchone()
        if unit is None:
            abort(404)
        if request.method == "POST":
            name = normalize_master_name(request.form.get("name"))
            decimal_places = request.form.get("decimal_places", type=int)
            if decimal_places is None:
                decimal_places = unit["decimal_places"]
            if not name or len(name) > 20:
                flash("単位名は1～20文字で入力してください。", "error")
            elif decimal_places not in {0, 1, 2}:
                flash("小数桁数は0～2を選択してください。", "error")
            elif db.execute("SELECT 1 FROM units WHERE name = ? AND environment = ? AND id <> ?", (name, unit["environment"], unit_id)).fetchone():
                flash("同じ単位がすでに登録されています。", "error")
            else:
                db.execute("UPDATE units SET name = ?, decimal_places = ? WHERE id = ?", (name, decimal_places, unit_id))
                db.execute("UPDATE products SET unit = ? WHERE unit_id = ? AND environment = ?", (name, unit_id, unit["environment"]))
                db.commit()
                flash(f"単位を「{name}」に変更しました。", "success")
                return redirect(url_for("units"))
        return render_template("master_edit.html", item=unit, master_name="単位", back_endpoint="units")

    @app.post("/units/<int:unit_id>/toggle")
    @business_admin_required
    def toggle_unit(unit_id):
        db = get_db()
        unit = db.execute("SELECT * FROM units WHERE id = ? AND is_deleted = 0 AND environment = ?", (unit_id, master_environment())).fetchone()
        if unit is None:
            abort(404)
        new_status = 0 if unit["is_active"] else 1
        db.execute("UPDATE units SET is_active = ? WHERE id = ?", (new_status, unit_id))
        db.commit()
        flash(f"単位「{unit['name']}」を{'再開' if new_status else '停止'}しました。", "success")
        return redirect(url_for("units"))

    @app.post("/units/<int:unit_id>/delete")
    @business_admin_required
    def delete_unit(unit_id):
        db = get_db()
        unit = db.execute("SELECT * FROM units WHERE id = ? AND is_deleted = 0 AND environment = ?", (unit_id, master_environment())).fetchone()
        if unit is None:
            abort(404)
        used = db.execute(
            "SELECT 1 FROM products WHERE unit_id = ? AND is_deleted = 0 LIMIT 1", (unit_id,)
        ).fetchone()
        if used:
            flash("商品で使用中の単位は削除できません。", "error")
        else:
            db.execute("UPDATE units SET is_active = 0, is_deleted = 1 WHERE id = ?", (unit_id,))
            db.commit()
            flash(f"単位「{unit['name']}」を削除しました。", "success")
        return redirect(url_for("units"))

    @app.route("/accounts", methods=["GET", "POST"])
    @admin_required
    def accounts():
        db = get_db()
        if request.method == "POST":
            store_id = request.form.get("store_id", type=int)
            login_id = normalize_login_id(request.form.get("login_id"))
            password = request.form.get("password", "")
            store = db.execute(
                """SELECT s.* FROM stores s LEFT JOIN users u ON u.store_id = s.id
                   WHERE s.id = ? AND s.is_deleted = 0 AND u.id IS NULL""",
                (store_id,),
            ).fetchone()
            error = validate_credentials(login_id, password)
            if store is None:
                error = "アカウント未登録の店舗を選択してください。"
            if db.execute("SELECT 1 FROM users WHERE login_id = ?", (login_id,)).fetchone():
                error = "このログインIDはすでに使用されています。"
            if error:
                flash(error, "error")
            else:
                db.execute(
                    """INSERT INTO users (login_id, password_hash, role, store_id)
                       VALUES (?, ?, 'store', ?)""",
                    (login_id, generate_password_hash(password), store_id),
                )
                db.commit()
                flash(f"{store['name']}のログインアカウントを作成しました。", "success")
                return redirect(url_for("accounts"))

        account_rows = db.execute(
            """SELECT u.*, s.name AS store_name, s.environment,
                      s.is_active AS store_is_active
               FROM users u JOIN stores s ON s.id = u.store_id
               WHERE u.role = 'store' AND s.is_deleted = 0 ORDER BY s.id"""
        ).fetchall()
        available_stores = db.execute(
            """SELECT s.* FROM stores s LEFT JOIN users u ON u.store_id = s.id
               WHERE s.is_deleted = 0 AND u.id IS NULL ORDER BY s.id"""
        ).fetchall()
        reviewer_accounts = db.execute(
            """SELECT * FROM users
               WHERE role = 'admin' AND is_training_reviewer = 1 ORDER BY id"""
        ).fetchall()
        return render_template(
            "accounts.html", accounts=account_rows, available_stores=available_stores,
            reviewer_accounts=reviewer_accounts,
        )

    @app.post("/accounts/training-reviewer")
    @admin_required
    def create_training_reviewer():
        db = get_db()
        login_id = normalize_login_id(request.form.get("login_id"))
        password = request.form.get("password", "")
        error = validate_credentials(login_id, password)
        if db.execute("SELECT 1 FROM users WHERE login_id = ?", (login_id,)).fetchone():
            error = "このログインIDはすでに使用されています。"
        if error:
            flash(error, "error")
        else:
            db.execute(
                """INSERT INTO users
                   (login_id, password_hash, role, is_training_reviewer)
                   VALUES (?, ?, 'admin', 1)""",
                (login_id, generate_password_hash(password)),
            )
            db.commit()
            flash("社長確認用アカウントを作成しました。", "success")
        return redirect(url_for("accounts"))

    @app.route("/accounts/<int:user_id>/edit", methods=["GET", "POST"])
    @admin_required
    def edit_account(user_id):
        db = get_db()
        account = db.execute(
            """SELECT u.*, COALESCE(s.name, '社長確認用アカウント') AS store_name
               FROM users u LEFT JOIN stores s ON s.id = u.store_id
               WHERE u.id = ? AND (
                   (u.role = 'store' AND s.is_deleted = 0)
                   OR (u.role = 'admin' AND u.is_training_reviewer = 1)
               )""",
            (user_id,),
        ).fetchone()
        if account is None:
            abort(404)
        if request.method == "POST":
            login_id = normalize_login_id(request.form.get("login_id"))
            password = request.form.get("password", "")
            password_confirmation = request.form.get("password_confirmation", "")
            error = validate_login_id(login_id)
            if password and len(password) < 8:
                error = "新しいパスワードは8文字以上で入力してください。"
            elif password and password != password_confirmation:
                error = "確認用パスワードが一致しません。"
            if db.execute(
                "SELECT 1 FROM users WHERE login_id = ? AND id <> ?", (login_id, user_id)
            ).fetchone():
                error = "このログインIDはすでに使用されています。"
            if error:
                flash(error, "error")
            else:
                if password:
                    db.execute(
                        """UPDATE users
                           SET login_id = ?, password_hash = ?,
                               session_version = session_version + 1
                           WHERE id = ?""",
                        (login_id, generate_password_hash(password), user_id),
                    )
                else:
                    db.execute(
                        """UPDATE users SET login_id = ?,
                               session_version = session_version + 1 WHERE id = ?""",
                        (login_id, user_id),
                    )
                db.commit()
                flash(f"{account['store_name']}のアカウントを更新しました。", "success")
                return redirect(url_for("accounts"))
        return render_template("account_edit.html", account=account)

    @app.post("/accounts/<int:user_id>/toggle")
    @admin_required
    def toggle_account(user_id):
        db = get_db()
        account = db.execute(
            """SELECT u.*, COALESCE(s.name, '社長確認用アカウント') AS store_name
               FROM users u LEFT JOIN stores s ON s.id = u.store_id
               WHERE u.id = ? AND (
                   u.role = 'store' OR (u.role = 'admin' AND u.is_training_reviewer = 1)
               )""", (user_id,)
        ).fetchone()
        if account is None:
            abort(404)
        new_status = 0 if account["is_active"] else 1
        db.execute(
            """UPDATE users SET is_active = ?,
                   session_version = session_version + 1 WHERE id = ?""",
            (new_status, user_id),
        )
        db.commit()
        flash(f"{account['store_name']}のアカウントを{'再開' if new_status else '停止'}しました。", "success")
        return redirect(url_for("accounts"))

    @app.route("/stores", methods=["GET", "POST"])
    @admin_required
    def stores():
        db = get_db()
        if request.method == "POST":
            name = normalize_store_name(request.form.get("name"))
            environment = request.form.get("environment", "production")
            if not name:
                flash("店舗名を入力してください。", "error")
            elif len(name) > 50:
                flash("店舗名は50文字以内で入力してください。", "error")
            elif environment not in ENVIRONMENT_LABELS:
                flash("環境を正しく選択してください。", "error")
            elif db.execute("SELECT 1 FROM stores WHERE name = ?", (name,)).fetchone():
                flash("同じ店舗名がすでに登録されています。", "error")
            else:
                db.execute(
                    "INSERT INTO stores (name, environment) VALUES (?, ?)",
                    (name, environment),
                )
                db.commit()
                flash(f"「{name}」を追加しました。", "success")
                return redirect(url_for("stores"))
        store_rows = db.execute(
            """SELECT s.*, u.id AS account_id, u.login_id, u.is_active AS account_active
               FROM stores s LEFT JOIN users u ON u.store_id = s.id AND u.role = 'store'
               WHERE s.is_deleted = 0 ORDER BY s.id"""
        ).fetchall()
        return render_template(
            "stores.html", stores=store_rows, environments=ENVIRONMENT_LABELS
        )

    @app.post("/stores/provision/training")
    @admin_required
    def provision_training_stores():
        db = get_db()
        created = []
        for name in TRAINING_STORE_NAMES:
            if db.execute("SELECT 1 FROM stores WHERE name = ?", (name,)).fetchone() is None:
                db.execute(
                    "INSERT INTO stores (name, environment) VALUES (?, 'training')",
                    (name,),
                )
                created.append(name)
        db.commit()
        if created:
            flash(f"{'、'.join(created)}を作成しました。アカウント画面でログイン情報を設定してください。", "success")
        else:
            flash("対象の店舗はすでに作成済みです。", "success")
        return redirect(url_for("stores"))

    @app.route("/stores/<int:store_id>/edit", methods=["GET", "POST"])
    @admin_required
    def edit_store(store_id):
        db = get_db()
        store = db.execute(
            "SELECT * FROM stores WHERE id = ? AND is_deleted = 0", (store_id,)
        ).fetchone()
        if store is None:
            abort(404)
        if request.method == "POST":
            name = normalize_store_name(request.form.get("name"))
            environment = request.form.get("environment", store["environment"])
            if not name:
                flash("店舗名を入力してください。", "error")
            elif len(name) > 50:
                flash("店舗名は50文字以内で入力してください。", "error")
            elif environment not in ENVIRONMENT_LABELS:
                flash("環境を正しく選択してください。", "error")
            elif db.execute(
                "SELECT 1 FROM stores WHERE name = ? AND id <> ?", (name, store_id)
            ).fetchone():
                flash("同じ店舗名がすでに登録されています。", "error")
            elif environment != store["environment"] and db.execute(
                """SELECT 1 FROM orders
                   WHERE from_store_id = ? OR to_store_id = ? LIMIT 1""",
                (store_id, store_id),
            ).fetchone():
                flash("取引履歴がある店舗の区分は変更できません。", "error")
            else:
                db.execute(
                    "UPDATE stores SET name = ?, environment = ? WHERE id = ?",
                    (name, environment, store_id),
                )
                db.commit()
                flash(f"店舗「{name}」を更新しました。", "success")
                return redirect(url_for("stores"))
        return render_template(
            "store_edit.html", store=store, environments=ENVIRONMENT_LABELS
        )

    @app.route("/stores/reset/training", methods=["GET", "POST"])
    @admin_required
    def reset_training_data():
        db = get_db()
        order_ids = [row["id"] for row in db.execute(
            """SELECT o.id FROM orders o
               JOIN stores f ON f.id = o.from_store_id
               JOIN stores t ON t.id = o.to_store_id
               WHERE f.environment = 'training' AND t.environment = 'training'"""
        ).fetchall()]
        if request.method == "POST":
            if request.form.get("confirmation", "").strip() != "リセット":
                flash("確認文字「リセット」を入力してください。", "error")
            else:
                try:
                    if order_ids:
                        placeholders = ",".join("?" for _ in order_ids)
                        db.execute(
                            f"DELETE FROM transaction_corrections WHERE order_id IN ({placeholders})",
                            order_ids,
                        )
                        db.execute(
                            f"DELETE FROM orders WHERE id IN ({placeholders})", order_ids
                        )
                    db.commit()
                except sqlite3.Error:
                    db.rollback()
                    raise
                flash(
                    f"トレーニングデータをリセットしました（{len(order_ids)}件）。",
                    "success",
                )
                return redirect(url_for("stores"))
        return render_template(
            "reset_store_data.html", order_count=len(order_ids),
        )

    @app.post("/stores/<int:store_id>/toggle")
    @admin_required
    def toggle_store(store_id):
        db = get_db()
        store = db.execute(
            "SELECT * FROM stores WHERE id = ? AND is_deleted = 0", (store_id,)
        ).fetchone()
        if store is None:
            abort(404)
        new_status = 0 if store["is_active"] else 1
        db.execute("UPDATE stores SET is_active = ? WHERE id = ?", (new_status, store_id))
        db.commit()
        action = "再開" if new_status else "停止"
        flash(f"「{store['name']}」を{action}しました。", "success")
        return redirect(url_for("stores"))

    @app.post("/stores/<int:store_id>/delete")
    @admin_required
    def delete_store(store_id):
        db = get_db()
        store = db.execute(
            "SELECT * FROM stores WHERE id = ? AND is_deleted = 0", (store_id,)
        ).fetchone()
        if store is None:
            abort(404)
        db.execute(
            "UPDATE stores SET is_active = 0, is_deleted = 1 WHERE id = ?", (store_id,)
        )
        db.commit()
        flash(f"「{store['name']}」を削除しました。過去の発注履歴は保持されます。", "success")
        return redirect(url_for("stores"))

    @app.cli.command("init-db")
    def init_db_command():
        init_db()
        print("データベースを初期化しました。")

    if not Path(app.config["DATABASE"]).exists() and not app.config.get("TESTING"):
        with app.app_context():
            init_db()
    with app.app_context():
        migrate_db()

    return app


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def load_or_create_secret_key():
    """再起動後もセッションを維持できる署名鍵を安全に永続化する。"""
    environment_key = os.environ.get("SECRET_KEY")
    if environment_key:
        return environment_key
    try:
        saved_key = SECRET_KEY_FILE.read_text(encoding="utf-8").strip()
        if len(saved_key) >= 32:
            return saved_key
    except FileNotFoundError:
        pass
    new_key = secrets.token_hex(32)
    try:
        SECRET_KEY_FILE.write_text(new_key, encoding="utf-8")
    except OSError:
        return new_key
    return new_key

def init_db():
    db = get_db()
    db.executescript((BASE_DIR / "schema.sql").read_text(encoding="utf-8"))
    db.executescript((BASE_DIR / "seed.sql").read_text(encoding="utf-8"))
    db.commit()
    migrate_db()


def migrate_db():
    """既存データを保持したまま、足りない管理列とテーブルだけを追加する。"""
    db = get_db()
    table = db.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'stores'"
    ).fetchone()
    if table is None:
        return
    columns = {row["name"] for row in db.execute("PRAGMA table_info(stores)").fetchall()}
    if "is_active" not in columns:
        db.execute("ALTER TABLE stores ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1")
    if "is_deleted" not in columns:
        db.execute("ALTER TABLE stores ADD COLUMN is_deleted INTEGER NOT NULL DEFAULT 0")
    if "environment" not in columns:
        db.execute(
            "ALTER TABLE stores ADD COLUMN environment TEXT NOT NULL DEFAULT 'production'"
        )
        if "store_type" in columns:
            db.execute(
                """UPDATE stores SET environment = CASE
                       WHEN store_type IN ('development', 'demo', 'training') THEN 'training'
                       ELSE 'production' END"""
            )

    db.execute(
        """CREATE TABLE IF NOT EXISTS users (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               login_id TEXT NOT NULL UNIQUE,
               password_hash TEXT NOT NULL,
               role TEXT NOT NULL,
               store_id INTEGER UNIQUE,
               is_active INTEGER NOT NULL DEFAULT 1,
               is_training_reviewer INTEGER NOT NULL DEFAULT 0,
               session_version INTEGER NOT NULL DEFAULT 1,
               created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
               FOREIGN KEY (store_id) REFERENCES stores (id),
               CHECK (role IN ('admin', 'store')),
               CHECK ((role = 'admin' AND store_id IS NULL)
                   OR (role = 'store' AND store_id IS NOT NULL))
           )"""
    )
    user_columns = {row["name"] for row in db.execute("PRAGMA table_info(users)")}
    if "is_training_reviewer" not in user_columns:
        db.execute(
            "ALTER TABLE users ADD COLUMN is_training_reviewer INTEGER NOT NULL DEFAULT 0"
        )
    if "session_version" not in user_columns:
        db.execute(
            "ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 1"
        )

    db.execute(
        """CREATE TABLE IF NOT EXISTS admin_recovery_tokens (
               token_hash TEXT PRIMARY KEY,
               used_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
           )"""
    )

    legacy_names = ("テスト店舗A", "テスト店舗B", "デモ店舗A", "デモ店舗B")
    legacy_rows = db.execute(
        """SELECT id FROM stores
           WHERE name IN (?, ?, ?, ?) AND environment = 'training' ORDER BY id""",
        legacy_names,
    ).fetchall()
    used_names = {row["name"] for row in db.execute("SELECT name FROM stores")}
    training_names = [f"トレーニング店舗{chr(code)}" for code in range(65, 91)]
    for row in legacy_rows:
        target_name = next(name for name in training_names if name not in used_names)
        db.execute("UPDATE stores SET name = ? WHERE id = ?", (target_name, row["id"]))
        used_names.add(target_name)

    db.execute(
        """CREATE TABLE IF NOT EXISTS product_categories (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               name TEXT NOT NULL,
               level INTEGER NOT NULL,
               parent_id INTEGER,
               is_active INTEGER NOT NULL DEFAULT 1,
               is_deleted INTEGER NOT NULL DEFAULT 0,
               FOREIGN KEY (parent_id) REFERENCES product_categories (id),
               CHECK (level IN (1, 2))
           )"""
    )
    db.execute(
        """CREATE TABLE IF NOT EXISTS units (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               name TEXT NOT NULL UNIQUE,
               is_active INTEGER NOT NULL DEFAULT 1,
               is_deleted INTEGER NOT NULL DEFAULT 0
           )"""
    )
    category_columns = {row["name"] for row in db.execute("PRAGMA table_info(product_categories)")}
    if "environment" not in category_columns:
        db.execute("ALTER TABLE product_categories ADD COLUMN environment TEXT NOT NULL DEFAULT 'production'")

    unit_columns = {row["name"] for row in db.execute("PRAGMA table_info(units)")}
    if "environment" not in unit_columns:
        # The legacy table has UNIQUE(name), which prevents equal names in the
        # production and training scopes. Rebuild it once without changing IDs.
        db.commit()
        db.execute("PRAGMA foreign_keys = OFF")
        db.execute(
            """CREATE TABLE units_v2 (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   name TEXT NOT NULL,
                   environment TEXT NOT NULL DEFAULT 'production',
                   decimal_places INTEGER NOT NULL DEFAULT 0,
                   is_active INTEGER NOT NULL DEFAULT 1,
                   is_deleted INTEGER NOT NULL DEFAULT 0,
                   UNIQUE (name, environment)
               )"""
        )
        db.execute(
            """INSERT INTO units_v2 (id, name, environment, decimal_places, is_active, is_deleted)
               SELECT id, name, 'production', CASE WHEN name = 'kg' THEN 2 ELSE 0 END,
                      is_active, is_deleted FROM units"""
        )
        db.execute("DROP TABLE units")
        db.execute("ALTER TABLE units_v2 RENAME TO units")
        db.commit()
        db.execute("PRAGMA foreign_keys = ON")
    else:
        if "decimal_places" not in unit_columns:
            db.execute("ALTER TABLE units ADD COLUMN decimal_places INTEGER NOT NULL DEFAULT 0")
        db.execute("UPDATE units SET decimal_places = 2 WHERE name = 'kg' AND decimal_places = 0")
    major = db.execute(
        """SELECT id FROM product_categories
           WHERE name = '未分類' AND level = 1 AND parent_id IS NULL LIMIT 1"""
    ).fetchone()
    if major is None:
        major_id = db.execute(
            "INSERT INTO product_categories (name, level) VALUES ('未分類', 1)"
        ).lastrowid
    else:
        major_id = major["id"]
    sub = db.execute(
        """SELECT id FROM product_categories
           WHERE name = '未分類' AND level = 2 AND parent_id = ? LIMIT 1""",
        (major_id,),
    ).fetchone()
    if sub is None:
        sub_id = db.execute(
            """INSERT INTO product_categories (name, level, parent_id)
               VALUES ('未分類', 2, ?)""", (major_id,)
        ).lastrowid
    else:
        sub_id = sub["id"]

    product_columns = {
        row["name"] for row in db.execute("PRAGMA table_info(products)").fetchall()
    }
    if "major_category_id" not in product_columns:
        db.execute("ALTER TABLE products ADD COLUMN major_category_id INTEGER")
    if "subcategory_id" not in product_columns:
        db.execute("ALTER TABLE products ADD COLUMN subcategory_id INTEGER")
    if "unit_id" not in product_columns:
        db.execute("ALTER TABLE products ADD COLUMN unit_id INTEGER")
    if "image_filename" not in product_columns:
        db.execute("ALTER TABLE products ADD COLUMN image_filename TEXT")
    if "is_deleted" not in product_columns:
        db.execute("ALTER TABLE products ADD COLUMN is_deleted INTEGER NOT NULL DEFAULT 0")
    if "environment" not in product_columns:
        db.execute("ALTER TABLE products ADD COLUMN environment TEXT NOT NULL DEFAULT 'production'")
    if "source_product_id" not in product_columns:
        db.execute("ALTER TABLE products ADD COLUMN source_product_id INTEGER")
    db.execute(
        "UPDATE products SET major_category_id = ? WHERE major_category_id IS NULL",
        (major_id,),
    )
    db.execute(
        "UPDATE products SET subcategory_id = ? WHERE subcategory_id IS NULL",
        (sub_id,),
    )
    for row in db.execute("SELECT DISTINCT unit FROM products WHERE unit IS NOT NULL"):
        if db.execute("SELECT 1 FROM units WHERE name = ?", (row["unit"],)).fetchone() is None:
            db.execute("INSERT INTO units (name) VALUES (?)", (row["unit"],))
    db.execute(
        """UPDATE products SET unit_id = (
               SELECT id FROM units WHERE units.name = products.unit
           ) WHERE unit_id IS NULL"""
    )

    db.execute(
        "CREATE TABLE IF NOT EXISTS app_migrations (name TEXT PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')))"
    )
    if db.execute(
        "SELECT 1 FROM app_migrations WHERE name = 'training_master_split_v1'"
    ).fetchone() is None:
        category_map = {}
        for row in db.execute(
            "SELECT * FROM product_categories WHERE environment = 'production' ORDER BY level, id"
        ).fetchall():
            parent_id = category_map.get(row["parent_id"]) if row["parent_id"] else None
            new_id = db.execute(
                """INSERT INTO product_categories
                   (name, level, parent_id, environment, is_active, is_deleted)
                   VALUES (?, ?, ?, 'training', ?, ?)""",
                (row["name"], row["level"], parent_id, row["is_active"], row["is_deleted"]),
            ).lastrowid
            category_map[row["id"]] = new_id
        unit_map = {}
        for row in db.execute("SELECT * FROM units WHERE environment = 'production' ORDER BY id").fetchall():
            new_id = db.execute(
                """INSERT INTO units
                   (name, environment, decimal_places, is_active, is_deleted)
                   VALUES (?, 'training', ?, ?, ?)""",
                (row["name"], row["decimal_places"], row["is_active"], row["is_deleted"]),
            ).lastrowid
            unit_map[row["id"]] = new_id
        for row in db.execute("SELECT * FROM products WHERE environment = 'production' ORDER BY id").fetchall():
            db.execute(
                """INSERT INTO products
                   (name, major_category_id, subcategory_id, unit_id, unit, unit_price,
                    image_filename, environment, source_product_id, display_order,
                    is_active, is_deleted)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 'training', ?, ?, ?, ?)""",
                (row["name"], category_map[row["major_category_id"]],
                 category_map[row["subcategory_id"]], unit_map[row["unit_id"]],
                 row["unit"], row["unit_price"], row["image_filename"], row["id"],
                 row["display_order"], row["is_active"], row["is_deleted"]),
            )
        db.execute("INSERT INTO app_migrations (name) VALUES ('training_master_split_v1')")

    order_columns = {
        row["name"] for row in db.execute("PRAGMA table_info(orders)").fetchall()
    }
    if "status" not in order_columns:
        db.execute("ALTER TABLE orders ADD COLUMN status TEXT NOT NULL DEFAULT 'ordered'")
    if "received_at" not in order_columns:
        db.execute("ALTER TABLE orders ADD COLUMN received_at TEXT")
    if "receipt_reported_at" not in order_columns:
        db.execute("ALTER TABLE orders ADD COLUMN receipt_reported_at TEXT")
    if "sender_approved_at" not in order_columns:
        db.execute("ALTER TABLE orders ADD COLUMN sender_approved_at TEXT")
    db.execute(
        """UPDATE orders SET receipt_reported_at = received_at
           WHERE receipt_reported_at IS NULL AND received_at IS NOT NULL"""
    )

    item_columns = {
        row["name"] for row in db.execute("PRAGMA table_info(order_items)").fetchall()
    }
    if "received_quantity" not in item_columns:
        db.execute("ALTER TABLE order_items ADD COLUMN received_quantity REAL")
    if "final_received_quantity" not in item_columns:
        db.execute("ALTER TABLE order_items ADD COLUMN final_received_quantity REAL")
    if "major_category_name" not in item_columns:
        db.execute("ALTER TABLE order_items ADD COLUMN major_category_name TEXT")
    if "subcategory_name" not in item_columns:
        db.execute("ALTER TABLE order_items ADD COLUMN subcategory_name TEXT")
    if "quantity_minor" not in item_columns:
        db.execute("ALTER TABLE order_items ADD COLUMN quantity_minor INTEGER")
    if "quantity_decimal_places" not in item_columns:
        db.execute("ALTER TABLE order_items ADD COLUMN quantity_decimal_places INTEGER NOT NULL DEFAULT 0")
    if "received_quantity_minor" not in item_columns:
        db.execute("ALTER TABLE order_items ADD COLUMN received_quantity_minor INTEGER")
    if "final_received_quantity_minor" not in item_columns:
        db.execute("ALTER TABLE order_items ADD COLUMN final_received_quantity_minor INTEGER")
    db.execute("UPDATE order_items SET quantity_minor = CAST(ROUND(quantity * 100) AS INTEGER) WHERE quantity_minor IS NULL")
    db.execute("UPDATE order_items SET quantity_decimal_places = 2 WHERE unit = 'kg' AND quantity_decimal_places = 0")
    db.execute("UPDATE order_items SET received_quantity_minor = CAST(ROUND(received_quantity * 100) AS INTEGER) WHERE received_quantity IS NOT NULL AND received_quantity_minor IS NULL")
    db.execute("UPDATE order_items SET final_received_quantity_minor = CAST(ROUND(final_received_quantity * 100) AS INTEGER) WHERE final_received_quantity IS NOT NULL AND final_received_quantity_minor IS NULL")
    db.execute(
        """UPDATE order_items SET
               major_category_name = COALESCE(major_category_name, (
                   SELECT major.name FROM products p
                   JOIN product_categories major ON major.id = p.major_category_id
                   WHERE p.id = order_items.product_id
               ), '未分類'),
               subcategory_name = COALESCE(subcategory_name, (
                   SELECT sub.name FROM products p
                   JOIN product_categories sub ON sub.id = p.subcategory_id
                   WHERE p.id = order_items.product_id
               ), '未分類')
           WHERE major_category_name IS NULL OR subcategory_name IS NULL"""
    )
    db.execute(
        """UPDATE order_items SET final_received_quantity = received_quantity
           WHERE final_received_quantity IS NULL AND received_quantity IS NOT NULL
             AND order_id IN (SELECT id FROM orders WHERE status = 'received')"""
    )
    db.execute(
        """CREATE TABLE IF NOT EXISTS unexpected_items (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               order_id INTEGER NOT NULL,
               product_id INTEGER NOT NULL,
               product_name TEXT NOT NULL,
               unit TEXT NOT NULL,
               arrived_quantity REAL NOT NULL,
               decision TEXT NOT NULL,
               status TEXT NOT NULL,
               final_received_quantity REAL,
               unit_price INTEGER,
               created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
               updated_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
               FOREIGN KEY (order_id) REFERENCES orders (id) ON DELETE CASCADE,
               FOREIGN KEY (product_id) REFERENCES products (id),
               CHECK (arrived_quantity > 0),
               CHECK (decision IN ('return', 'accept')),
               CHECK (status IN ('return_pending', 'returned', 'return_complete',
                                 'accept_pending', 'accepted'))
           )"""
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_unexpected_items_order ON unexpected_items (order_id)"
    )
    unexpected_columns = {
        row["name"] for row in db.execute("PRAGMA table_info(unexpected_items)").fetchall()
    }
    if "unit_price" not in unexpected_columns:
        db.execute("ALTER TABLE unexpected_items ADD COLUMN unit_price INTEGER")
    if "major_category_name" not in unexpected_columns:
        db.execute("ALTER TABLE unexpected_items ADD COLUMN major_category_name TEXT")
    if "subcategory_name" not in unexpected_columns:
        db.execute("ALTER TABLE unexpected_items ADD COLUMN subcategory_name TEXT")
    if "arrived_quantity_minor" not in unexpected_columns:
        db.execute("ALTER TABLE unexpected_items ADD COLUMN arrived_quantity_minor INTEGER")
    if "quantity_decimal_places" not in unexpected_columns:
        db.execute("ALTER TABLE unexpected_items ADD COLUMN quantity_decimal_places INTEGER NOT NULL DEFAULT 0")
    if "final_received_quantity_minor" not in unexpected_columns:
        db.execute("ALTER TABLE unexpected_items ADD COLUMN final_received_quantity_minor INTEGER")
    db.execute("UPDATE unexpected_items SET arrived_quantity_minor = CAST(ROUND(arrived_quantity * 100) AS INTEGER) WHERE arrived_quantity_minor IS NULL")
    db.execute("UPDATE unexpected_items SET quantity_decimal_places = 2 WHERE unit = 'kg' AND quantity_decimal_places = 0")
    db.execute("UPDATE unexpected_items SET final_received_quantity_minor = CAST(ROUND(final_received_quantity * 100) AS INTEGER) WHERE final_received_quantity IS NOT NULL AND final_received_quantity_minor IS NULL")
    db.execute(
        """UPDATE unexpected_items SET
               major_category_name = COALESCE(major_category_name, (
                   SELECT major.name FROM products p
                   JOIN product_categories major ON major.id = p.major_category_id
                   WHERE p.id = unexpected_items.product_id
               ), '未分類'),
               subcategory_name = COALESCE(subcategory_name, (
                   SELECT sub.name FROM products p
                   JOIN product_categories sub ON sub.id = p.subcategory_id
                   WHERE p.id = unexpected_items.product_id
               ), '未分類')
           WHERE major_category_name IS NULL OR subcategory_name IS NULL"""
    )
    db.execute(
        """CREATE TABLE IF NOT EXISTS transaction_corrections (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               order_id INTEGER NOT NULL,
               line_type TEXT NOT NULL,
               line_id INTEGER NOT NULL,
               corrected_product_id INTEGER NOT NULL,
               corrected_product_name TEXT NOT NULL,
               corrected_major_category_name TEXT NOT NULL,
               corrected_subcategory_name TEXT NOT NULL,
               corrected_unit TEXT NOT NULL,
               corrected_quantity REAL NOT NULL,
               corrected_unit_price INTEGER,
               reason TEXT NOT NULL,
               before_json TEXT NOT NULL,
               after_json TEXT NOT NULL,
               admin_user_id INTEGER NOT NULL,
               created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
               FOREIGN KEY (order_id) REFERENCES orders (id),
               FOREIGN KEY (corrected_product_id) REFERENCES products (id),
               FOREIGN KEY (admin_user_id) REFERENCES users (id),
               CHECK (line_type IN ('order_item', 'unexpected_item')),
               CHECK (corrected_quantity >= 0),
               CHECK (corrected_unit_price IS NULL OR corrected_unit_price >= 0)
           )"""
    )
    db.execute(
        """CREATE INDEX IF NOT EXISTS idx_corrections_line
           ON transaction_corrections (line_type, line_id, id DESC)"""
    )
    db.execute(
        """CREATE INDEX IF NOT EXISTS idx_corrections_order
           ON transaction_corrections (order_id, id DESC)"""
    )
    correction_columns = {row["name"] for row in db.execute("PRAGMA table_info(transaction_corrections)")}
    if "corrected_quantity_minor" not in correction_columns:
        db.execute("ALTER TABLE transaction_corrections ADD COLUMN corrected_quantity_minor INTEGER")
    db.execute("UPDATE transaction_corrections SET corrected_quantity_minor = CAST(ROUND(corrected_quantity * 100) AS INTEGER) WHERE corrected_quantity_minor IS NULL")
    db.execute(
        """CREATE TABLE IF NOT EXISTS audit_events (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               occurred_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
               user_id INTEGER NOT NULL, user_login_id TEXT NOT NULL,
               store_id INTEGER, store_name TEXT, order_id INTEGER, order_number TEXT,
               event_type TEXT NOT NULL, product_name TEXT, quantity_minor INTEGER,
               before_json TEXT, after_json TEXT, approval_status TEXT,
               environment TEXT NOT NULL, snapshot_path TEXT,
               FOREIGN KEY (user_id) REFERENCES users (id),
               FOREIGN KEY (store_id) REFERENCES stores (id),
               FOREIGN KEY (order_id) REFERENCES orders (id)
           )"""
    )
    db.execute("CREATE INDEX IF NOT EXISTS idx_audit_events_search ON audit_events (store_id, occurred_at, event_type, order_id)")
    db.executescript(
        """CREATE TRIGGER IF NOT EXISTS fill_order_item_quantity_minor
           AFTER INSERT ON order_items WHEN NEW.quantity_minor IS NULL BEGIN
             UPDATE order_items SET quantity_minor = CAST(ROUND(NEW.quantity * 100) AS INTEGER),
               received_quantity_minor = CASE WHEN NEW.received_quantity IS NULL THEN NULL ELSE CAST(ROUND(NEW.received_quantity * 100) AS INTEGER) END,
               final_received_quantity_minor = CASE WHEN NEW.final_received_quantity IS NULL THEN NULL ELSE CAST(ROUND(NEW.final_received_quantity * 100) AS INTEGER) END
             WHERE id = NEW.id;
           END;
           CREATE TRIGGER IF NOT EXISTS fill_unexpected_quantity_minor
           AFTER INSERT ON unexpected_items WHEN NEW.arrived_quantity_minor IS NULL BEGIN
             UPDATE unexpected_items SET arrived_quantity_minor = CAST(ROUND(NEW.arrived_quantity * 100) AS INTEGER),
               final_received_quantity_minor = CASE WHEN NEW.final_received_quantity IS NULL THEN NULL ELSE CAST(ROUND(NEW.final_received_quantity * 100) AS INTEGER) END
             WHERE id = NEW.id;
           END;
           CREATE TRIGGER IF NOT EXISTS fill_correction_quantity_minor
           AFTER INSERT ON transaction_corrections WHEN NEW.corrected_quantity_minor IS NULL BEGIN
             UPDATE transaction_corrections SET corrected_quantity_minor = CAST(ROUND(NEW.corrected_quantity * 100) AS INTEGER)
             WHERE id = NEW.id;
           END;"""
    )
    db.commit()


def valid_store_pair(from_id, to_id, required_environment=None):
    if not from_id or not to_id or from_id == to_id:
        return False
    rows = get_db().execute(
        """SELECT environment FROM stores
           WHERE id IN (?, ?) AND is_active = 1 AND is_deleted = 0""",
        (from_id, to_id)
    ).fetchall()
    return (
        len(rows) == 2
        and rows[0]["environment"] == rows[1]["environment"]
        and (required_environment is None or rows[0]["environment"] == required_environment)
    )


def current_order_context():
    context = session.get("order_context")
    return context if isinstance(context, dict) else None


def load_context_stores(context):
    db = get_db()
    return {
        "from_store": db.execute(
            "SELECT * FROM stores WHERE id = ?", (context["from_store_id"],)
        ).fetchone(),
        "to_store": db.execute(
            "SELECT * FROM stores WHERE id = ?", (context["to_store_id"],)
        ).fetchone(),
    }


def build_cart_items(cart):
    if not cart:
        return []
    db = get_db()
    items = []
    for saved in cart:
        product = db.execute(
            """SELECT p.*, major.name AS major_name, sub.name AS subcategory_name,
                      u.decimal_places
               FROM products p
               JOIN product_categories major ON major.id = p.major_category_id
               JOIN product_categories sub ON sub.id = p.subcategory_id
               JOIN units u ON u.id = p.unit_id
               WHERE p.id = ? AND p.is_active = 1 AND p.is_deleted = 0
                 AND major.is_active = 1 AND major.is_deleted = 0
                 AND sub.is_active = 1 AND sub.is_deleted = 0
                 AND u.is_active = 1 AND u.is_deleted = 0 AND p.environment = ?""",
            (saved.get("product_id"), master_environment() if current_order_context() is None
             else load_context_stores(current_order_context())["from_store"]["environment"]),
        ).fetchone()
        if product is None:
            continue
        try:
            amount, quantity_minor = parse_quantity(saved["quantity"], product["decimal_places"])
        except (InvalidOperation, KeyError):
            continue
        subtotal = None
        if product["unit_price"] is not None:
            subtotal = float(amount) * product["unit_price"]
        items.append({
            "product_id": product["id"], "name": product["name"],
            "unit": product["unit"], "unit_price": product["unit_price"],
            "quantity": float(amount), "subtotal": subtotal,
            "quantity_minor": quantity_minor, "decimal_places": product["decimal_places"],
            "major_name": product["major_name"],
            "subcategory_name": product["subcategory_name"],
        })
    return items


def fetch_order(order_id):
    return get_db().execute(
        """SELECT o.*, f.name AS from_store_name, t.name AS to_store_name,
                  f.environment AS from_environment, t.environment AS to_environment
           FROM orders o JOIN stores f ON f.id = o.from_store_id
           JOIN stores t ON t.id = o.to_store_id WHERE o.id = ?""",
        (order_id,),
    ).fetchone()


def normalize_store_name(value):
    return " ".join((value or "").split())


def parse_quantity(value, decimal_places, *, allow_zero=False):
    """Validate a quantity and return (Decimal, fixed hundredths integer)."""
    try:
        amount = Decimal((value or "").strip())
        places = int(decimal_places)
        quantum = Decimal(1).scaleb(-places)
        if (
            places not in {0, 1, 2} or not amount.is_finite()
            or amount > Decimal("99999") or amount < 0
            or (amount == 0 and not allow_zero)
            or amount != amount.quantize(quantum)
        ):
            raise InvalidOperation
    except (InvalidOperation, ValueError, TypeError):
        raise InvalidOperation from None
    return amount, int(amount * 100)


def minor_to_decimal(value):
    return Decimal(int(value)) / Decimal(100)


def normalize_master_name(value):
    return " ".join((value or "").split())


def normalize_login_id(value):
    return (value or "").strip().lower()


def validate_login_id(login_id):
    if not re.fullmatch(r"[a-z0-9_.-]{3,50}", login_id or ""):
        return "ログインIDは半角英数字と . _ - を使い、3～50文字で入力してください。"
    return None


def validate_credentials(login_id, password):
    return validate_login_id(login_id) or (
        "パスワードは8文字以上で入力してください。" if len(password or "") < 8 else None
    )


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login"))
        if not is_admin():
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def business_admin_required(view):
    """Allow system admin everywhere and reviewer only inside training."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login"))
        if not is_environment_operator():
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def is_admin():
    return (
        g.user is not None and g.user["role"] == "admin"
        and not g.user["is_training_reviewer"]
    )


def is_training_reviewer():
    return bool(
        g.user is not None and g.user["role"] == "admin"
        and g.user["is_training_reviewer"]
    )


def is_environment_operator():
    return is_admin() or is_training_reviewer()


def audit_operation(event_type, order, *, store_id=None, product_name=None,
                    quantity_minor=None, before=None, after=None,
                    approval_status=None):
    if not feature_enabled(current_app.config.get("AUDIT_SNAPSHOT_ENABLED", False)):
        return False
    db = get_db()
    if store_id is None:
        store_id = g.user["store_id"] if g.user and g.user["store_id"] else order["from_store_id"]
    store = db.execute("SELECT * FROM stores WHERE id = ?", (store_id,)).fetchone()
    environment = "training" if order_is_training(order) else "production"
    return record_audit(
        db, current_app.config, user=g.user, event_type=event_type,
        environment=environment, store=store, order=order,
        product_name=product_name, quantity_minor=quantity_minor,
        before=before, after=after, approval_status=approval_status,
    )


def master_environment():
    """Master-data scope; reviewers can never select production."""
    if is_training_reviewer():
        return "training"
    if g.user and g.user["role"] == "store":
        return g.user["store_environment"]
    return session.get("view_environment", "production")


def order_is_training(order):
    return order["from_environment"] == "training" and order["to_environment"] == "training"


def set_request_environment(environment):
    """表示中の実データを基準に、このリクエストの画面テーマを確定する。"""
    g.training_mode = environment == "training"


def set_request_environment_for_order(order):
    set_request_environment("training" if order_is_training(order) else "production")


def can_access_order(order):
    return is_admin() or (is_training_reviewer() and order_is_training(order)) or (
        g.user and g.user["store_id"] in {order["from_store_id"], order["to_store_id"]}
    )


def require_order_role(order, store_column):
    if is_admin():
        return
    if is_training_reviewer() and order_is_training(order):
        return
    if g.user is None or g.user["store_id"] != order[store_column]:
        abort(403)


def validate_category(db, name, level, parent_id, exclude_id=None, environment=None):
    environment = environment or master_environment()
    if not name or len(name) > 50:
        return "分類名は1～50文字で入力してください。"
    if level not in {1, 2}:
        return "分類の種類が正しくありません。"
    if level == 2:
        parent = db.execute(
            """SELECT 1 FROM product_categories
               WHERE id = ? AND level = 1 AND is_active = 1 AND is_deleted = 0
                 AND environment = ?""",
            (parent_id, environment),
        ).fetchone()
        if parent is None:
            return "有効な大分類を選択してください。"
    duplicate = db.execute(
        """SELECT 1 FROM product_categories
           WHERE name = ? AND level = ? AND parent_id IS ? AND is_deleted = 0
             AND environment = ?
             AND (? IS NULL OR id <> ?)""",
        (name, level, parent_id, environment, exclude_id, exclude_id),
    ).fetchone()
    if duplicate:
        return "同じ分類がすでに登録されています。"
    return None


def render_product_form(product=None):
    db = get_db()
    environment = master_environment()
    set_request_environment(environment)
    majors = db.execute(
        """SELECT * FROM product_categories
           WHERE level = 1 AND is_active = 1 AND is_deleted = 0
             AND environment = ? ORDER BY name, id""", (environment,)
    ).fetchall()
    subcategories = db.execute(
        """SELECT c.* FROM product_categories c
           JOIN product_categories p ON p.id = c.parent_id
           WHERE c.level = 2 AND c.is_active = 1 AND c.is_deleted = 0
             AND p.is_active = 1 AND p.is_deleted = 0
             AND c.environment = ? AND p.environment = ? ORDER BY c.name, c.id""",
        (environment, environment),
    ).fetchall()
    units = db.execute(
        "SELECT * FROM units WHERE is_active = 1 AND is_deleted = 0 AND environment = ? ORDER BY name, id",
        (environment,),
    ).fetchall()
    return render_template(
        "product_form.html", product=product, majors=majors,
        subcategories=subcategories, units=units,
    )


def save_product_form(product=None):
    db = get_db()
    environment = master_environment()
    name = normalize_master_name(request.form.get("name"))
    major_id = request.form.get("major_category_id", type=int)
    subcategory_id = request.form.get("subcategory_id", type=int)
    unit_id = request.form.get("unit_id", type=int)
    raw_price = request.form.get("unit_price", "").replace(",", "").strip()

    error = None
    if not name or len(name) > 100:
        error = "商品名は1～100文字で入力してください。"
    category = db.execute(
        """SELECT sub.id, sub.parent_id FROM product_categories sub
           JOIN product_categories major ON major.id = sub.parent_id
           WHERE sub.id = ? AND sub.level = 2 AND sub.is_active = 1 AND sub.is_deleted = 0
             AND major.id = ? AND major.level = 1
             AND major.is_active = 1 AND major.is_deleted = 0
             AND sub.environment = ? AND major.environment = ?""",
        (subcategory_id, major_id, environment, environment),
    ).fetchone()
    unit = db.execute(
        "SELECT * FROM units WHERE id = ? AND is_active = 1 AND is_deleted = 0 AND environment = ?",
        (unit_id, environment),
    ).fetchone()
    if category is None:
        error = error or "大分類に対応する有効な中分類を選択してください。"
    if unit is None:
        error = error or "有効な単位を選択してください。"
    unit_price = None
    if raw_price:
        try:
            unit_price = int(raw_price)
            if unit_price < 0 or unit_price > 100_000_000:
                raise ValueError
        except ValueError:
            error = error or "単価は0～100,000,000円の整数で入力してください。"

    image_filename = product["image_filename"] if product else None
    image = request.files.get("image")
    if not error and image and image.filename:
        try:
            image_filename = save_product_image(image)
        except ValueError as exc:
            error = error or str(exc)

    if error:
        flash(error, "error")
        endpoint = "edit_product" if product else "new_product"
        values = {"product_id": product["id"]} if product else {}
        return redirect(url_for(endpoint, **values))

    if product:
        db.execute(
            """UPDATE products SET name = ?, major_category_id = ?, subcategory_id = ?,
                      unit_id = ?, unit = ?, unit_price = ?, image_filename = ?
               WHERE id = ?""",
            (name, major_id, subcategory_id, unit_id, unit["name"], unit_price,
             image_filename, product["id"]),
        )
        message = f"「{name}」を更新しました。"
    else:
        display_order = db.execute(
            "SELECT COALESCE(MAX(display_order), 0) + 10 FROM products WHERE environment = ?",
            (environment,),
        ).fetchone()[0]
        db.execute(
            """INSERT INTO products
               (name, major_category_id, subcategory_id, unit_id, unit, unit_price,
                image_filename, display_order, environment)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (name, major_id, subcategory_id, unit_id, unit["name"], unit_price,
             image_filename, display_order, environment),
        )
        message = f"「{name}」を登録しました。"
    db.commit()
    flash(message, "success")
    return redirect(url_for("product_management"))


def save_product_image(image):
    original = secure_filename(image.filename or "")
    extension = Path(image.filename or original).suffix.lower()
    if extension not in {".jpg", ".jpeg", ".png", ".gif", ".webp"}:
        raise ValueError("画像はPNG・JPEG・GIF・WebP形式を選択してください。")
    header = image.stream.read(16)
    image.stream.seek(0)
    signatures = {
        ".png": header.startswith(b"\x89PNG\r\n\x1a\n"),
        ".jpg": header.startswith(b"\xff\xd8"),
        ".jpeg": header.startswith(b"\xff\xd8"),
        ".gif": header.startswith((b"GIF87a", b"GIF89a")),
        ".webp": header.startswith(b"RIFF") and header[8:12] == b"WEBP",
    }
    if not signatures[extension]:
        raise ValueError("画像ファイルの内容を確認できませんでした。")
    upload_dir = Path(current_app.config["UPLOAD_FOLDER"])
    upload_dir.mkdir(parents=True, exist_ok=True)
    filename = f"{uuid.uuid4().hex}{extension}"
    image.save(upload_dir / filename)
    return filename


def orderable_products(environment=None):
    environment = environment or (
        load_context_stores(current_order_context())["from_store"]["environment"]
        if current_order_context() else master_environment()
    )
    return get_db().execute(
        """SELECT p.*, major.name AS major_name, sub.name AS subcategory_name,
                  u.name AS unit_name, u.decimal_places
           FROM products p
           JOIN product_categories major ON major.id = p.major_category_id
           JOIN product_categories sub ON sub.id = p.subcategory_id
           JOIN units u ON u.id = p.unit_id
           WHERE p.is_active = 1 AND p.is_deleted = 0
             AND major.is_active = 1 AND major.is_deleted = 0
             AND sub.is_active = 1 AND sub.is_deleted = 0
             AND u.is_active = 1 AND u.is_deleted = 0
             AND p.environment = ? AND major.environment = ?
             AND sub.environment = ? AND u.environment = ?
           ORDER BY major.name, sub.name, p.display_order, p.name, p.id""",
        (environment, environment, environment, environment),
    ).fetchall()


def parse_month(value):
    text = value or date.today().strftime("%Y-%m")
    try:
        first = datetime.strptime(text, "%Y-%m").date().replace(day=1)
    except ValueError:
        abort(400)
    if first.month == 12:
        following = first.replace(year=first.year + 1, month=1)
    else:
        following = first.replace(month=first.month + 1)
    return text, first, following


def parse_report_date(value, default=None):
    if not value:
        return default or date.today()
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        abort(400)


def report_scope_store_id(requested_store_id):
    if not is_environment_operator():
        return g.user["store_id"]
    if not requested_store_id:
        return None
    exists = get_db().execute(
        "SELECT environment FROM stores WHERE id = ? AND is_deleted = 0", (requested_store_id,)
    ).fetchone()
    if exists is None:
        abort(404)
    if is_training_reviewer() and exists["environment"] != "training":
        abort(403)
    return requested_store_id


def report_scope_environment(requested_environment, store_id=None):
    db = get_db()
    if not is_environment_operator():
        row = db.execute(
            "SELECT environment FROM stores WHERE id = ?", (g.user["store_id"],)
        ).fetchone()
        return row["environment"]
    if is_training_reviewer():
        return "training"
    if requested_environment in ENVIRONMENT_LABELS:
        return requested_environment
    if store_id:
        row = db.execute(
            "SELECT environment FROM stores WHERE id = ?", (store_id,)
        ).fetchone()
        if row is None:
            abort(404)
        return row["environment"]
    return session.get("view_environment", "production")


def normalize_report_store_id(store_id, environment):
    """明示された環境と店舗が不一致なら、管理者の対象を全店舗へ戻す。"""
    if store_id is None:
        return None
    row = get_db().execute(
        "SELECT environment FROM stores WHERE id = ? AND is_deleted = 0", (store_id,)
    ).fetchone()
    if row is None:
        abort(404)
    if row["environment"] == environment:
        return store_id
    if is_admin():
        return None
    abort(403)


def store_ids_for_environment(environment):
    rows = get_db().execute(
        "SELECT id FROM stores WHERE environment = ?", (environment,)
    ).fetchall()
    return [row["id"] for row in rows] or [-1]


def require_report_store(store_id):
    if is_admin():
        return
    if is_training_reviewer():
        row = get_db().execute(
            "SELECT environment FROM stores WHERE id = ?", (store_id,)
        ).fetchone()
        if row and row["environment"] == "training":
            return
        abort(403)
    if g.user["store_id"] != store_id:
        abort(403)


def transaction_lines(start_date=None, end_date=None, related_store_id=None, environment=None):
    db = get_db()
    conditions = []
    params = []
    if start_date:
        conditions.append("date(o.created_at) >= ?")
        params.append(start_date.isoformat())
    if end_date:
        conditions.append("date(o.created_at) < ?")
        params.append(end_date.isoformat())
    if related_store_id:
        conditions.append("(o.from_store_id = ? OR o.to_store_id = ?)")
        params.extend([related_store_id, related_store_id])
    if environment:
        conditions.append("f.environment = ? AND t.environment = ?")
        params.extend([environment, environment])
    where = " AND ".join(conditions) if conditions else "1 = 1"
    ordered_rows = db.execute(
        f"""SELECT oi.*, o.order_number, o.from_store_id, o.to_store_id,
                   o.created_at AS order_created_at, o.status AS order_status,
                   f.name AS from_store_name, t.name AS to_store_name,
                   f.environment AS environment
            FROM order_items oi
            JOIN orders o ON o.id = oi.order_id
            JOIN stores f ON f.id = o.from_store_id
            JOIN stores t ON t.id = o.to_store_id
            WHERE {where} ORDER BY o.created_at, o.id, oi.id""", params
    ).fetchall()
    unexpected_rows = db.execute(
        f"""SELECT ux.*, o.order_number, o.from_store_id, o.to_store_id,
                   o.created_at AS order_created_at, o.status AS order_status,
                   f.name AS from_store_name, t.name AS to_store_name,
                   f.environment AS environment
            FROM unexpected_items ux
            JOIN orders o ON o.id = ux.order_id
            JOIN stores f ON f.id = o.from_store_id
            JOIN stores t ON t.id = o.to_store_id
            WHERE {where} ORDER BY o.created_at, o.id, ux.id""", params
    ).fetchall()
    corrections = {}
    for correction in db.execute(
        "SELECT * FROM transaction_corrections ORDER BY id"
    ).fetchall():
        corrections[(correction["line_type"], correction["line_id"])] = correction

    lines = []
    for row in ordered_rows:
        correction = corrections.get(("order_item", row["id"]))
        final_quantity = None if row["final_received_quantity_minor"] is None else minor_to_decimal(row["final_received_quantity_minor"])
        product_name = row["product_name"]
        major_name = row["major_category_name"] or "未分類"
        sub_name = row["subcategory_name"] or "未分類"
        unit = row["unit"]
        final_price = row["unit_price"]
        if correction:
            product_name = correction["corrected_product_name"]
            major_name = correction["corrected_major_category_name"]
            sub_name = correction["corrected_subcategory_name"]
            unit = correction["corrected_unit"]
            final_quantity = minor_to_decimal(correction["corrected_quantity_minor"])
            final_price = correction["corrected_unit_price"]
        status_label = order_status_label(row, final_quantity)
        lines.append(make_report_line(
            row, "order_item", row["id"], product_name, major_name, sub_name, unit,
            minor_to_decimal(row["quantity_minor"]), final_quantity, row["unit_price"], final_price,
            status_label, bool(correction),
        ))

    unexpected_labels = {
        "return_pending": "返品予定", "returned": "返品済み",
        "return_complete": "返品完了", "accept_pending": "注文外商品承認待ち",
        "accepted": "注文外商品承認済",
    }
    for row in unexpected_rows:
        correction = corrections.get(("unexpected_item", row["id"]))
        final_quantity = None if row["final_received_quantity_minor"] is None else minor_to_decimal(row["final_received_quantity_minor"])
        product_name = row["product_name"]
        major_name = row["major_category_name"] or "未分類"
        sub_name = row["subcategory_name"] or "未分類"
        unit = row["unit"]
        final_price = row["unit_price"]
        if correction:
            product_name = correction["corrected_product_name"]
            major_name = correction["corrected_major_category_name"]
            sub_name = correction["corrected_subcategory_name"]
            unit = correction["corrected_unit"]
            final_quantity = minor_to_decimal(correction["corrected_quantity_minor"])
            final_price = correction["corrected_unit_price"]
        lines.append(make_report_line(
            row, "unexpected_item", row["id"], product_name, major_name, sub_name, unit,
            0, final_quantity, row["unit_price"], final_price,
            unexpected_labels.get(row["status"], row["status"]), bool(correction),
            original_product_name="注文外：" + row["product_name"],
        ))
    lines.sort(key=lambda item: (item["created_at"], item["order_id"], item["line_type"], item["line_id"]))
    return lines


def make_report_line(row, line_type, line_id, product_name, major_name, sub_name, unit,
                     ordered_quantity, final_quantity, ordered_price, final_price,
                     status_label, corrected, original_product_name=None):
    created_at = row["order_created_at"]
    ordered_quantity = Decimal(str(ordered_quantity or 0))
    final_quantity = None if final_quantity is None else Decimal(str(final_quantity))
    ordered_amount = 0 if ordered_price is None else int((ordered_quantity * ordered_price).quantize(Decimal("1")))
    final_amount = None if final_quantity is None else (
        0 if final_price is None else int((final_quantity * final_price).quantize(Decimal("1")))
    )
    return {
        "line_type": line_type, "line_id": line_id,
        "order_id": row["order_id"], "order_number": row["order_number"],
        "created_at": created_at, "date": created_at[:10], "time": created_at[11:16],
        "from_store_id": row["from_store_id"], "to_store_id": row["to_store_id"],
        "from_store_name": row["from_store_name"], "to_store_name": row["to_store_name"],
        "environment": row["environment"],
        "original_product_name": original_product_name or row["product_name"],
        "original_unit": row["unit"], "original_unit_price": ordered_price,
        "product_id": row["product_id"], "product_name": product_name,
        "major_category_name": major_name, "subcategory_name": sub_name,
        "unit": unit, "ordered_quantity": ordered_quantity,
        "final_quantity": final_quantity, "unit_price": final_price,
        "ordered_amount": ordered_amount, "final_amount": final_amount,
        "status_label": status_label, "corrected": corrected,
    }


def order_status_label(row, final_quantity):
    if row["order_status"] == "ordered":
        return "受取待ち"
    if row["order_status"] == "pending_sender_approval":
        return "数量差異・承認待ち"
    if final_quantity is not None and Decimal(str(final_quantity)) != minor_to_decimal(row["quantity_minor"]):
        return "数量変更・承認済"
    return "承認済"


def aggregate_products(lines):
    groups = {}
    for line in lines:
        if line["final_quantity"] is None or line["final_quantity"] <= 0:
            continue
        key = (
            line["major_category_name"], line["subcategory_name"], line["product_name"],
            line["unit"], line["unit_price"],
        )
        group = groups.setdefault(key, {
            "major_category_name": key[0], "subcategory_name": key[1],
            "product_name": key[2], "unit": key[3], "unit_price": key[4],
            "quantity": Decimal("0"), "amount": 0, "details": [],
        })
        group["quantity"] += line["final_quantity"]
        group["amount"] += line["final_amount"] or 0
        group["details"].append(line)
    return sorted(groups.values(), key=lambda row: (
        row["major_category_name"], row["subcategory_name"], row["product_name"],
        -1 if row["unit_price"] is None else row["unit_price"],
    ))


def aggregate_counterparty_products(lines, store_id, direction):
    groups = {}
    for line in lines:
        if direction == "orders":
            if line["from_store_id"] != store_id or line["line_type"] != "order_item":
                continue
            counterpart = line["to_store_name"]
            quantity = line["ordered_quantity"]
            unit = line["original_unit"]
            price = line["original_unit_price"]
            product_name = line["original_product_name"]
            amount = line["ordered_amount"]
        else:
            if line["to_store_id"] != store_id or line["final_quantity"] is None or line["final_quantity"] <= 0:
                continue
            counterpart = line["from_store_name"]
            quantity = line["final_quantity"]
            unit = line["unit"]
            price = line["unit_price"]
            product_name = line["product_name"]
            amount = line["final_amount"] or 0
        key = (product_name, counterpart, unit, price)
        group = groups.setdefault(key, {
            "product_name": product_name, "counterpart": counterpart,
            "unit": unit, "unit_price": price, "quantity": Decimal("0"), "amount": 0,
        })
        group["quantity"] += quantity
        group["amount"] += amount
    return sorted(groups.values(), key=lambda row: (row["product_name"], row["counterpart"]))


def find_transaction_line(line_type, line_id):
    for line in transaction_lines():
        if line["line_type"] == line_type and line["line_id"] == line_id:
            return line
    return None


def correction_snapshot(line):
    return {
        "product_id": line["product_id"], "product_name": line["product_name"],
        "major_category_name": line["major_category_name"],
        "subcategory_name": line["subcategory_name"], "unit": line["unit"],
        "quantity": None if line["final_quantity"] is None else float(line["final_quantity"]),
        "unit_price": line["unit_price"],
    }


def correction_history(line_type, line_id):
    rows = get_db().execute(
        """SELECT c.*, u.login_id AS admin_login_id
           FROM transaction_corrections c JOIN users u ON u.id = c.admin_user_id
           WHERE c.line_type = ? AND c.line_id = ? ORDER BY c.id DESC""",
        (line_type, line_id),
    ).fetchall()
    return rows


def dashboard_counts(store_id=None, environment=None):
    db = get_db()
    if store_id is None:
        store_ids = store_ids_for_environment(environment)
        placeholders = ",".join("?" for _ in store_ids)
        environment_sql = (
            f"o.from_store_id IN ({placeholders}) AND o.to_store_id IN ({placeholders})"
        )
        environment_params = tuple(store_ids + store_ids)
        order_count = db.execute(
            f"SELECT COUNT(*) FROM orders o WHERE {environment_sql}",
            environment_params,
        ).fetchone()[0]
        receipt_count = db.execute(
            f"""SELECT COUNT(*) FROM orders o
                WHERE o.receipt_reported_at IS NOT NULL AND {environment_sql}""",
            environment_params,
        ).fetchone()[0]
        approved_scope = f" AND {environment_sql}"
        params = environment_params
    else:
        order_count = db.execute(
            "SELECT COUNT(*) FROM orders WHERE from_store_id = ?", (store_id,)
        ).fetchone()[0]
        receipt_count = db.execute(
            """SELECT COUNT(*) FROM orders o WHERE o.to_store_id = ?
               AND NOT (o.status = 'received' AND NOT EXISTS (
                   SELECT 1 FROM unexpected_items ux WHERE ux.order_id = o.id
                   AND ux.status IN ('return_pending', 'returned', 'accept_pending')
               ))""", (store_id,)
        ).fetchone()[0]
        params = (store_id, store_id)
        approved_scope = " AND (o.from_store_id = ? OR o.to_store_id = ?)"
    approved_count = db.execute(
        f"""SELECT COUNT(*) FROM orders o
           WHERE o.status = 'received' AND NOT EXISTS (
               SELECT 1 FROM unexpected_items ux WHERE ux.order_id = o.id
               AND ux.status IN ('return_pending', 'returned', 'accept_pending')
           ) {approved_scope}""", params
    ).fetchone()[0]
    return {
        "orders": order_count,
        "receipts": receipt_count,
        "approved": approved_count,
        "pending": len(pending_tasks(store_id, environment)),
    }


def decorate_store_orders(orders, store_id, category):
    tasks_by_order = {}
    for task in pending_tasks(store_id):
        tasks_by_order.setdefault(task["order_id"], []).append(task)
    decorated = []
    for order in orders:
        row = dict(order)
        tasks = tasks_by_order.get(order["id"], [])
        own_tasks = [task for task in tasks if task["next_store_id"] == store_id]
        other_tasks = [task for task in tasks if task["next_store_id"] != store_id]
        row["action_required"] = bool(own_tasks)
        row["waiting_tasks"] = other_tasks
        row["pending_count"] = len(tasks)
        row["detail_endpoint"] = "receipt_detail" if category == "receipts" else "received_detail"
        decorated.append(row)
    return decorated


def pending_tasks(store_id=None, environment=None):
    """商品単位で、次の操作が必要な案件を一覧化する。"""
    rows = get_db().execute(
        """SELECT 'receipt' AS task_type, oi.id AS task_id,
                  o.id AS order_id, o.order_number, o.created_at,
                  f.id AS from_store_id, t.id AS to_store_id,
                  f.name AS from_store_name, t.name AS to_store_name,
                  oi.product_name, oi.quantity AS ordered_quantity,
                  NULL AS received_quantity, oi.unit,
                  '受取店舗の受取確認待ち' AS state_label, t.id AS next_store_id,
                  t.name AS next_store_name
           FROM orders o
           JOIN order_items oi ON oi.order_id = o.id
           JOIN stores f ON f.id = o.from_store_id
           JOIN stores t ON t.id = o.to_store_id
           WHERE o.status = 'ordered'

           UNION ALL

           SELECT 'quantity_difference', oi.id, o.id, o.order_number, o.created_at,
                  f.id, t.id, f.name, t.name, oi.product_name, oi.quantity,
                  oi.received_quantity, oi.unit,
                  '発注元の数量差異承認待ち', f.id, f.name
           FROM orders o
           JOIN order_items oi ON oi.order_id = o.id
           JOIN stores f ON f.id = o.from_store_id
           JOIN stores t ON t.id = o.to_store_id
           WHERE o.status = 'pending_sender_approval'
             AND oi.received_quantity IS NOT NULL
             AND oi.received_quantity != oi.quantity
             AND oi.final_received_quantity IS NULL

           UNION ALL

           SELECT 'unexpected_accept', ux.id, o.id, o.order_number, o.created_at,
                  f.id, t.id, f.name, t.name, ux.product_name, NULL,
                  ux.arrived_quantity, ux.unit,
                  '注文外商品の発注元承認待ち', f.id, f.name
           FROM unexpected_items ux
           JOIN orders o ON o.id = ux.order_id
           JOIN stores f ON f.id = o.from_store_id
           JOIN stores t ON t.id = o.to_store_id
           WHERE ux.status = 'accept_pending'

           UNION ALL

           SELECT 'return_pending', ux.id, o.id, o.order_number, o.created_at,
                  f.id, t.id, f.name, t.name, ux.product_name, NULL,
                  ux.arrived_quantity, ux.unit,
                  '受取店舗の返品処理待ち', t.id, t.name
           FROM unexpected_items ux
           JOIN orders o ON o.id = ux.order_id
           JOIN stores f ON f.id = o.from_store_id
           JOIN stores t ON t.id = o.to_store_id
           WHERE ux.status = 'return_pending'

           UNION ALL

           SELECT 'return_confirmation', ux.id, o.id, o.order_number, o.created_at,
                  f.id, t.id, f.name, t.name, ux.product_name, NULL,
                  ux.arrived_quantity, ux.unit,
                  '発注元の返品確認待ち', f.id, f.name
           FROM unexpected_items ux
           JOIN orders o ON o.id = ux.order_id
           JOIN stores f ON f.id = o.from_store_id
           JOIN stores t ON t.id = o.to_store_id
           WHERE ux.status = 'returned'

           ORDER BY created_at DESC, order_id DESC, task_id"""
    ).fetchall()
    if store_id is None and environment:
        allowed_store_ids = set(store_ids_for_environment(environment))
        rows = [
            row for row in rows
            if row["from_store_id"] in allowed_store_ids
            and row["to_store_id"] in allowed_store_ids
        ]
    if store_id is None:
        return rows
    return [
        row for row in rows
        if store_id in {row["from_store_id"], row["to_store_id"]}
    ]


app = create_app()


if __name__ == "__main__":
    app.run(
        host=os.environ.get("PITA_HOST", "127.0.0.1"),
        port=int(os.environ.get("PITA_PORT", "5000")),
        debug=os.environ.get("FLASK_DEBUG") == "1",
    )
