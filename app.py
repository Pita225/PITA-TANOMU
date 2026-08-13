import os
import re
import secrets
import sqlite3
import uuid
import csv
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
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename


BASE_DIR = Path(__file__).resolve().parent
SECRET_KEY_FILE = BASE_DIR / ".secret_key"


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=load_or_create_secret_key(),
        DATABASE=os.environ.get("PITA_DATABASE", str(BASE_DIR / "pita_tanom.db")),
        UPLOAD_FOLDER=str(BASE_DIR / "static" / "uploads"),
        MAX_CONTENT_LENGTH=5 * 1024 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
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
        number = float(value)
        return str(int(number)) if number.is_integer() else f"{number:g}"

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

    @app.before_request
    def load_logged_in_user():
        user_id = session.get("user_id")
        g.user = None
        if user_id:
            user = get_db().execute(
                """SELECT u.*, s.name AS store_name, s.is_active AS store_is_active,
                          s.is_deleted AS store_is_deleted
                   FROM users u LEFT JOIN stores s ON s.id = u.store_id
                   WHERE u.id = ?""", (user_id,)
            ).fetchone()
            valid = user and user["is_active"]
            if valid and user["role"] == "store":
                valid = user["store_is_active"] and not user["store_is_deleted"]
            if valid:
                g.user = user
            else:
                session.clear()

        allowed = {"login", "setup", "static"}
        if request.endpoint in allowed:
            return None
        admin_exists = get_db().execute(
            "SELECT 1 FROM users WHERE role = 'admin' LIMIT 1"
        ).fetchone()
        if admin_exists is None:
            return redirect(url_for("setup"))
        if g.user is None:
            return redirect(url_for("login"))
        return None

    @app.route("/setup", methods=["GET", "POST"])
    def setup():
        db = get_db()
        if db.execute("SELECT 1 FROM users WHERE role = 'admin' LIMIT 1").fetchone():
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
                return redirect(url_for("index"))
        return render_template("setup.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if get_db().execute("SELECT 1 FROM users WHERE role = 'admin' LIMIT 1").fetchone() is None:
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
                return redirect(url_for("index"))
        return render_template("login.html")

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.get("/")
    def index():
        db = get_db()
        if is_admin():
            stores = db.execute(
                "SELECT * FROM stores WHERE is_active = 1 AND is_deleted = 0 ORDER BY name, id"
            ).fetchall()
            scoped_store_id = None
        else:
            stores = db.execute(
                """SELECT * FROM stores
                   WHERE is_active = 1 AND is_deleted = 0 AND id <> ? ORDER BY name, id""",
                (g.user["store_id"],),
            ).fetchall()
            scoped_store_id = g.user["store_id"]
        return render_template(
            "index.html", stores=stores, counts=dashboard_counts(scoped_store_id)
        )

    @app.get("/product-images/<path:filename>")
    def product_image(filename):
        return send_from_directory(current_app.config["UPLOAD_FOLDER"], filename)

    @app.get("/status/<category>")
    def status_list(category):
        if category not in {"orders", "receipts", "approved", "pending"}:
            abort(404)
        db = get_db()
        scoped_store_id = None if is_admin() else g.user["store_id"]
        counts = dashboard_counts(scoped_store_id)
        if category == "pending" and scoped_store_id is not None:
            return redirect(url_for("index"))
        if category == "pending":
            return render_template(
                "status_list.html", category=category, counts=counts,
                tasks=pending_tasks(scoped_store_id), orders=[],
            )

        conditions = {
            "orders": "1 = 1",
            "receipts": "o.receipt_reported_at IS NOT NULL",
            "approved": """o.status = 'received' AND NOT EXISTS (
                SELECT 1 FROM unexpected_items ux WHERE ux.order_id = o.id
                AND ux.status IN ('return_pending', 'returned', 'accept_pending'))""",
        }
        if scoped_store_id is None:
            scope_sql = ""
            params = ()
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
            orders=orders, tasks=[],
        )

    @app.post("/order/start")
    def start_order():
        from_id = request.form.get("from_store_id", type=int) if is_admin() else g.user["store_id"]
        to_id = request.form.get("to_store_id", type=int)
        if not valid_store_pair(from_id, to_id):
            flash("発注元と発注先には別々の店舗を選んでください。", "error")
            return redirect(url_for("index"))
        session["order_context"] = {"from_store_id": from_id, "to_store_id": to_id}
        session.pop("cart", None)
        return redirect(url_for("products"))

    @app.get("/products")
    def products():
        context = current_order_context()
        if context is None or (not is_admin() and context.get("from_store_id") != g.user["store_id"]) or not valid_store_pair(
            context.get("from_store_id"), context.get("to_store_id")
        ):
            session.pop("order_context", None)
            session.pop("cart", None)
            flash("最初に発注元と発注先を選んでください。", "error")
            return redirect(url_for("index"))
        db = get_db()
        product_rows = orderable_products()
        major_categories = db.execute(
            """SELECT * FROM product_categories
               WHERE level = 1 AND is_active = 1 AND is_deleted = 0 ORDER BY name, id"""
        ).fetchall()
        subcategories = db.execute(
            """SELECT c.* FROM product_categories c
               JOIN product_categories p ON p.id = c.parent_id
               WHERE c.level = 2 AND c.is_active = 1 AND c.is_deleted = 0
                 AND p.is_active = 1 AND p.is_deleted = 0 ORDER BY c.name, c.id"""
        ).fetchall()
        stores = load_context_stores(context)
        return render_template(
            "products.html", products=product_rows, major_categories=major_categories,
            subcategories=subcategories, **stores
        )

    @app.post("/cart")
    def update_cart():
        context = current_order_context()
        if context is None or (not is_admin() and context.get("from_store_id") != g.user["store_id"]):
            session.pop("order_context", None)
            session.pop("cart", None)
            return redirect(url_for("index"))

        products_by_id = {row["id"]: row for row in orderable_products()}
        cart = []
        invalid = False
        for product_id, product in products_by_id.items():
            raw = request.form.get(f"quantity_{product_id}", "").strip()
            if not raw:
                continue
            try:
                amount = Decimal(raw)
                if not amount.is_finite() or amount <= 0 or amount > Decimal("99999"):
                    raise InvalidOperation
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
            not is_admin() and context.get("from_store_id") != g.user["store_id"]
        ):
            flash("カートが空です。", "error")
            return redirect(url_for("index"))
        stores = load_context_stores(context)
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
            not is_admin() and context.get("from_store_id") != g.user["store_id"]
        ) or not valid_store_pair(
            context.get("from_store_id"), context.get("to_store_id")
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
                   (order_id, product_id, product_name, unit, quantity, unit_price,
                    major_category_name, subcategory_name)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                [(
                    order_id, item["product_id"], item["name"], item["unit"],
                    float(item["quantity"]), item["unit_price"],
                    item["major_name"], item["subcategory_name"]
                ) for item in items],
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
        return render_template("complete.html", order=order)

    @app.get("/received")
    def received():
        db = get_db()
        stores = db.execute(
            "SELECT * FROM stores WHERE is_deleted = 0 ORDER BY is_active DESC, name, id"
        ).fetchall() if is_admin() else []
        store_id = request.args.get("store_id", type=int) if is_admin() else g.user["store_id"]
        selected_store = None
        orders = []
        if store_id:
            selected_store = db.execute(
                "SELECT * FROM stores WHERE id = ? AND is_deleted = 0", (store_id,)
            ).fetchone()
            if selected_store:
                store_column = "o.to_store_id" if is_admin() else "o.from_store_id"
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
            can_sender_action=is_admin() or g.user["store_id"] == order["from_store_id"],
        )

    @app.post("/received/<int:order_id>/approve")
    def approve_receipt_difference(order_id):
        db = get_db()
        order = fetch_order(order_id)
        if order is None:
            abort(404)
        require_order_role(order, "from_store_id")
        if order["status"] != "pending_sender_approval":
            flash("この発注には承認待ちの受取差異がありません。", "error")
            return redirect(url_for("received_detail", order_id=order_id))
        try:
            db.execute(
                """UPDATE order_items SET final_received_quantity = received_quantity
                   WHERE order_id = ? AND final_received_quantity IS NULL""",
                (order_id,),
            )
            db.execute(
                """UPDATE unexpected_items
                   SET status = 'accepted', final_received_quantity = arrived_quantity,
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
        require_order_role(order, "from_store_id")
        if item["status"] != "returned":
            flash("返品済みの商品だけ返品完了にできます。", "error")
        else:
            db.execute(
                """UPDATE unexpected_items SET status = 'return_complete',
                       updated_at = datetime('now', 'localtime') WHERE id = ?""",
                (item_id,),
            )
            db.commit()
            flash(f"「{item['product_name']}」の返品を確認しました。", "success")
        return redirect(url_for("received_detail", order_id=order_id))

    @app.get("/receipts")
    def receipts():
        db = get_db()
        stores = db.execute(
            "SELECT * FROM stores WHERE is_deleted = 0 ORDER BY is_active DESC, name, id"
        ).fetchall() if is_admin() else []
        store_id = request.args.get("store_id", type=int) if is_admin() else g.user["store_id"]
        selected_store = None
        orders = []
        if store_id:
            selected_store = db.execute(
                "SELECT * FROM stores WHERE id = ? AND is_deleted = 0", (store_id,)
            ).fetchone()
            if selected_store:
                store_column = "o.from_store_id" if is_admin() else "o.to_store_id"
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
                    amount = Decimal(raw)
                    if not amount.is_finite() or amount < 0 or amount > Decimal("99999"):
                        raise InvalidOperation
                except InvalidOperation:
                    flash("届いた数量は0以上の数値で入力してください。", "error")
                    return redirect(url_for("receipt_detail", order_id=order_id))
                ordered_amount = Decimal(str(item["quantity"]))
                is_match = amount == ordered_amount
                approval_required = approval_required or not is_match
                final_quantity = float(amount) if is_match else None
                received_values.append((float(amount), final_quantity, item["id"], order_id))

            ordered_product_ids = {item["product_id"] for item in items}
            product_map = {product["id"]: product for product in products}
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
                    amount = Decimal(raw_quantity)
                    if not amount.is_finite() or amount <= 0 or amount > Decimal("99999"):
                        raise InvalidOperation
                except InvalidOperation:
                    flash("注文外商品の数量は0より大きい数値で入力してください。", "error")
                    return redirect(url_for("receipt_detail", order_id=order_id))
                seen_extra_products.add(product_id)
                status = "return_pending" if decision == "return" else "accept_pending"
                final_quantity = 0 if decision == "return" else None
                approval_required = approval_required or decision == "accept"
                extra_values.append((
                    order_id, product_id, product["name"], product["unit"],
                    float(amount), decision, status, final_quantity, product["unit_price"],
                    product["major_name"], product["subcategory_name"],
                ))

            try:
                db.executemany(
                    """UPDATE order_items
                       SET received_quantity = ?, final_received_quantity = ?
                       WHERE id = ? AND order_id = ?""",
                    received_values,
                )
                if extra_values:
                    db.executemany(
                        """INSERT INTO unexpected_items
                           (order_id, product_id, product_name, unit, arrived_quantity,
                            decision, status, final_received_quantity, unit_price,
                            major_category_name, subcategory_name)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
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
            can_receive_action=is_admin() or g.user["store_id"] == order["to_store_id"],
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
        require_order_role(order, "to_store_id")
        if item["status"] != "return_pending":
            flash("返品予定の商品だけ返品済みにできます。", "error")
        else:
            db.execute(
                """UPDATE unexpected_items SET status = 'returned',
                       updated_at = datetime('now', 'localtime') WHERE id = ?""",
                (item_id,),
            )
            db.commit()
            flash(f"「{item['product_name']}」を返品済みにしました。", "success")
        return redirect(url_for("receipt_detail", order_id=order_id))

    @app.get("/reports")
    def reports():
        month, start_date, end_date = parse_month(request.args.get("month"))
        scope_store_id = report_scope_store_id(request.args.get("store_id", type=int))
        lines = transaction_lines(start_date, end_date)
        db = get_db()
        if is_admin():
            if scope_store_id:
                stores = db.execute(
                    "SELECT * FROM stores WHERE id = ? AND is_deleted = 0", (scope_store_id,)
                ).fetchall()
            else:
                stores = db.execute(
                    "SELECT * FROM stores WHERE is_deleted = 0 ORDER BY id"
                ).fetchall()
            store_options = db.execute(
                "SELECT * FROM stores WHERE is_deleted = 0 ORDER BY id"
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
        lines = transaction_lines(report_date, report_date + timedelta(days=1), scope_store_id)
        store_options = []
        if is_admin():
            store_options = get_db().execute(
                "SELECT * FROM stores WHERE is_deleted = 0 ORDER BY id"
            ).fetchall()
        return render_template(
            "report_daily.html", report_date=report_date.isoformat(), lines=lines,
            product_summary=aggregate_products(lines), store_options=store_options,
            selected_store_id=scope_store_id,
        )

    @app.route("/reports/correct/<line_type>/<int:line_id>", methods=["GET", "POST"])
    @admin_required
    def correct_transaction(line_type, line_id):
        if line_type not in {"order_item", "unexpected_item"}:
            abort(404)
        line = find_transaction_line(line_type, line_id)
        if line is None:
            abort(404)
        db = get_db()
        if request.method == "POST":
            reason = " ".join(request.form.get("reason", "").split())
            product_id = request.form.get("product_id", type=int)
            raw_quantity = request.form.get("quantity", "").strip()
            raw_price = request.form.get("unit_price", "").replace(",", "").strip()
            product = db.execute(
                """SELECT p.*, major.name AS major_name, sub.name AS subcategory_name
                   FROM products p
                   JOIN product_categories major ON major.id = p.major_category_id
                   JOIN product_categories sub ON sub.id = p.subcategory_id
                   WHERE p.id = ? AND p.is_deleted = 0""", (product_id,)
            ).fetchone()
            error = None
            try:
                quantity_value = Decimal(raw_quantity)
                if not quantity_value.is_finite() or quantity_value < 0 or quantity_value > Decimal("99999"):
                    raise InvalidOperation
            except InvalidOperation:
                error = "最終数量は0以上の数値で入力してください。"
                quantity_value = Decimal("0")
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
                        corrected_unit_price, reason, before_json, after_json, admin_user_id)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (line["order_id"], line_type, line_id, product["id"], product["name"],
                     product["major_name"], product["subcategory_name"], product["unit"],
                     float(quantity_value), unit_price, reason,
                     json.dumps(before, ensure_ascii=False), json.dumps(after, ensure_ascii=False),
                     g.user["id"]),
                )
                db.commit()
                flash("最終確定値を訂正し、訂正履歴を保存しました。", "success")
                return redirect(url_for(
                    "report_daily", date=line["date"], store_id=request.args.get("store_id")
                ))
        products = db.execute(
            """SELECT p.*, major.name AS major_name, sub.name AS subcategory_name
               FROM products p JOIN product_categories major ON major.id = p.major_category_id
               JOIN product_categories sub ON sub.id = p.subcategory_id
               WHERE p.is_deleted = 0 ORDER BY major.name, sub.name, p.name"""
        ).fetchall()
        history = correction_history(line_type, line_id)
        return render_template(
            "correction_form.html", line=line, products=products, history=history
        )

    @app.get("/reports/corrections")
    @admin_required
    def report_corrections():
        rows = get_db().execute(
            """SELECT c.*, u.login_id AS admin_login_id, o.order_number,
                      f.name AS from_store_name, t.name AS to_store_name
               FROM transaction_corrections c
               JOIN users u ON u.id = c.admin_user_id
               JOIN orders o ON o.id = c.order_id
               JOIN stores f ON f.id = o.from_store_id
               JOIN stores t ON t.id = o.to_store_id
               ORDER BY c.created_at DESC, c.id DESC"""
        ).fetchall()
        return render_template("correction_history.html", corrections=rows)

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
        lines = transaction_lines(start_date, end_inclusive + timedelta(days=1))
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
    @admin_required
    def product_management():
        products = get_db().execute(
            """SELECT p.*, major.name AS major_name, sub.name AS subcategory_name,
                      u.name AS unit_name
               FROM products p
               LEFT JOIN product_categories major ON major.id = p.major_category_id
               LEFT JOIN product_categories sub ON sub.id = p.subcategory_id
               LEFT JOIN units u ON u.id = p.unit_id
               WHERE p.is_deleted = 0
               ORDER BY p.is_active DESC, major.name, sub.name, p.display_order, p.id"""
        ).fetchall()
        return render_template("product_management.html", products=products)

    @app.route("/product-management/new", methods=["GET", "POST"])
    @admin_required
    def new_product():
        if request.method == "POST":
            return save_product_form()
        return render_product_form()

    @app.route("/product-management/<int:product_id>/edit", methods=["GET", "POST"])
    @admin_required
    def edit_product(product_id):
        product = get_db().execute(
            "SELECT * FROM products WHERE id = ? AND is_deleted = 0", (product_id,)
        ).fetchone()
        if product is None:
            abort(404)
        if request.method == "POST":
            return save_product_form(product)
        return render_product_form(product)

    @app.post("/product-management/<int:product_id>/toggle")
    @admin_required
    def toggle_product(product_id):
        db = get_db()
        product = db.execute(
            "SELECT * FROM products WHERE id = ? AND is_deleted = 0", (product_id,)
        ).fetchone()
        if product is None:
            abort(404)
        new_status = 0 if product["is_active"] else 1
        db.execute("UPDATE products SET is_active = ? WHERE id = ?", (new_status, product_id))
        db.commit()
        flash(f"「{product['name']}」を{'再開' if new_status else '停止'}しました。", "success")
        return redirect(url_for("product_management"))

    @app.post("/product-management/<int:product_id>/delete")
    @admin_required
    def delete_product(product_id):
        db = get_db()
        product = db.execute(
            "SELECT * FROM products WHERE id = ? AND is_deleted = 0", (product_id,)
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
    @admin_required
    def categories():
        db = get_db()
        majors = db.execute(
            """SELECT * FROM product_categories
               WHERE level = 1 AND is_deleted = 0 ORDER BY id"""
        ).fetchall()
        subs = db.execute(
            """SELECT c.*, p.name AS parent_name FROM product_categories c
               JOIN product_categories p ON p.id = c.parent_id
               WHERE c.level = 2 AND c.is_deleted = 0 ORDER BY p.id, c.id"""
        ).fetchall()
        return render_template("categories.html", majors=majors, subcategories=subs)

    @app.post("/categories/add")
    @admin_required
    def add_category():
        db = get_db()
        name = normalize_master_name(request.form.get("name"))
        level = request.form.get("level", type=int)
        parent_id = request.form.get("parent_id", type=int) if level == 2 else None
        error = validate_category(db, name, level, parent_id)
        if error:
            flash(error, "error")
        else:
            db.execute(
                "INSERT INTO product_categories (name, level, parent_id) VALUES (?, ?, ?)",
                (name, level, parent_id),
            )
            db.commit()
            flash(f"分類「{name}」を追加しました。", "success")
        return redirect(url_for("categories"))

    @app.route("/categories/<int:category_id>/edit", methods=["GET", "POST"])
    @admin_required
    def edit_category(category_id):
        db = get_db()
        category = db.execute(
            "SELECT * FROM product_categories WHERE id = ? AND is_deleted = 0",
            (category_id,),
        ).fetchone()
        if category is None:
            abort(404)
        if request.method == "POST":
            name = normalize_master_name(request.form.get("name"))
            error = validate_category(
                db, name, category["level"], category["parent_id"], category_id
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
    @admin_required
    def toggle_category(category_id):
        db = get_db()
        category = db.execute(
            "SELECT * FROM product_categories WHERE id = ? AND is_deleted = 0",
            (category_id,),
        ).fetchone()
        if category is None:
            abort(404)
        new_status = 0 if category["is_active"] else 1
        db.execute("UPDATE product_categories SET is_active = ? WHERE id = ?", (new_status, category_id))
        db.commit()
        flash(f"分類「{category['name']}」を{'再開' if new_status else '停止'}しました。", "success")
        return redirect(url_for("categories"))

    @app.post("/categories/<int:category_id>/delete")
    @admin_required
    def delete_category(category_id):
        db = get_db()
        category = db.execute(
            "SELECT * FROM product_categories WHERE id = ? AND is_deleted = 0",
            (category_id,),
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
    @admin_required
    def units():
        rows = get_db().execute(
            "SELECT * FROM units WHERE is_deleted = 0 ORDER BY id"
        ).fetchall()
        return render_template("units.html", units=rows)

    @app.post("/units/add")
    @admin_required
    def add_unit():
        db = get_db()
        name = normalize_master_name(request.form.get("name"))
        if not name:
            flash("単位名を入力してください。", "error")
        elif len(name) > 20:
            flash("単位名は20文字以内で入力してください。", "error")
        elif db.execute("SELECT 1 FROM units WHERE name = ?", (name,)).fetchone():
            flash("同じ単位がすでに登録されています。", "error")
        else:
            db.execute("INSERT INTO units (name) VALUES (?)", (name,))
            db.commit()
            flash(f"単位「{name}」を追加しました。", "success")
        return redirect(url_for("units"))

    @app.route("/units/<int:unit_id>/edit", methods=["GET", "POST"])
    @admin_required
    def edit_unit(unit_id):
        db = get_db()
        unit = db.execute("SELECT * FROM units WHERE id = ? AND is_deleted = 0", (unit_id,)).fetchone()
        if unit is None:
            abort(404)
        if request.method == "POST":
            name = normalize_master_name(request.form.get("name"))
            if not name or len(name) > 20:
                flash("単位名は1～20文字で入力してください。", "error")
            elif db.execute("SELECT 1 FROM units WHERE name = ? AND id <> ?", (name, unit_id)).fetchone():
                flash("同じ単位がすでに登録されています。", "error")
            else:
                db.execute("UPDATE units SET name = ? WHERE id = ?", (name, unit_id))
                db.execute("UPDATE products SET unit = ? WHERE unit_id = ?", (name, unit_id))
                db.commit()
                flash(f"単位を「{name}」に変更しました。", "success")
                return redirect(url_for("units"))
        return render_template("master_edit.html", item=unit, master_name="単位", back_endpoint="units")

    @app.post("/units/<int:unit_id>/toggle")
    @admin_required
    def toggle_unit(unit_id):
        db = get_db()
        unit = db.execute("SELECT * FROM units WHERE id = ? AND is_deleted = 0", (unit_id,)).fetchone()
        if unit is None:
            abort(404)
        new_status = 0 if unit["is_active"] else 1
        db.execute("UPDATE units SET is_active = ? WHERE id = ?", (new_status, unit_id))
        db.commit()
        flash(f"単位「{unit['name']}」を{'再開' if new_status else '停止'}しました。", "success")
        return redirect(url_for("units"))

    @app.post("/units/<int:unit_id>/delete")
    @admin_required
    def delete_unit(unit_id):
        db = get_db()
        unit = db.execute("SELECT * FROM units WHERE id = ? AND is_deleted = 0", (unit_id,)).fetchone()
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
            """SELECT u.*, s.name AS store_name, s.is_active AS store_is_active
               FROM users u JOIN stores s ON s.id = u.store_id
               WHERE u.role = 'store' AND s.is_deleted = 0 ORDER BY s.id"""
        ).fetchall()
        available_stores = db.execute(
            """SELECT s.* FROM stores s LEFT JOIN users u ON u.store_id = s.id
               WHERE s.is_deleted = 0 AND u.id IS NULL ORDER BY s.id"""
        ).fetchall()
        return render_template(
            "accounts.html", accounts=account_rows, available_stores=available_stores
        )

    @app.route("/accounts/<int:user_id>/edit", methods=["GET", "POST"])
    @admin_required
    def edit_account(user_id):
        db = get_db()
        account = db.execute(
            """SELECT u.*, s.name AS store_name FROM users u JOIN stores s ON s.id = u.store_id
               WHERE u.id = ? AND u.role = 'store' AND s.is_deleted = 0""",
            (user_id,),
        ).fetchone()
        if account is None:
            abort(404)
        if request.method == "POST":
            login_id = normalize_login_id(request.form.get("login_id"))
            password = request.form.get("password", "")
            error = validate_login_id(login_id)
            if password and len(password) < 8:
                error = "新しいパスワードは8文字以上で入力してください。"
            if db.execute(
                "SELECT 1 FROM users WHERE login_id = ? AND id <> ?", (login_id, user_id)
            ).fetchone():
                error = "このログインIDはすでに使用されています。"
            if error:
                flash(error, "error")
            else:
                if password:
                    db.execute(
                        "UPDATE users SET login_id = ?, password_hash = ? WHERE id = ?",
                        (login_id, generate_password_hash(password), user_id),
                    )
                else:
                    db.execute("UPDATE users SET login_id = ? WHERE id = ?", (login_id, user_id))
                db.commit()
                flash(f"{account['store_name']}のアカウントを更新しました。", "success")
                return redirect(url_for("accounts"))
        return render_template("account_edit.html", account=account)

    @app.post("/accounts/<int:user_id>/toggle")
    @admin_required
    def toggle_account(user_id):
        db = get_db()
        account = db.execute(
            """SELECT u.*, s.name AS store_name FROM users u JOIN stores s ON s.id = u.store_id
               WHERE u.id = ? AND u.role = 'store'""", (user_id,)
        ).fetchone()
        if account is None:
            abort(404)
        new_status = 0 if account["is_active"] else 1
        db.execute("UPDATE users SET is_active = ? WHERE id = ?", (new_status, user_id))
        db.commit()
        flash(f"{account['store_name']}のアカウントを{'再開' if new_status else '停止'}しました。", "success")
        return redirect(url_for("accounts"))

    @app.route("/stores", methods=["GET", "POST"])
    @admin_required
    def stores():
        db = get_db()
        if request.method == "POST":
            name = normalize_store_name(request.form.get("name"))
            if not name:
                flash("店舗名を入力してください。", "error")
            elif len(name) > 50:
                flash("店舗名は50文字以内で入力してください。", "error")
            elif db.execute("SELECT 1 FROM stores WHERE name = ?", (name,)).fetchone():
                flash("同じ店舗名がすでに登録されています。", "error")
            else:
                db.execute("INSERT INTO stores (name) VALUES (?)", (name,))
                db.commit()
                flash(f"「{name}」を追加しました。", "success")
                return redirect(url_for("stores"))
        store_rows = db.execute(
            """SELECT s.*, u.id AS account_id, u.login_id, u.is_active AS account_active
               FROM stores s LEFT JOIN users u ON u.store_id = s.id AND u.role = 'store'
               WHERE s.is_deleted = 0 ORDER BY s.id"""
        ).fetchall()
        return render_template("stores.html", stores=store_rows)

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
            if not name:
                flash("店舗名を入力してください。", "error")
            elif len(name) > 50:
                flash("店舗名は50文字以内で入力してください。", "error")
            elif db.execute(
                "SELECT 1 FROM stores WHERE name = ? AND id <> ?", (name, store_id)
            ).fetchone():
                flash("同じ店舗名がすでに登録されています。", "error")
            else:
                db.execute("UPDATE stores SET name = ? WHERE id = ?", (name, store_id))
                db.commit()
                flash(f"店舗名を「{name}」に変更しました。", "success")
                return redirect(url_for("stores"))
        return render_template("store_edit.html", store=store)

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

    db.execute(
        """CREATE TABLE IF NOT EXISTS users (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               login_id TEXT NOT NULL UNIQUE,
               password_hash TEXT NOT NULL,
               role TEXT NOT NULL,
               store_id INTEGER UNIQUE,
               is_active INTEGER NOT NULL DEFAULT 1,
               created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
               FOREIGN KEY (store_id) REFERENCES stores (id),
               CHECK (role IN ('admin', 'store')),
               CHECK ((role = 'admin' AND store_id IS NULL)
                   OR (role = 'store' AND store_id IS NOT NULL))
           )"""
    )

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
    db.commit()


def valid_store_pair(from_id, to_id):
    if not from_id or not to_id or from_id == to_id:
        return False
    count = get_db().execute(
        """SELECT COUNT(*) FROM stores
           WHERE id IN (?, ?) AND is_active = 1 AND is_deleted = 0""",
        (from_id, to_id)
    ).fetchone()[0]
    return count == 2


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
            """SELECT p.*, major.name AS major_name, sub.name AS subcategory_name
               FROM products p
               JOIN product_categories major ON major.id = p.major_category_id
               JOIN product_categories sub ON sub.id = p.subcategory_id
               JOIN units u ON u.id = p.unit_id
               WHERE p.id = ? AND p.is_active = 1 AND p.is_deleted = 0
                 AND major.is_active = 1 AND major.is_deleted = 0
                 AND sub.is_active = 1 AND sub.is_deleted = 0
                 AND u.is_active = 1 AND u.is_deleted = 0""",
            (saved.get("product_id"),),
        ).fetchone()
        if product is None:
            continue
        try:
            amount = Decimal(saved["quantity"])
        except (InvalidOperation, KeyError):
            continue
        subtotal = None
        if product["unit_price"] is not None:
            subtotal = float(amount) * product["unit_price"]
        items.append({
            "product_id": product["id"], "name": product["name"],
            "unit": product["unit"], "unit_price": product["unit_price"],
            "quantity": float(amount), "subtotal": subtotal,
            "major_name": product["major_name"],
            "subcategory_name": product["subcategory_name"],
        })
    return items


def fetch_order(order_id):
    return get_db().execute(
        """SELECT o.*, f.name AS from_store_name, t.name AS to_store_name
           FROM orders o JOIN stores f ON f.id = o.from_store_id
           JOIN stores t ON t.id = o.to_store_id WHERE o.id = ?""",
        (order_id,),
    ).fetchone()


def normalize_store_name(value):
    return " ".join((value or "").split())


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
        if g.user["role"] != "admin":
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def is_admin():
    return g.user is not None and g.user["role"] == "admin"


def can_access_order(order):
    return is_admin() or (
        g.user and g.user["store_id"] in {order["from_store_id"], order["to_store_id"]}
    )


def require_order_role(order, store_column):
    if is_admin():
        return
    if g.user is None or g.user["store_id"] != order[store_column]:
        abort(403)


def validate_category(db, name, level, parent_id, exclude_id=None):
    if not name or len(name) > 50:
        return "分類名は1～50文字で入力してください。"
    if level not in {1, 2}:
        return "分類の種類が正しくありません。"
    if level == 2:
        parent = db.execute(
            """SELECT 1 FROM product_categories
               WHERE id = ? AND level = 1 AND is_active = 1 AND is_deleted = 0""",
            (parent_id,),
        ).fetchone()
        if parent is None:
            return "有効な大分類を選択してください。"
    duplicate = db.execute(
        """SELECT 1 FROM product_categories
           WHERE name = ? AND level = ? AND parent_id IS ? AND is_deleted = 0
             AND (? IS NULL OR id <> ?)""",
        (name, level, parent_id, exclude_id, exclude_id),
    ).fetchone()
    if duplicate:
        return "同じ分類がすでに登録されています。"
    return None


def render_product_form(product=None):
    db = get_db()
    majors = db.execute(
        """SELECT * FROM product_categories
           WHERE level = 1 AND is_active = 1 AND is_deleted = 0 ORDER BY name, id"""
    ).fetchall()
    subcategories = db.execute(
        """SELECT c.* FROM product_categories c
           JOIN product_categories p ON p.id = c.parent_id
           WHERE c.level = 2 AND c.is_active = 1 AND c.is_deleted = 0
             AND p.is_active = 1 AND p.is_deleted = 0 ORDER BY c.name, c.id"""
    ).fetchall()
    units = db.execute(
        "SELECT * FROM units WHERE is_active = 1 AND is_deleted = 0 ORDER BY name, id"
    ).fetchall()
    return render_template(
        "product_form.html", product=product, majors=majors,
        subcategories=subcategories, units=units,
    )


def save_product_form(product=None):
    db = get_db()
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
             AND major.is_active = 1 AND major.is_deleted = 0""",
        (subcategory_id, major_id),
    ).fetchone()
    unit = db.execute(
        "SELECT * FROM units WHERE id = ? AND is_active = 1 AND is_deleted = 0",
        (unit_id,),
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
            "SELECT COALESCE(MAX(display_order), 0) + 10 FROM products"
        ).fetchone()[0]
        db.execute(
            """INSERT INTO products
               (name, major_category_id, subcategory_id, unit_id, unit, unit_price,
                image_filename, display_order)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (name, major_id, subcategory_id, unit_id, unit["name"], unit_price,
             image_filename, display_order),
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


def orderable_products():
    return get_db().execute(
        """SELECT p.*, major.name AS major_name, sub.name AS subcategory_name,
                  u.name AS unit_name
           FROM products p
           JOIN product_categories major ON major.id = p.major_category_id
           JOIN product_categories sub ON sub.id = p.subcategory_id
           JOIN units u ON u.id = p.unit_id
           WHERE p.is_active = 1 AND p.is_deleted = 0
             AND major.is_active = 1 AND major.is_deleted = 0
             AND sub.is_active = 1 AND sub.is_deleted = 0
             AND u.is_active = 1 AND u.is_deleted = 0
           ORDER BY major.name, sub.name, p.display_order, p.name, p.id"""
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
    if not is_admin():
        return g.user["store_id"]
    if not requested_store_id:
        return None
    exists = get_db().execute(
        "SELECT 1 FROM stores WHERE id = ? AND is_deleted = 0", (requested_store_id,)
    ).fetchone()
    if exists is None:
        abort(404)
    return requested_store_id


def require_report_store(store_id):
    if not is_admin() and g.user["store_id"] != store_id:
        abort(403)


def transaction_lines(start_date=None, end_date=None, related_store_id=None):
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
    where = " AND ".join(conditions) if conditions else "1 = 1"
    ordered_rows = db.execute(
        f"""SELECT oi.*, o.order_number, o.from_store_id, o.to_store_id,
                   o.created_at AS order_created_at, o.status AS order_status,
                   f.name AS from_store_name, t.name AS to_store_name
            FROM order_items oi
            JOIN orders o ON o.id = oi.order_id
            JOIN stores f ON f.id = o.from_store_id
            JOIN stores t ON t.id = o.to_store_id
            WHERE {where} ORDER BY o.created_at, o.id, oi.id""", params
    ).fetchall()
    unexpected_rows = db.execute(
        f"""SELECT ux.*, o.order_number, o.from_store_id, o.to_store_id,
                   o.created_at AS order_created_at, o.status AS order_status,
                   f.name AS from_store_name, t.name AS to_store_name
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
        final_quantity = row["final_received_quantity"]
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
            final_quantity = correction["corrected_quantity"]
            final_price = correction["corrected_unit_price"]
        status_label = order_status_label(row, final_quantity)
        lines.append(make_report_line(
            row, "order_item", row["id"], product_name, major_name, sub_name, unit,
            row["quantity"], final_quantity, row["unit_price"], final_price,
            status_label, bool(correction),
        ))

    unexpected_labels = {
        "return_pending": "返品予定", "returned": "返品済み",
        "return_complete": "返品完了", "accept_pending": "注文外商品承認待ち",
        "accepted": "注文外商品承認済",
    }
    for row in unexpected_rows:
        correction = corrections.get(("unexpected_item", row["id"]))
        final_quantity = row["final_received_quantity"]
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
            final_quantity = correction["corrected_quantity"]
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
    ordered_quantity = float(ordered_quantity or 0)
    final_quantity = None if final_quantity is None else float(final_quantity)
    ordered_amount = 0 if ordered_price is None else round(ordered_quantity * ordered_price)
    final_amount = None if final_quantity is None else (
        0 if final_price is None else round(final_quantity * final_price)
    )
    return {
        "line_type": line_type, "line_id": line_id,
        "order_id": row["order_id"], "order_number": row["order_number"],
        "created_at": created_at, "date": created_at[:10], "time": created_at[11:16],
        "from_store_id": row["from_store_id"], "to_store_id": row["to_store_id"],
        "from_store_name": row["from_store_name"], "to_store_name": row["to_store_name"],
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
    if final_quantity is not None and float(final_quantity) != float(row["quantity"]):
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
            "quantity": 0, "amount": 0, "details": [],
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
            "unit": unit, "unit_price": price, "quantity": 0, "amount": 0,
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
        "quantity": line["final_quantity"], "unit_price": line["unit_price"],
    }


def correction_history(line_type, line_id):
    rows = get_db().execute(
        """SELECT c.*, u.login_id AS admin_login_id
           FROM transaction_corrections c JOIN users u ON u.id = c.admin_user_id
           WHERE c.line_type = ? AND c.line_id = ? ORDER BY c.id DESC""",
        (line_type, line_id),
    ).fetchall()
    return rows


def dashboard_counts(store_id=None):
    db = get_db()
    if store_id is None:
        order_count = db.execute("SELECT COUNT(*) FROM orders").fetchone()[0]
        receipt_count = db.execute(
            "SELECT COUNT(*) FROM orders WHERE receipt_reported_at IS NOT NULL"
        ).fetchone()[0]
        params = ()
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
    approved_scope = "" if store_id is None else " AND (o.from_store_id = ? OR o.to_store_id = ?)"
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
        "pending": len(pending_tasks(store_id)),
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


def pending_tasks(store_id=None):
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
