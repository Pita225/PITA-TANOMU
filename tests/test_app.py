import sqlite3
import tempfile
import unittest
import csv
import io
from io import BytesIO
from pathlib import Path

from app import create_app, init_db


class OrderFlowTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = str(Path(self.temp_dir.name) / "test.db")
        self.app = create_app({
            "TESTING": True,
            "SECRET_KEY": "test",
            "DATABASE": self.database,
            "UPLOAD_FOLDER": str(Path(self.temp_dir.name) / "uploads"),
        })
        with self.app.app_context():
            init_db()
        self.client = self.app.test_client()
        response = self.client.post("/setup", data={
            "login_id": "admin", "password": "admin-pass-123",
            "password_confirmation": "admin-pass-123",
        })
        self.assertEqual(response.status_code, 302)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_complete_order_flow(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("発注をはじめる", response.get_data(as_text=True))

        response = self.client.post(
            "/order/start",
            data={"from_store_id": 1, "to_store_id": 2},
            follow_redirects=True,
        )
        self.assertIn("国産鶏もも肉", response.get_data(as_text=True))

        response = self.client.post(
            "/cart",
            data={"quantity_1": "2.5", "quantity_3": "4", "quantity_5": ""},
            follow_redirects=True,
        )
        page = response.get_data(as_text=True)
        self.assertIn("発注内容の確認", page)
        self.assertIn("国産鶏もも肉", page)
        self.assertIn("トマト", page)
        self.assertNotIn("玉ねぎ", page)
        self.assertIn("¥3,680", page)

        response = self.client.post("/order/submit", follow_redirects=True)
        page = response.get_data(as_text=True)
        self.assertIn("発注が完了しました", page)
        self.assertIn("ORD-000001", page)

        response = self.client.get("/received?store_id=2")
        page = response.get_data(as_text=True)
        self.assertIn("ORD-000001", page)
        self.assertIn("本店</span><b>→</b><span>駅前店", page)
        self.assertIn("¥3,680", page)

        response = self.client.get("/received/1")
        page = response.get_data(as_text=True)
        self.assertIn("受注内容", page)
        self.assertIn("2.5 kg", page)
        self.assertIn("4 個", page)

        connection = sqlite3.connect(self.database)
        self.assertEqual(connection.execute("SELECT COUNT(*) FROM orders").fetchone()[0], 1)
        self.assertEqual(connection.execute("SELECT COUNT(*) FROM order_items").fetchone()[0], 2)
        connection.close()

    def test_rejects_same_store(self):
        response = self.client.post(
            "/order/start",
            data={"from_store_id": 1, "to_store_id": 1},
            follow_redirects=True,
        )
        self.assertIn("別々の店舗", response.get_data(as_text=True))

    def test_rejects_empty_cart(self):
        self.client.post("/order/start", data={"from_store_id": 1, "to_store_id": 2})
        response = self.client.post("/cart", data={}, follow_redirects=True)
        self.assertIn("1つ以上入力", response.get_data(as_text=True))

    def test_store_add_pause_resume_and_order_screen_linkage(self):
        response = self.client.post(
            "/stores", data={"name": "南口店"}, follow_redirects=True
        )
        self.assertIn("南口店", response.get_data(as_text=True))

        connection = sqlite3.connect(self.database)
        store_id = connection.execute(
            "SELECT id FROM stores WHERE name = ?", ("南口店",)
        ).fetchone()[0]
        connection.close()

        page = self.client.get("/").get_data(as_text=True)
        self.assertIn("南口店", page)

        self.client.post(f"/stores/{store_id}/toggle")
        page = self.client.get("/").get_data(as_text=True)
        self.assertNotIn(">南口店</option>", page)
        management = self.client.get("/stores").get_data(as_text=True)
        self.assertIn("南口店", management)
        self.assertIn("停止中", management)

        self.client.post(f"/stores/{store_id}/toggle")
        page = self.client.get("/").get_data(as_text=True)
        self.assertIn("南口店", page)

    def test_store_edit_and_soft_delete_preserves_order_history(self):
        self.client.post("/order/start", data={"from_store_id": 1, "to_store_id": 2})
        self.client.post("/cart", data={"quantity_1": "1"})
        self.client.post("/order/submit")

        self.client.post("/stores/2/edit", data={"name": "駅東店"})
        self.assertIn("駅東店", self.client.get("/").get_data(as_text=True))
        self.client.post("/stores/2/delete")
        self.assertNotIn(
            ">駅東店</option>", self.client.get("/").get_data(as_text=True)
        )
        detail = self.client.get("/received/1").get_data(as_text=True)
        self.assertIn("駅東店", detail)

        connection = sqlite3.connect(self.database)
        self.assertEqual(connection.execute("SELECT COUNT(*) FROM orders").fetchone()[0], 1)
        self.assertEqual(
            connection.execute("SELECT is_deleted FROM stores WHERE id = 2").fetchone()[0], 1
        )
        connection.close()

    def place_single_item_order(self, quantity="10"):
        self.client.post("/order/start", data={"from_store_id": 1, "to_store_id": 2})
        self.client.post("/cart", data={"quantity_3": quantity})
        self.client.post("/order/submit")
        connection = sqlite3.connect(self.database)
        order_id = connection.execute("SELECT MAX(id) FROM orders").fetchone()[0]
        item_id = connection.execute(
            "SELECT id FROM order_items WHERE order_id = ?", (order_id,)
        ).fetchone()[0]
        connection.close()
        return order_id, item_id

    def test_1_exact_match_completes_without_sender_approval(self):
        order_id, item_id = self.place_single_item_order("10")

        page = self.client.get(f"/receipts/{order_id}").get_data(as_text=True)
        self.assertIn("発注数量 <strong>10 個", page)
        self.assertIn('value="10"', page)

        response = self.client.post(
            f"/receipts/{order_id}",
            data={f"received_quantity_{item_id}": "10"},
            follow_redirects=True,
        )
        page = response.get_data(as_text=True)
        self.assertIn("受取完了", page)
        self.assertIn("実際に届いた数量", page)
        self.assertIn("10 個", page)

        connection = sqlite3.connect(self.database)
        order = connection.execute(
            "SELECT status, received_at FROM orders WHERE id = ?", (order_id,)
        ).fetchone()
        item = connection.execute(
            """SELECT quantity, received_quantity, final_received_quantity
               FROM order_items WHERE order_id = ?""", (order_id,)
        ).fetchone()
        self.assertEqual(order[0], "received")
        self.assertIsNotNone(order[1])
        self.assertEqual(item, (10.0, 10.0, 10.0))
        connection.close()

    def test_2_less_quantity_requires_sender_approval(self):
        order_id, item_id = self.place_single_item_order("10")
        response = self.client.post(
            f"/receipts/{order_id}",
            data={f"received_quantity_{item_id}": "8"},
            follow_redirects=True,
        )
        page = response.get_data(as_text=True)
        self.assertIn("送付元の確認待ち", page)
        self.assertIn("発注数量 <strong>10 個", page)
        self.assertIn("8 個", page)

        sender_page = self.client.get(f"/received/{order_id}").get_data(as_text=True)
        self.assertIn("差異を承認する", sender_page)
        self.client.post(f"/received/{order_id}/approve")
        history = self.client.get(f"/received/{order_id}").get_data(as_text=True)
        self.assertIn("発注数量", history)
        self.assertIn("最終受取数量", history)
        self.assertIn("10 個", history)
        self.assertIn("8 個", history)

        connection = sqlite3.connect(self.database)
        item = connection.execute(
            """SELECT quantity, received_quantity, final_received_quantity
               FROM order_items WHERE order_id = ?""", (order_id,)
        ).fetchone()
        status = connection.execute(
            "SELECT status FROM orders WHERE id = ?", (order_id,)
        ).fetchone()[0]
        self.assertEqual(item, (10.0, 8.0, 8.0))
        self.assertEqual(status, "received")
        connection.close()

    def test_3_more_quantity_requires_sender_approval(self):
        order_id, item_id = self.place_single_item_order("10")
        self.client.post(
            f"/receipts/{order_id}", data={f"received_quantity_{item_id}": "12"}
        )
        connection = sqlite3.connect(self.database)
        before = connection.execute(
            """SELECT o.status, i.quantity, i.received_quantity, i.final_received_quantity
               FROM orders o JOIN order_items i ON i.order_id = o.id WHERE o.id = ?""",
            (order_id,),
        ).fetchone()
        self.assertEqual(before, ("pending_sender_approval", 10.0, 12.0, None))
        connection.close()
        self.client.post(f"/received/{order_id}/approve")
        connection = sqlite3.connect(self.database)
        after = connection.execute(
            "SELECT quantity, received_quantity, final_received_quantity FROM order_items WHERE order_id = ?",
            (order_id,),
        ).fetchone()
        self.assertEqual(after, (10.0, 12.0, 12.0))
        connection.close()

    def test_4_unexpected_item_return_full_lifecycle(self):
        order_id, item_id = self.place_single_item_order("10")
        self.client.post(f"/receipts/{order_id}", data={
            f"received_quantity_{item_id}": "10",
            "unexpected_product_0": "6",
            "unexpected_quantity_0": "1",
            "unexpected_decision_0": "return",
        })
        connection = sqlite3.connect(self.database)
        extra = connection.execute(
            "SELECT id, status, final_received_quantity FROM unexpected_items WHERE order_id = ?",
            (order_id,),
        ).fetchone()
        order_status = connection.execute(
            "SELECT status FROM orders WHERE id = ?", (order_id,)
        ).fetchone()[0]
        self.assertEqual(extra[1:], ("return_pending", 0.0))
        self.assertEqual(order_status, "received")
        extra_id = extra[0]
        connection.close()

        sender_page = self.client.get(f"/received/{order_id}").get_data(as_text=True)
        self.assertIn("注文外商品", sender_page)
        self.assertIn("返品予定", sender_page)
        self.client.post(f"/receipts/{order_id}/unexpected/{extra_id}/returned")
        self.client.post(f"/received/{order_id}/unexpected/{extra_id}/complete-return")
        connection = sqlite3.connect(self.database)
        status = connection.execute(
            "SELECT status FROM unexpected_items WHERE id = ?", (extra_id,)
        ).fetchone()[0]
        self.assertEqual(status, "return_complete")
        connection.close()

    def test_5_unexpected_item_accept_requires_sender_approval(self):
        order_id, item_id = self.place_single_item_order("10")
        self.client.post(f"/receipts/{order_id}", data={
            f"received_quantity_{item_id}": "10",
            "unexpected_product_0": "6",
            "unexpected_quantity_0": "1",
            "unexpected_decision_0": "accept",
        })
        connection = sqlite3.connect(self.database)
        before = connection.execute(
            "SELECT status, final_received_quantity FROM unexpected_items WHERE order_id = ?",
            (order_id,),
        ).fetchone()
        self.assertEqual(before, ("accept_pending", None))
        connection.close()
        self.client.post(f"/received/{order_id}/approve")
        connection = sqlite3.connect(self.database)
        after = connection.execute(
            "SELECT status, arrived_quantity, final_received_quantity FROM unexpected_items WHERE order_id = ?",
            (order_id,),
        ).fetchone()
        self.assertEqual(after, ("accepted", 1.0, 1.0))
        connection.close()

    def test_6_quantity_difference_and_unexpected_item_together(self):
        order_id, item_id = self.place_single_item_order("10")
        self.client.post(f"/receipts/{order_id}", data={
            f"received_quantity_{item_id}": "8",
            "unexpected_product_0": "6",
            "unexpected_quantity_0": "2",
            "unexpected_decision_0": "accept",
        })
        sender_page = self.client.get(f"/received/{order_id}").get_data(as_text=True)
        self.assertIn("数量差異", sender_page)
        self.assertIn("注文外商品", sender_page)
        self.assertIn("承認待ち", sender_page)
        self.client.post(f"/received/{order_id}/approve")

        connection = sqlite3.connect(self.database)
        ordered = connection.execute(
            "SELECT quantity, received_quantity, final_received_quantity FROM order_items WHERE order_id = ?",
            (order_id,),
        ).fetchone()
        unexpected = connection.execute(
            "SELECT arrived_quantity, status, final_received_quantity FROM unexpected_items WHERE order_id = ?",
            (order_id,),
        ).fetchone()
        order_status = connection.execute(
            "SELECT status FROM orders WHERE id = ?", (order_id,)
        ).fetchone()[0]
        self.assertEqual(ordered, (10.0, 8.0, 8.0))
        self.assertEqual(unexpected, (2.0, "accepted", 2.0))
        self.assertEqual(order_status, "received")
        connection.close()

    def test_dashboard_difference_moves_pending_to_approved(self):
        order_id, item_id = self.place_single_item_order("10")
        top = self.client.get("/").get_data(as_text=True)
        self.assertIn('id="status-orders" data-count="1"', top)
        self.assertIn('id="status-pending" data-count="1"', top)

        self.client.post(
            f"/receipts/{order_id}", data={f"received_quantity_{item_id}": "8"}
        )
        pending = self.client.get("/status/pending").get_data(as_text=True)
        self.assertIn("発注元の数量差異承認待ち", pending)
        self.assertIn("本店 → 駅前店", pending)
        self.assertIn("発注 <strong>10 個", pending)
        self.assertIn("受取 <strong>8 個", pending)
        self.assertIn("次に処理する店舗", pending)
        self.assertIn("駅前店", pending)

        self.client.post(f"/received/{order_id}/approve")
        top = self.client.get("/").get_data(as_text=True)
        self.assertIn('id="status-receipts" data-count="1"', top)
        self.assertIn('id="status-approved" data-count="1"', top)
        self.assertIn('id="status-pending" data-count="0"', top)
        approved = self.client.get("/status/approved").get_data(as_text=True)
        self.assertIn("ORD-000001", approved)

    def test_dashboard_return_stays_pending_until_sender_confirms(self):
        order_id, item_id = self.place_single_item_order("10")
        self.client.post(f"/receipts/{order_id}", data={
            f"received_quantity_{item_id}": "10",
            "unexpected_product_0": "6",
            "unexpected_quantity_0": "1",
            "unexpected_decision_0": "return",
        })
        connection = sqlite3.connect(self.database)
        extra_id = connection.execute(
            "SELECT id FROM unexpected_items WHERE order_id = ?", (order_id,)
        ).fetchone()[0]
        connection.close()

        top = self.client.get("/").get_data(as_text=True)
        self.assertIn('id="status-approved" data-count="0"', top)
        self.assertIn('id="status-pending" data-count="1"', top)
        pending = self.client.get("/status/pending").get_data(as_text=True)
        self.assertIn("受取店舗の返品処理待ち", pending)
        self.assertIn("本店", pending)

        self.client.post(f"/receipts/{order_id}/unexpected/{extra_id}/returned")
        pending = self.client.get("/status/pending").get_data(as_text=True)
        self.assertIn("発注元の返品確認待ち", pending)
        self.assertIn("駅前店", pending)

        self.client.post(f"/received/{order_id}/unexpected/{extra_id}/complete-return")
        top = self.client.get("/").get_data(as_text=True)
        self.assertIn('id="status-pending" data-count="0"', top)
        self.assertIn('id="status-approved" data-count="1"', top)

    def test_category_unit_photo_product_order_cart_and_receipt_flow(self):
        self.client.post("/categories/add", data={"level": "1", "name": "肉"})
        connection = sqlite3.connect(self.database)
        major_id = connection.execute(
            "SELECT id FROM product_categories WHERE name = '肉' AND level = 1"
        ).fetchone()[0]
        connection.close()

        self.client.post("/categories/add", data={
            "level": "2", "parent_id": str(major_id), "name": "牛",
        })
        self.client.post("/units/add", data={"name": "ケース"})
        connection = sqlite3.connect(self.database)
        subcategory_id = connection.execute(
            "SELECT id FROM product_categories WHERE name = '牛' AND parent_id = ?",
            (major_id,),
        ).fetchone()[0]
        unit_id = connection.execute(
            "SELECT id FROM units WHERE name = 'ケース'"
        ).fetchone()[0]
        connection.close()

        fake_png = b"\x89PNG\r\n\x1a\n" + b"test-image-data"
        response = self.client.post(
            "/product-management/new",
            data={
                "major_category_id": str(major_id),
                "subcategory_id": str(subcategory_id),
                "name": "牛タン",
                "unit_id": str(unit_id),
                "unit_price": "3500",
                "image": (BytesIO(fake_png), "gyutan.png"),
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        page = response.get_data(as_text=True)
        self.assertIn("牛タン", page)
        self.assertIn("肉 / 牛", page)
        self.assertIn("¥3,500", page)

        connection = sqlite3.connect(self.database)
        product = connection.execute(
            """SELECT id, unit, unit_price, image_filename FROM products
               WHERE name = '牛タン'"""
        ).fetchone()
        connection.close()
        product_id, unit_name, price, image_filename = product
        self.assertEqual((unit_name, price), ("ケース", 3500))
        self.assertTrue((Path(self.temp_dir.name) / "uploads" / image_filename).exists())

        self.client.post("/order/start", data={"from_store_id": 1, "to_store_id": 2})
        order_page = self.client.get("/products").get_data(as_text=True)
        self.assertIn("牛タン", order_page)
        self.assertIn("肉 / 牛", order_page)
        self.assertIn(f"product-images/{image_filename}", order_page)
        image_response = self.client.get(f"/product-images/{image_filename}")
        self.assertEqual(image_response.status_code, 200)
        image_response.close()

        cart = self.client.post(
            "/cart", data={f"quantity_{product_id}": "3"}, follow_redirects=True
        ).get_data(as_text=True)
        self.assertIn("3 ケース", cart)
        self.assertIn("¥10,500", cart)
        self.client.post("/order/submit")

        connection = sqlite3.connect(self.database)
        order_id = connection.execute("SELECT MAX(id) FROM orders").fetchone()[0]
        item = connection.execute(
            "SELECT id, quantity, unit_price FROM order_items WHERE order_id = ?",
            (order_id,),
        ).fetchone()
        connection.close()
        self.assertEqual(item[1:], (3.0, 3500))

        received = self.client.post(
            f"/receipts/{order_id}",
            data={f"received_quantity_{item[0]}": "3"},
            follow_redirects=True,
        ).get_data(as_text=True)
        self.assertIn("受取完了", received)
        self.assertIn("¥10,500", received)

    def test_category_unit_and_product_management_actions(self):
        self.client.post("/categories/add", data={"level": "1", "name": "魚"})
        connection = sqlite3.connect(self.database)
        category_id = connection.execute(
            "SELECT id FROM product_categories WHERE name = '魚'"
        ).fetchone()[0]
        connection.close()
        self.client.post(f"/categories/{category_id}/edit", data={"name": "鮮魚"})
        self.client.post(f"/categories/{category_id}/toggle")
        self.client.post(f"/categories/{category_id}/toggle")
        self.client.post(f"/categories/{category_id}/delete")

        self.client.post("/units/add", data={"name": "箱"})
        connection = sqlite3.connect(self.database)
        unit_id = connection.execute("SELECT id FROM units WHERE name = '箱'").fetchone()[0]
        connection.close()
        self.client.post(f"/units/{unit_id}/edit", data={"name": "大箱"})
        self.client.post(f"/units/{unit_id}/toggle")
        self.client.post(f"/units/{unit_id}/toggle")
        self.client.post(f"/units/{unit_id}/delete")

        self.client.post("/product-management/3/edit", data={
            "major_category_id": "1", "subcategory_id": "2",
            "name": "ミニトマト", "unit_id": "2", "unit_price": "130",
        })
        self.client.post("/product-management/3/toggle")
        self.client.post("/order/start", data={"from_store_id": 1, "to_store_id": 2})
        self.assertNotIn(
            "<h2>ミニトマト</h2>", self.client.get("/products").get_data(as_text=True)
        )
        self.client.post("/product-management/3/toggle")
        self.assertIn(
            "<h2>ミニトマト</h2>", self.client.get("/products").get_data(as_text=True)
        )

        connection = sqlite3.connect(self.database)
        category = connection.execute(
            "SELECT name, is_deleted FROM product_categories WHERE id = ?", (category_id,)
        ).fetchone()
        unit = connection.execute(
            "SELECT name, is_deleted FROM units WHERE id = ?", (unit_id,)
        ).fetchone()
        product = connection.execute(
            "SELECT name, unit_price, is_active FROM products WHERE id = 3"
        ).fetchone()
        self.assertEqual(category, ("鮮魚", 1))
        self.assertEqual(unit, ("大箱", 1))
        self.assertEqual(product, ("ミニトマト", 130, 1))
        connection.close()

    def test_login_accounts_store_scoping_and_approval_flow(self):
        # 1. 管理者ログイン（初期管理者はsetUpで一度だけ作成済み）
        self.client.post("/logout")
        response = self.client.post("/login", data={
            "login_id": "admin", "password": "admin-pass-123",
        }, follow_redirects=True)
        self.assertIn("ログイン中：<strong>管理者", response.get_data(as_text=True))
        self.assertEqual(self.client.get("/setup").status_code, 302)

        # 2. 管理者が既存3店舗のアカウントを作成
        for store_id, login_id in ((1, "honten"), (2, "ekimae"), (3, "chuo")):
            response = self.client.post("/accounts", data={
                "store_id": str(store_id), "login_id": login_id,
                "password": f"{login_id}-pass-123",
            }, follow_redirects=True)
            self.assertEqual(response.status_code, 200)
        connection = sqlite3.connect(self.database)
        users = connection.execute(
            "SELECT login_id, password_hash FROM users WHERE role = 'store' ORDER BY store_id"
        ).fetchall()
        self.assertEqual([row[0] for row in users], ["honten", "ekimae", "chuo"])
        self.assertTrue(all("pass-123" not in row[1] for row in users))
        connection.close()

        # 3–5. 本店でログインし、改ざんしたfrom_store_idを無視して駅前店へ発注
        self.client.post("/logout")
        response = self.client.post("/login", data={
            "login_id": "honten", "password": "honten-pass-123",
        }, follow_redirects=True)
        page = response.get_data(as_text=True)
        self.assertIn("ログイン中：<strong>本店", page)
        self.assertIn("本店（ログイン店舗）", page)
        self.client.post("/order/start", data={"from_store_id": "3", "to_store_id": "2"})
        with self.client.session_transaction() as login_session:
            self.assertEqual(login_session["order_context"]["from_store_id"], 1)
            self.assertEqual(login_session["order_context"]["to_store_id"], 2)
        self.client.post("/cart", data={"quantity_3": "10"})
        self.client.post("/order/submit")
        connection = sqlite3.connect(self.database)
        order_id, item_id, from_id, to_id = connection.execute(
            """SELECT o.id, oi.id, o.from_store_id, o.to_store_id
               FROM orders o JOIN order_items oi ON oi.order_id = o.id
               ORDER BY o.id DESC LIMIT 1"""
        ).fetchone()
        self.assertEqual((from_id, to_id), (1, 2))
        connection.close()

        # 6. 発注先（駅前店）は自店舗に届いた発注だけを確認できる
        self.client.post("/logout")
        self.client.post("/login", data={
            "login_id": "ekimae", "password": "ekimae-pass-123",
        })
        incoming = self.client.get("/status/receipts").get_data(as_text=True)
        self.assertIn(f"ORD-{order_id:06d}", incoming)
        self.assertNotIn("未承認", incoming)

        # 6–7. 発注先（駅前店）が受取詳細から数量差異を報告
        receipt_result = self.client.post(
            f"/receipts/{order_id}", data={f"received_quantity_{item_id}": "8"}
        )
        self.assertEqual(receipt_result.status_code, 302)
        receipt_list = self.client.get("/status/receipts").get_data(as_text=True)
        self.assertIn(f"ORD-{order_id:06d}", receipt_list)
        self.assertIn("相手店舗の処理待ち", receipt_list)

        # 受取側が発注元の承認操作を行うことは拒否
        forged_approval = self.client.post(f"/received/{order_id}/approve")
        self.assertEqual(forged_approval.status_code, 403)

        # 8. 発注元（本店）の発注一覧に要対応として現れ、承認できる
        self.client.post("/logout")
        self.client.post("/login", data={
            "login_id": "honten", "password": "honten-pass-123",
        })
        order_list = self.client.get("/status/orders").get_data(as_text=True)
        self.assertIn(f"ORD-{order_id:06d}", order_list)
        self.assertIn("要確認", order_list)
        self.assertEqual(self.client.get("/status/pending").status_code, 302)
        self.client.post(f"/received/{order_id}/approve")
        approved = self.client.get("/status/approved").get_data(as_text=True)
        self.assertIn(f"ORD-{order_id:06d}", approved)

        # 9. 店舗ユーザーは管理者画面へ入れない
        for path in ("/stores", "/product-management", "/categories", "/units", "/accounts"):
            self.assertEqual(self.client.get(path).status_code, 403)

        # 10. 無関係な中央店は閲覧も処理もできない
        self.client.post("/logout")
        self.client.post("/login", data={
            "login_id": "chuo", "password": "chuo-pass-123",
        })
        self.assertEqual(self.client.get(f"/received/{order_id}").status_code, 403)
        self.assertEqual(self.client.get(f"/receipts/{order_id}").status_code, 403)
        self.assertNotIn(f"ORD-{order_id:06d}", self.client.get("/status/orders").get_data(as_text=True))

        # 11. ログアウト後は業務画面へアクセスできない
        self.client.post("/logout")
        response = self.client.get("/", follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith("/login"))

    def test_admin_can_reset_pause_account_and_store_pause_blocks_login(self):
        self.client.post("/accounts", data={
            "store_id": "1", "login_id": "honten-old",
            "password": "old-password-123",
        })
        connection = sqlite3.connect(self.database)
        user_id, old_hash = connection.execute(
            "SELECT id, password_hash FROM users WHERE store_id = 1"
        ).fetchone()
        connection.close()

        self.client.post(f"/accounts/{user_id}/edit", data={
            "login_id": "honten-new", "password": "new-password-456",
        })
        connection = sqlite3.connect(self.database)
        login_id, new_hash = connection.execute(
            "SELECT login_id, password_hash FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        self.assertEqual(login_id, "honten-new")
        self.assertNotEqual(old_hash, new_hash)
        connection.close()

        self.client.post(f"/accounts/{user_id}/toggle")
        self.client.post("/logout")
        failed = self.client.post("/login", data={
            "login_id": "honten-new", "password": "new-password-456",
        }, follow_redirects=True)
        self.assertIn("ログインIDまたはパスワード", failed.get_data(as_text=True))

        self.client.post("/login", data={
            "login_id": "admin", "password": "admin-pass-123",
        })
        self.client.post(f"/accounts/{user_id}/toggle")
        self.client.post("/stores/1/toggle")
        self.client.post("/logout")
        stopped_store = self.client.post("/login", data={
            "login_id": "honten-new", "password": "new-password-456",
        }, follow_redirects=True)
        self.assertIn("ログインIDまたはパスワード", stopped_store.get_data(as_text=True))

    def test_store_dashboard_scopes_three_transaction_directions(self):
        # 本店用アカウントを管理者として作成する。
        self.client.post("/accounts", data={
            "store_id": "1", "login_id": "honten-scope",
            "password": "honten-scope-pass",
        })

        # 本店→A店、A店→本店、A店→B店を、未完了・承認済の両状態で用意する。
        connection = sqlite3.connect(self.database)
        transactions = [
            ("SCOPE-OUT-P", 1, 2, "ordered"),
            ("SCOPE-IN-P", 2, 1, "ordered"),
            ("SCOPE-OTHER-P", 2, 3, "ordered"),
            ("SCOPE-OUT-A", 1, 2, "received"),
            ("SCOPE-IN-A", 2, 1, "received"),
            ("SCOPE-OTHER-A", 2, 3, "received"),
        ]
        order_ids = {}
        for number, from_id, to_id, status in transactions:
            cursor = connection.execute(
                """INSERT INTO orders
                   (order_number, from_store_id, to_store_id, status,
                    receipt_reported_at, received_at)
                   VALUES (?, ?, ?, ?,
                       CASE WHEN ? = 'received' THEN datetime('now') END,
                       CASE WHEN ? = 'received' THEN datetime('now') END)""",
                (number, from_id, to_id, status, status, status),
            )
            order_ids[number] = cursor.lastrowid
            connection.execute(
                """INSERT INTO order_items
                   (order_id, product_id, product_name, unit, quantity,
                    received_quantity, final_received_quantity, unit_price)
                   VALUES (?, 3, 'トマト', '個', 10,
                       CASE WHEN ? = 'received' THEN 10 END,
                       CASE WHEN ? = 'received' THEN 10 END, 120)""",
                (cursor.lastrowid, status, status),
            )
        connection.commit()
        connection.close()

        self.client.post("/logout")
        self.client.post("/login", data={
            "login_id": "honten-scope", "password": "honten-scope-pass",
        })

        home = self.client.get("/").get_data(as_text=True)
        self.assertIn('id="status-orders"', home)
        self.assertIn('id="status-receipts"', home)
        self.assertIn('id="status-approved"', home)
        self.assertNotIn('id="status-pending"', home)

        pages = {
            name: self.client.get(f"/status/{name}").get_data(as_text=True)
            for name in ("orders", "receipts", "approved")
        }

        # 発注は本店発だけ、受取は本店宛だけ。
        self.assertIn("SCOPE-OUT-P", pages["orders"])
        self.assertIn("SCOPE-OUT-A", pages["orders"])
        self.assertNotIn("SCOPE-IN-P", pages["orders"])
        self.assertNotIn("SCOPE-OTHER-P", pages["orders"])
        self.assertIn("SCOPE-IN-P", pages["receipts"])
        self.assertNotIn("SCOPE-IN-A", pages["receipts"])
        self.assertNotIn("SCOPE-OUT-P", pages["receipts"])
        self.assertNotIn("SCOPE-OTHER-P", pages["receipts"])

        # 承認済は本店がどちら側でも表示し、他店舗間は除外する。
        self.assertIn("SCOPE-OUT-A", pages["approved"])
        self.assertIn("SCOPE-IN-A", pages["approved"])
        self.assertNotIn("SCOPE-OTHER-A", pages["approved"])

        # 未完了状態は発注・受取内に統合され、現在の処理担当を表示する。
        self.assertIn("相手店舗の処理待ち", pages["orders"])
        self.assertIn("要確認", pages["receipts"])
        self.assertNotIn("pending-tab", pages["orders"])
        self.assertEqual(self.client.get("/status/pending").status_code, 302)

        # 無関係なA店→B店はURLを直接指定しても閲覧できない。
        unrelated_id = order_ids["SCOPE-OTHER-P"]
        self.assertEqual(self.client.get(f"/received/{unrelated_id}").status_code, 403)
        self.assertEqual(self.client.get(f"/receipts/{unrelated_id}").status_code, 403)

    def test_sender_receiver_labels_on_admin_and_store_views(self):
        # 承認済案件を1件作る。
        approved_id, approved_item_id = self.place_single_item_order("10")
        self.client.post(
            f"/receipts/{approved_id}",
            data={f"received_quantity_{approved_item_id}": "10"},
        )

        # 数量差異で未承認の案件を1件作る。
        pending_id, pending_item_id = self.place_single_item_order("10")
        self.client.post(
            f"/receipts/{pending_id}",
            data={f"received_quantity_{pending_item_id}": "8"},
        )

        # 管理者の履歴（発注）、承認済、未承認に方向が表示される。
        for category, number in (
            ("orders", f"ORD-{approved_id:06d}"),
            ("approved", f"ORD-{approved_id:06d}"),
            ("pending", f"ORD-{pending_id:06d}"),
        ):
            page = self.client.get(f"/status/{category}").get_data(as_text=True)
            self.assertIn(number, page)
            self.assertIn("本店 → 駅前店", page)

        # 管理者が開く両詳細画面にラベル付き経路を表示する。
        for path in (f"/received/{approved_id}", f"/receipts/{approved_id}"):
            detail = self.client.get(path).get_data(as_text=True)
            self.assertIn("送付元", detail)
            self.assertIn("本店", detail)
            self.assertIn("受取店舗", detail)
            self.assertIn("駅前店", detail)

        # 駅前店アカウントでも、自店舗が関係する受取一覧・詳細に同じ方向を表示。
        self.client.post("/accounts", data={
            "store_id": "2", "login_id": "ekimae-label",
            "password": "ekimae-label-pass",
        })
        self.client.post("/logout")
        self.client.post("/login", data={
            "login_id": "ekimae-label", "password": "ekimae-label-pass",
        })
        receipt_list = self.client.get("/status/receipts").get_data(as_text=True)
        self.assertIn(f"ORD-{pending_id:06d}", receipt_list)
        self.assertIn("本店 → 駅前店", receipt_list)
        detail = self.client.get(f"/receipts/{pending_id}").get_data(as_text=True)
        self.assertIn("送付元", detail)
        self.assertIn("本店", detail)
        self.assertIn("受取店舗", detail)
        self.assertIn("駅前店", detail)

    def test_reporting_corrections_csv_and_store_permissions(self):
        """通常・増減・注文外受取・返品を集計し、訂正と権限を通しで確認する。"""
        flows = []

        # 1. 通常数量、2. 増加、3. 減少
        for received_quantity in (10, 12, 8):
            order_id, item_id = self.place_single_item_order("10")
            self.client.post(
                f"/receipts/{order_id}",
                data={f"received_quantity_{item_id}": str(received_quantity)},
            )
            if received_quantity != 10:
                self.client.post(f"/received/{order_id}/approve")
            flows.append((order_id, item_id))

        # 4. 注文外商品を受け取り、双方で承認
        accepted_order, accepted_item = self.place_single_item_order("10")
        self.client.post(f"/receipts/{accepted_order}", data={
            f"received_quantity_{accepted_item}": "10",
            "unexpected_product_0": "6", "unexpected_quantity_0": "1",
            "unexpected_decision_0": "accept",
        })
        self.client.post(f"/received/{accepted_order}/approve")
        flows.append((accepted_order, accepted_item))

        # 5. 注文外商品を返品し、送付元確認まで完了
        returned_order, returned_item = self.place_single_item_order("10")
        self.client.post(f"/receipts/{returned_order}", data={
            f"received_quantity_{returned_item}": "10",
            "unexpected_product_0": "6", "unexpected_quantity_0": "1",
            "unexpected_decision_0": "return",
        })
        connection = sqlite3.connect(self.database)
        returned_extra = connection.execute(
            "SELECT id FROM unexpected_items WHERE order_id = ?", (returned_order,)
        ).fetchone()[0]
        connection.close()
        self.client.post(f"/receipts/{returned_order}/unexpected/{returned_extra}/returned")
        self.client.post(f"/received/{returned_order}/unexpected/{returned_extra}/complete-return")
        flows.append((returned_order, returned_item))

        # 全案件を同じ対象日に置き、店舗とは無関係な案件も1件加える。
        connection = sqlite3.connect(self.database)
        for index, (order_id, _item_id) in enumerate(flows, start=9):
            connection.execute(
                "UPDATE orders SET created_at = ? WHERE id = ?",
                (f"2026-08-13 {index:02d}:12:00", order_id),
            )
        other = connection.execute(
            """INSERT INTO orders (order_number, from_store_id, to_store_id, status,
               receipt_reported_at, received_at, created_at)
               VALUES ('OTHER-ONLY', 2, 3, 'received', '2026-08-13', '2026-08-13',
                       '2026-08-13 15:00:00')"""
        ).lastrowid
        connection.execute(
            """INSERT INTO order_items
               (order_id, product_id, product_name, unit, quantity, received_quantity,
                final_received_quantity, unit_price, major_category_name, subcategory_name)
               VALUES (?, 3, 'トマト', '個', 4, 4, 4, 120, '野菜', '果菜')""",
            (other,),
        )
        connection.commit()
        connection.close()

        # 6–7. 日別・月次に数量増減、注文外受取を反映し、返品分は最終0。
        daily = self.client.get("/reports/daily?date=2026-08-13").get_data(as_text=True)
        self.assertIn("本店 → 駅前店", daily)
        self.assertIn("注文外", daily)
        self.assertIn("返品完了", daily)
        self.assertIn("12", daily)
        self.assertIn("8", daily)
        monthly = self.client.get("/reports?month=2026-08").get_data(as_text=True)
        self.assertIn("店舗別サマリー", monthly)
        self.assertIn("商品別集計", monthly)
        self.assertIn("¥6,240", monthly)  # 駅前店の訂正前・最終受注額
        store_breakdown = self.client.get("/reports/store/2?month=2026-08").get_data(as_text=True)
        self.assertIn("発注元", store_breakdown)
        self.assertIn("本店", store_breakdown)

        # 8–9. 管理者訂正。元の発注10個は残し、最終15個・単価130円を反映。
        corrected_item = flows[1][1]
        correction = self.client.post(
            f"/reports/correct/order_item/{corrected_item}",
            data={"product_id": "3", "quantity": "15", "unit_price": "130",
                  "reason": "受取伝票の入力値を確認したため"},
            follow_redirects=True,
        )
        self.assertIn("訂正あり", correction.get_data(as_text=True))
        connection = sqlite3.connect(self.database)
        original = connection.execute(
            "SELECT quantity, final_received_quantity, unit_price FROM order_items WHERE id = ?",
            (corrected_item,),
        ).fetchone()
        audit = connection.execute(
            "SELECT reason, before_json, after_json FROM transaction_corrections WHERE line_id = ?",
            (corrected_item,),
        ).fetchone()
        connection.close()
        self.assertEqual(original, (10.0, 12.0, 120))
        self.assertEqual(audit[0], "受取伝票の入力値を確認したため")
        self.assertIn('"quantity": 12.0', audit[1])
        self.assertIn('"quantity": 15.0', audit[2])
        corrected_month = self.client.get("/reports?month=2026-08").get_data(as_text=True)
        self.assertIn("¥6,750", corrected_month)
        history = self.client.get("/reports/corrections").get_data(as_text=True)
        self.assertIn("受取伝票の入力値を確認したため", history)
        self.assertIn("12個", history)
        self.assertIn("15個", history)

        # 10–11. BOM付きCSVは1商品1行。画面とCSVの最終合計が一致。
        response = self.client.get(
            "/reports/csv?direction=receipts&start_date=2026-08-13&end_date=2026-08-13&store_id=2"
        )
        self.assertTrue(response.data.startswith(b"\xef\xbb\xbf"))
        rows = list(csv.DictReader(io.StringIO(response.data.decode("utf-8-sig"))))
        self.assertEqual(sum(int(row["最終金額"] or 0) for row in rows), 6750)
        self.assertTrue(any(row["訂正あり／なし"] == "あり" for row in rows))
        self.assertTrue(all(row["発注先店舗"] == "駅前店" for row in rows))

        # 12–14. 管理者は全件。店舗は自店舗のみで、URLとCSVパラメータも改ざん不可。
        self.assertIn("OTHER-ONLY", daily)
        self.client.post("/accounts", data={
            "store_id": "1", "login_id": "honten-report",
            "password": "honten-report-pass",
        })
        self.client.post("/logout")
        self.client.post("/login", data={
            "login_id": "honten-report", "password": "honten-report-pass",
        })
        scoped_daily = self.client.get(
            "/reports/daily?date=2026-08-13&store_id=3"
        ).get_data(as_text=True)
        self.assertIn("本店 → 駅前店", scoped_daily)
        self.assertNotIn("OTHER-ONLY", scoped_daily)
        self.assertEqual(self.client.get("/reports/store/2?month=2026-08").status_code, 403)
        self.assertEqual(
            self.client.get(f"/reports/correct/order_item/{corrected_item}").status_code, 403
        )
        scoped_csv = self.client.get(
            "/reports/csv?direction=orders&start_date=2026-08-13&end_date=2026-08-13&store_id=3"
        )
        scoped_rows = list(csv.DictReader(io.StringIO(scoped_csv.data.decode("utf-8-sig"))))
        self.assertTrue(scoped_rows)
        self.assertTrue(all(row["発注元店舗"] == "本店" for row in scoped_rows))
        self.assertFalse(any(row["発注番号"] == "OTHER-ONLY" for row in scoped_rows))


if __name__ == "__main__":
    unittest.main()
