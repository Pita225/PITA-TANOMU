DROP TABLE IF EXISTS order_items;
DROP TABLE IF EXISTS unexpected_items;
DROP TABLE IF EXISTS transaction_corrections;
DROP TABLE IF EXISTS orders;
DROP TABLE IF EXISTS products;
DROP TABLE IF EXISTS units;
DROP TABLE IF EXISTS product_categories;
DROP TABLE IF EXISTS admin_recovery_tokens;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS stores;

CREATE TABLE stores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    environment TEXT NOT NULL DEFAULT 'production'
        CHECK (environment IN ('production', 'training')),
    is_active INTEGER NOT NULL DEFAULT 1,
    is_deleted INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE users (
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
    CHECK ((role = 'admin' AND store_id IS NULL) OR (role = 'store' AND store_id IS NOT NULL))
);

CREATE TABLE admin_recovery_tokens (
    token_hash TEXT PRIMARY KEY,
    used_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);

CREATE TABLE product_categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    level INTEGER NOT NULL,
    parent_id INTEGER,
    environment TEXT NOT NULL DEFAULT 'production'
        CHECK (environment IN ('production', 'training')),
    is_active INTEGER NOT NULL DEFAULT 1,
    is_deleted INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (parent_id) REFERENCES product_categories (id),
    CHECK (level IN (1, 2)),
    CHECK ((level = 1 AND parent_id IS NULL) OR (level = 2 AND parent_id IS NOT NULL))
);

CREATE TABLE units (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    environment TEXT NOT NULL DEFAULT 'production'
        CHECK (environment IN ('production', 'training')),
    decimal_places INTEGER NOT NULL DEFAULT 0 CHECK (decimal_places BETWEEN 0 AND 2),
    is_active INTEGER NOT NULL DEFAULT 1,
    is_deleted INTEGER NOT NULL DEFAULT 0,
    UNIQUE (name, environment)
);

CREATE TABLE products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    major_category_id INTEGER NOT NULL,
    subcategory_id INTEGER NOT NULL,
    unit_id INTEGER NOT NULL,
    unit TEXT NOT NULL,
    unit_price INTEGER,
    image_filename TEXT,
    environment TEXT NOT NULL DEFAULT 'production'
        CHECK (environment IN ('production', 'training')),
    source_product_id INTEGER,
    display_order INTEGER NOT NULL DEFAULT 0,
    is_active INTEGER NOT NULL DEFAULT 1,
    is_deleted INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (major_category_id) REFERENCES product_categories (id),
    FOREIGN KEY (subcategory_id) REFERENCES product_categories (id),
    FOREIGN KEY (unit_id) REFERENCES units (id),
    FOREIGN KEY (source_product_id) REFERENCES products (id),
    CHECK (unit_price IS NULL OR unit_price >= 0)
);

CREATE TABLE orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_number TEXT UNIQUE,
    from_store_id INTEGER NOT NULL,
    to_store_id INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    status TEXT NOT NULL DEFAULT 'ordered',
    receipt_reported_at TEXT,
    received_at TEXT,
    sender_approved_at TEXT,
    FOREIGN KEY (from_store_id) REFERENCES stores (id),
    FOREIGN KEY (to_store_id) REFERENCES stores (id),
    CHECK (from_store_id <> to_store_id)
);

CREATE TABLE order_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    product_name TEXT NOT NULL,
    unit TEXT NOT NULL,
    quantity REAL NOT NULL,
    quantity_minor INTEGER,
    quantity_decimal_places INTEGER NOT NULL DEFAULT 0 CHECK (quantity_decimal_places BETWEEN 0 AND 2),
    received_quantity REAL,
    received_quantity_minor INTEGER,
    final_received_quantity REAL,
    final_received_quantity_minor INTEGER,
    unit_price INTEGER,
    major_category_name TEXT,
    subcategory_name TEXT,
    FOREIGN KEY (order_id) REFERENCES orders (id) ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES products (id),
    CHECK (quantity > 0)
);

CREATE INDEX idx_orders_to_store ON orders (to_store_id, created_at DESC);
CREATE INDEX idx_order_items_order ON order_items (order_id);

CREATE TABLE unexpected_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    product_name TEXT NOT NULL,
    unit TEXT NOT NULL,
    arrived_quantity REAL NOT NULL,
    arrived_quantity_minor INTEGER,
    quantity_decimal_places INTEGER NOT NULL DEFAULT 0 CHECK (quantity_decimal_places BETWEEN 0 AND 2),
    decision TEXT NOT NULL,
    status TEXT NOT NULL,
    final_received_quantity REAL,
    final_received_quantity_minor INTEGER,
    unit_price INTEGER,
    major_category_name TEXT,
    subcategory_name TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    FOREIGN KEY (order_id) REFERENCES orders (id) ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES products (id),
    CHECK (arrived_quantity > 0),
    CHECK (decision IN ('return', 'accept')),
    CHECK (status IN ('return_pending', 'returned', 'return_complete', 'accept_pending', 'accepted'))
);

CREATE INDEX idx_unexpected_items_order ON unexpected_items (order_id);

CREATE TABLE transaction_corrections (
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
    corrected_quantity_minor INTEGER,
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
);

CREATE INDEX idx_corrections_line ON transaction_corrections (line_type, line_id, id DESC);
CREATE INDEX idx_corrections_order ON transaction_corrections (order_id, id DESC);

CREATE TRIGGER fill_order_item_quantity_minor AFTER INSERT ON order_items
WHEN NEW.quantity_minor IS NULL BEGIN
    UPDATE order_items SET quantity_minor = CAST(ROUND(NEW.quantity * 100) AS INTEGER),
        received_quantity_minor = CASE WHEN NEW.received_quantity IS NULL THEN NULL ELSE CAST(ROUND(NEW.received_quantity * 100) AS INTEGER) END,
        final_received_quantity_minor = CASE WHEN NEW.final_received_quantity IS NULL THEN NULL ELSE CAST(ROUND(NEW.final_received_quantity * 100) AS INTEGER) END
    WHERE id = NEW.id;
END;

CREATE TRIGGER fill_unexpected_quantity_minor AFTER INSERT ON unexpected_items
WHEN NEW.arrived_quantity_minor IS NULL BEGIN
    UPDATE unexpected_items SET arrived_quantity_minor = CAST(ROUND(NEW.arrived_quantity * 100) AS INTEGER),
        final_received_quantity_minor = CASE WHEN NEW.final_received_quantity IS NULL THEN NULL ELSE CAST(ROUND(NEW.final_received_quantity * 100) AS INTEGER) END
    WHERE id = NEW.id;
END;

CREATE TRIGGER fill_correction_quantity_minor AFTER INSERT ON transaction_corrections
WHEN NEW.corrected_quantity_minor IS NULL BEGIN
    UPDATE transaction_corrections SET corrected_quantity_minor = CAST(ROUND(NEW.corrected_quantity * 100) AS INTEGER)
    WHERE id = NEW.id;
END;

CREATE TABLE audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    user_id INTEGER NOT NULL,
    user_login_id TEXT NOT NULL,
    store_id INTEGER,
    store_name TEXT,
    order_id INTEGER,
    order_number TEXT,
    event_type TEXT NOT NULL,
    product_name TEXT,
    quantity_minor INTEGER,
    before_json TEXT,
    after_json TEXT,
    approval_status TEXT,
    environment TEXT NOT NULL CHECK (environment IN ('production', 'training')),
    snapshot_path TEXT,
    FOREIGN KEY (user_id) REFERENCES users (id),
    FOREIGN KEY (store_id) REFERENCES stores (id),
    FOREIGN KEY (order_id) REFERENCES orders (id)
);

CREATE INDEX idx_audit_events_search
    ON audit_events (store_id, occurred_at, event_type, order_id);
