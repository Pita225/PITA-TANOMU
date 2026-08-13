INSERT INTO stores (name) VALUES
    ('本店'),
    ('駅前店'),
    ('中央店');

INSERT INTO product_categories (name, level) VALUES ('未分類', 1);
INSERT INTO product_categories (name, level, parent_id) VALUES ('未分類', 2, 1);

INSERT INTO units (name) VALUES ('kg'), ('個'), ('本'), ('袋');

INSERT INTO products
    (name, major_category_id, subcategory_id, unit_id, unit, unit_price, display_order)
VALUES
    ('国産鶏もも肉', 1, 2, 1, 'kg', 1280, 10),
    ('玉ねぎ', 1, 2, 1, 'kg', 350, 20),
    ('トマト', 1, 2, 2, '個', 120, 30),
    ('食パン', 1, 2, 3, '本', 420, 40),
    ('紙ナプキン', 1, 2, 4, '袋', NULL, 50),
    ('牛乳', 1, 2, 3, '本', 240, 60);
