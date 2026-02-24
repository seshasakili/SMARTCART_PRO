-- =========================
-- USERS TABLE
-- =========================
CREATE TABLE IF NOT EXISTS users (
 user_id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 email TEXT UNIQUE NOT NULL,
 password BLOB NOT NULL,
 profile_image TEXT DEFAULT 'default.png'
);

-- =========================
-- ADMIN TABLE
-- =========================
CREATE TABLE IF NOT EXISTS admin (
 admin_id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 email TEXT UNIQUE NOT NULL,
 password BLOB NOT NULL,
 profile_image TEXT DEFAULT 'default.png',
 reset_token TEXT,
 reset_token_expiry TEXT
);

-- =========================
-- PRODUCTS TABLE
-- =========================
CREATE TABLE IF NOT EXISTS products (
 product_id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 description TEXT,
 price REAL NOT NULL,
 image TEXT,
 category TEXT,
 stock INTEGER DEFAULT 0
);

-- =========================
-- ORDERS TABLE
-- =========================
CREATE TABLE IF NOT EXISTS orders (
 order_id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER,
 delivery_address TEXT,
 city TEXT,
 state TEXT,
 pincode TEXT,
 razorpay_order_id TEXT,
 razorpay_payment_id TEXT,
 amount REAL,
 payment_status TEXT,
 order_status TEXT DEFAULT 'Pending',
 created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- =========================
-- ORDER ITEMS TABLE
-- =========================
CREATE TABLE IF NOT EXISTS order_items (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 order_id INTEGER,
 product_id INTEGER,
 product_name TEXT,
 quantity INTEGER,
 price REAL,
 FOREIGN KEY (order_id) REFERENCES orders(order_id),
 FOREIGN KEY (product_id) REFERENCES products(product_id)
);

-- =========================
-- USER ADDRESSES TABLE
-- =========================
CREATE TABLE IF NOT EXISTS user_addresses (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER,
 full_name TEXT,
 phone TEXT,
 address TEXT,
 city TEXT,
 state TEXT,
 country TEXT,
 pincode TEXT,
 FOREIGN KEY (user_id) REFERENCES users(user_id)
);