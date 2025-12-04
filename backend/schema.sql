-- Listings table
CREATE TABLE IF NOT EXISTS listings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    price REAL NOT NULL,
    payment_methods TEXT NOT NULL,  -- JSON array of enabled payment methods
    sold INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Images table
CREATE TABLE IF NOT EXISTS images (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    listing_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    sort_order INTEGER DEFAULT 0,
    FOREIGN KEY (listing_id) REFERENCES listings(id)
);

-- Config table for settings
CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Insert default admin password (change this!)
INSERT OR IGNORE INTO config (key, value) VALUES ('admin_password', 'scrypt:32768:8:1$NE7uiVdPTyJVhvZY$7c00b3231c09cfa68e8d21163bef306be835cf74144ea8f1453a7a366b8a8a2bf8990ea0e8d7fb2e4f87d78b7f2de80c8515d6119b0c8fdfeea72365a50834f3');
-- Default password is 'admin' - CHANGE THIS in the admin settings!
