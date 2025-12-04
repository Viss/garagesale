#!/usr/bin/env python3
"""Reset admin password to 'admin'"""

import sqlite3
from werkzeug.security import generate_password_hash

# Connect to database
db = sqlite3.connect('garagesale.db')
cursor = db.cursor()

# Generate hash for 'admin'
password_hash = generate_password_hash('admin')

# Update the password
cursor.execute(
    "INSERT OR REPLACE INTO config (key, value) VALUES ('admin_password', ?)",
    (password_hash,)
)

db.commit()
db.close()

print("Admin password has been reset to: admin")
print("Please change this immediately after logging in!")
