import sqlite3
import os
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "database", "app.db")

def get_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            full_name TEXT NOT NULL,
            scans_remaining INTEGER DEFAULT 100,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def get_user_by_email(email: str):
    if not email:
        return None
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE LOWER(email) = LOWER(?)", (email.strip(),))
    row = cursor.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None

def create_user(email: str, password_hash: str, salt: str, full_name: str):
    conn = get_connection()
    cursor = conn.cursor()
    created_at = datetime.now(timezone.utc).isoformat()
    cursor.execute(
        "INSERT INTO users (email, password_hash, salt, full_name, scans_remaining, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (email.strip().lower(), password_hash, salt, full_name.strip(), 100, created_at)
    )
    conn.commit()
    user_id = cursor.lastrowid
    conn.close()
    return get_user_by_email(email)

def decrement_user_scans(email: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET scans_remaining = MAX(0, scans_remaining - 1) WHERE LOWER(email) = LOWER(?)",
        (email.strip(),)
    )
    conn.commit()
    conn.close()

# Initialize DB upon module load
init_db()
