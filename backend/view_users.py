import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database", "app.db")

def view_all_users():
    if not os.path.exists(DB_PATH):
        print("Database does not exist yet. No registered users found.")
        return

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, email, full_name, scans_remaining, created_at FROM users ORDER BY id ASC")
    users = cursor.fetchall()
    conn.close()

    if not users:
        print("No users registered yet.")
        return

    print("=" * 70)
    print(f"{'ID':<4} | {'Email':<28} | {'Full Name':<18} | {'Scans':<6} | {'Created At'}")
    print("=" * 70)
    for u in users:
        print(f"{u['id']:<4} | {u['email']:<28} | {u['full_name']:<18} | {u['scans_remaining']:<6} | {u['created_at']}")
    print("=" * 70)
    print(f"Total Users: {len(users)}")

if __name__ == "__main__":
    view_all_users()
