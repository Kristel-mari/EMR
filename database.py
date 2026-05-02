import sqlite3
from werkzeug.security import generate_password_hash

DB_NAME = "emr.db"


def get_connection():
    return sqlite3.connect(DB_NAME)


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS patients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chart_number TEXT UNIQUE,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            dob TEXT NOT NULL
        )
    """)

    cursor.execute("PRAGMA table_info(patients)")
    patient_columns = [row[1] for row in cursor.fetchall()]
    if "chart_number" not in patient_columns:
        cursor.execute("ALTER TABLE patients ADD COLUMN chart_number TEXT UNIQUE")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    """)

    cursor.execute("SELECT * FROM users WHERE username = ?", ("admin",))
    existing_user = cursor.fetchone()

    if not existing_user:
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("admin", generate_password_hash("Admin123!"), "admin"),
        )

    conn.commit()
    conn.close()
