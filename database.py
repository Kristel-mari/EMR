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
        CREATE TABLE IF NOT EXISTS vitals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            height_inches REAL NOT NULL,
            weight_lbs REAL NOT NULL,
            bmi REAL NOT NULL,
            recorded_date TEXT NOT NULL,
            FOREIGN KEY (patient_id) REFERENCES patients(id)
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
        cursor.execute("ALTER TABLE patients ADD COLUMN chart_number TEXT")

    cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_patients_chart_number ON patients(chart_number)")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS labs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER,
            test_name TEXT NOT NULL,
            result_value TEXT NOT NULL,
            result_unit TEXT,
            result_date TEXT NOT NULL,
            FOREIGN KEY(patient_id) REFERENCES patients(id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS medications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            medication_name TEXT NOT NULL,
            dose TEXT,
            start_date TEXT,
            end_date TEXT,
            status TEXT,
            FOREIGN KEY (patient_id) REFERENCES patients(id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vitals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            height REAL,
            weight REAL,
            bmi REAL,
            recorded_date TEXT,
            FOREIGN KEY (patient_id) REFERENCES patients(id)
        )
    """)

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
