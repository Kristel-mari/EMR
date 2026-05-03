import os
import secrets
from datetime import datetime
from functools import wraps

from flask import Flask, abort, redirect, render_template, request, session
from werkzeug.security import check_password_hash

import sqlite3

from database import get_connection, init_db

app = Flask(__name__)
app.secret_key = os.environ.get("EMR_SECRET_KEY", secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("EMR_SECURE_COOKIE", "0") == "1",
)

init_db()


def log_action(action):
    if "user_id" not in session:
        return

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO audit_log (user_id, action, timestamp) VALUES (?, ?, ?)",
        (session["user_id"], action, datetime.utcnow().isoformat()),
    )

    conn.commit()
    conn.close()


def login_required(route_function):
    @wraps(route_function)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")
        return route_function(*args, **kwargs)

    return wrapper


def role_required(required_role):
    def decorator(route_function):
        @wraps(route_function)
        def wrapper(*args, **kwargs):
            if session.get("role") != required_role:
                abort(403)
            return route_function(*args, **kwargs)

        return wrapper

    return decorator


def ensure_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(24)


def validate_csrf():
    ensure_csrf_token()
    submitted = request.form.get("csrf_token", "")
    if not submitted or submitted != session.get("csrf_token"):
        abort(400)


@app.before_request
def set_csrf_token():
    ensure_csrf_token()


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": session.get("csrf_token", "")}


@app.route("/")
def home():
    return redirect("/login")


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""

    if request.method == "POST":
        validate_csrf()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id, username, password_hash, role FROM users WHERE username = ?",
            (username,),
        )
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session.clear()
            session["user_id"] = user[0]
            session["username"] = user[1]
            session["role"] = user[3]
            ensure_csrf_token()
            log_action("User logged in")
            return redirect("/dashboard")
        error = "Invalid username or password."

    return render_template("login.html", error=error)


@app.route("/dashboard")
@login_required
def dashboard():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM patients")
    patient_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM labs")
    lab_count = cursor.fetchone()[0]

    cursor.execute(
        "SELECT timestamp, action FROM audit_log WHERE user_id = ? ORDER BY id DESC LIMIT 5",
        (session["user_id"],),
    )
    recent_activity = cursor.fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        patient_count=patient_count,
        lab_count=lab_count,
        recent_activity=recent_activity,
    )


@app.route("/labs")
@login_required
def labs():
    patient_id = request.args.get("patient_id", "").strip()

    conn = get_connection()
    cursor = conn.cursor()

    query = "SELECT id, patient_id, test_name, result_value, result_unit, result_date FROM labs"
    params = []

    if patient_id:
        query += " WHERE patient_id = ?"
        params.append(patient_id)

    query += " ORDER BY result_date DESC"

    cursor.execute(query, params)
    lab_results = cursor.fetchall()
    conn.close()

    if patient_id:
        log_action(f"Viewed labs for patient_id={patient_id}")
    else:
        log_action("Viewed all labs")

    return render_template("labs.html", labs=lab_results, patient_id=patient_id)


@app.route("/labs")
@login_required
def labs():
    patient_id = request.args.get("patient_id", "").strip()

    conn = get_connection()
    cursor = conn.cursor()

    query = "SELECT id, patient_id, test_name, result_value, result_unit, result_date FROM labs"
    params = []

    if patient_id:
        query += " WHERE patient_id = ?"
        params.append(patient_id)

    query += " ORDER BY result_date DESC"

    cursor.execute(query, params)
    lab_results = cursor.fetchall()
    conn.close()

    if patient_id:
        log_action(f"Viewed labs for patient_id={patient_id}")
    else:
        log_action("Viewed all labs")

    return render_template("labs.html", labs=lab_results, patient_id=patient_id)


@app.route("/patients")
@login_required
def patients():
    patient_id = request.args.get("patient_id", "").strip()
    chart_number = request.args.get("chart_number", "").strip()
    error = request.args.get("error", "").strip()

    conn = get_connection()
    cursor = conn.cursor()

    query = "SELECT id, chart_number, first_name, last_name, dob FROM patients"
    conditions = []
    params = []

    if patient_id:
        conditions.append("id = ?")
        params.append(patient_id)

    if chart_number:
        conditions.append("chart_number = ?")
        params.append(chart_number)

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    cursor.execute(query, params)
    patient_list = cursor.fetchall()

    conn.close()

    if patient_id or chart_number:
        log_action(f"Searched patient list (patient_id={patient_id}, chart_number={chart_number})")
    else:
        log_action("Viewed patient list")

    return render_template(
        "patients.html",
        patients=patient_list,
        patient_id=patient_id,
        chart_number=chart_number,
        error=error,
    )
   



@app.route("/add-patient", methods=["POST"])
@login_required
@role_required("admin")
def add_patient():
    validate_csrf()
    chart_number = request.form.get("chart_number", "").strip()
    first_name = request.form.get("first_name", "").strip()
    last_name = request.form.get("last_name", "").strip()
    dob = request.form.get("dob", "").strip()

    if not chart_number or not first_name or not last_name or not dob:
        return redirect("/patients")

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            "INSERT INTO patients (chart_number, first_name, last_name, dob) VALUES (?, ?, ?, ?)",
            (chart_number, first_name, last_name, dob),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return redirect("/patients?error=Chart+number+already+exists")

    conn.close()

    log_action(f"Added patient: chart={chart_number}, name={first_name} {last_name}")

    return redirect("/patients")


@app.route("/logout")
@login_required
def logout():
    log_action("User logged out")
    session.clear()
    return redirect("/login")


if __name__ == "__main__":
    app.run(debug=False)
