import os
import secrets
from datetime import datetime
from functools import wraps

from flask import Flask, abort, redirect, render_template, request, session
from werkzeug.security import check_password_hash

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
    return render_template("dashboard.html")


@app.route("/patients")
@login_required
def patients():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id, first_name, last_name, dob FROM patients")
    patient_list = cursor.fetchall()

    conn.close()

    log_action("Viewed patient list")

    return render_template("patients.html", patients=patient_list)


@app.route("/add-patient", methods=["POST"])
@login_required
@role_required("admin")
def add_patient():
    validate_csrf()
    first_name = request.form.get("first_name", "").strip()
    last_name = request.form.get("last_name", "").strip()
    dob = request.form.get("dob", "").strip()

    if not first_name or not last_name or not dob:
        return redirect("/patients")

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO patients (first_name, last_name, dob) VALUES (?, ?, ?)",
        (first_name, last_name, dob),
    )

    conn.commit()
    conn.close()

    log_action(f"Added patient: {first_name} {last_name}")

    return redirect("/patients")


@app.route("/logout")
@login_required
def logout():
    log_action("User logged out")
    session.clear()
    return redirect("/login")


if __name__ == "__main__":
    app.run(debug=False)
