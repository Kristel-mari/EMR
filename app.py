import os
import secrets
import sqlite3
from datetime import datetime
from functools import wraps

from flask import Flask, abort, redirect, render_template, request, session
from werkzeug.security import check_password_hash

from database import get_connection, init_db


class EMRApplication:
    def __init__(self):
        self.app = Flask(__name__)
        self.app.secret_key = os.environ.get("EMR_SECRET_KEY", secrets.token_hex(32))

        init_db()
        self.register_routes()

    def log_action(self, action):
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

    def ensure_csrf_token(self):
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(24)

    def register_routes(self):

        @self.app.route("/login", methods=["GET", "POST"])
        def login():
            error = ""

            if request.method == "POST":
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
                    self.ensure_csrf_token()
                    self.log_action("User logged in")
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

    def validate_csrf(self):
        self.ensure_csrf_token()
        submitted = request.form.get("csrf_token", "")
        if not submitted or submitted != session.get("csrf_token"):
            abort(400)

    def login_required(self, route_function):
        @wraps(route_function)
        def wrapper(*args, **kwargs):
            if "user_id" not in session:
                return redirect("/login")
            return route_function(*args, **kwargs)

        return wrapper

    def role_required(self, required_role):
        def decorator(route_function):
            @wraps(route_function)
            def wrapper(*args, **kwargs):
                if session.get("role") != required_role:
                    abort(403)
                return route_function(*args, **kwargs)

            return wrapper

        return decorator

    def register_hooks(self):
        @self.app.before_request
        def set_csrf_token():
            self.ensure_csrf_token()

        @self.app.context_processor
        def inject_csrf_token():
            return {"csrf_token": session.get("csrf_token", "")}

    def register_routes(self):
        @self.app.route("/")
        def home():
            return redirect("/login")

        @self.app.route("/login", methods=["GET", "POST"])
        def login():
            error = ""
            if request.method == "POST":
                self.validate_csrf()
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
                    self.ensure_csrf_token()
                    self.log_action("User logged in")
                    return redirect("/dashboard")
                error = "Invalid username or password."

            return render_template("login.html", error=error)

        @self.app.route("/dashboard")
        @self.login_required
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

        @self.app.route("/labs")
        @self.login_required
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
                self.log_action(f"Viewed labs for patient_id={patient_id}")
            else:
                self.log_action("Viewed all labs")

            return render_template("labs.html", labs=lab_results, patient_id=patient_id)

        @self.app.route("/patients")
        @self.login_required
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
                self.log_action(
                    f"Searched patient list (patient_id={patient_id}, chart_number={chart_number})"
                )
            else:
                self.log_action("Viewed patient list")

            return render_template(
                "patients.html",
                patients=patient_list,
                patient_id=patient_id,
                chart_number=chart_number,
                error=error,
            )

        @self.app.route("/add-patient", methods=["POST"])
        @self.login_required
        @self.role_required("admin")
        def add_patient():
            self.validate_csrf()
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
            self.log_action(f"Added patient: chart={chart_number}, name={first_name} {last_name}")
            return redirect("/patients")

        @self.app.route("/logout")
        @self.login_required
        def logout():
            self.log_action("User logged out")
            session.clear()
            return redirect("/login")


emr_application = EMRApplication()
app = emr_application.app


if __name__ == "__main__":
    app.run(debug=False)
