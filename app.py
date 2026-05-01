from flask import Flask, render_template, request, redirect, session
from werkzeug.security import check_password_hash
from datetime import datetime
from database import init_db, get_connection

app = Flask(__name__)
app.secret_key = "change-this-secret-key"

init_db()

def log_action(action):
    if "user_id" not in session:
        return

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO audit_log (user_id, action, timestamp) VALUES (?, ?, ?)",
        (session["user_id"], action, datetime.now().isoformat())
    )

    conn.commit()
    conn.close()

def login_required(route_function):
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")
        return route_function(*args, **kwargs)

    wrapper.__name__ = route_function.__name__
    return wrapper

@app.route("/")
def home():
    return redirect("/login")

@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id, username, password_hash, role FROM users WHERE username = ?",
            (username,)
        )
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session["user_id"] = user[0]
            session["username"] = user[1]
            session["role"] = user[3]
            log_action("User logged in")
            return redirect("/dashboard")
        else:
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
def add_patient():
    first_name = request.form.get("first_name", "").strip()
    last_name = request.form.get("last_name", "").strip()
    dob = request.form.get("dob", "").strip()

    if not first_name or not last_name or not dob:
        return redirect("/patients")

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO patients (first_name, last_name, dob) VALUES (?, ?, ?)",
        (first_name, last_name, dob)
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
    app.run(debug=True)