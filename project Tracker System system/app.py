from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash
)
import os
import hmac
import mysql.connector
from contextlib import contextmanager
from datetime import date, datetime
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, static_url_path="")

app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "dev-only-change-this-secret-key"
)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

TEACHER_ACCESS_CODE = os.environ.get("TEACHER_ACCESS_CODE", "")

# CHANGE THESE TO MATCH YOUR MYSQL WORKBENCH SETTINGS
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "pretado@123",
    "database": "class_project_tracker",
    "port": 3306,
}

SUBJECT_TEACHERS = {
    "GEN 033": "",
    "HIS 007": "",
    "ITE 031": "",
    "ITE 083": "",
    "ITE 292": "",
    "ITE 298": "",
    "ITE 300": "",
    "PED 032": "",
}

SUBJECTS = list(SUBJECT_TEACHERS)
STATUSES = ("pending", "submitted")


# ---------------------------------------------------------
# MYSQL CONNECTION
# ---------------------------------------------------------

@contextmanager
def db():
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor(dictionary=True)

    try:
        yield cursor
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()


# ---------------------------------------------------------
# CREATE TABLES
# ---------------------------------------------------------

def init_db():
    with db() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                role ENUM('student', 'teacher') NOT NULL,
                full_name VARCHAR(150) NOT NULL,
                school_id VARCHAR(100) NOT NULL UNIQUE,
                email VARCHAR(255) NOT NULL UNIQUE,
                contact VARCHAR(50) NOT NULL,
                password VARCHAR(255) NOT NULL
            ) ENGINE=InnoDB
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS projects (
                id INT AUTO_INCREMENT PRIMARY KEY,
                student_id INT NOT NULL,
                subject VARCHAR(20) NOT NULL,
                title VARCHAR(120) NOT NULL,
                due_date DATE NOT NULL,
                status ENUM('pending', 'submitted')
                    NOT NULL DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                CONSTRAINT fk_project_student
                    FOREIGN KEY (student_id)
                    REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_projects_student (student_id)
            ) ENGINE=InnoDB
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS teacher_subjects (
                teacher_id INT NOT NULL,
                subject VARCHAR(20) NOT NULL,
                PRIMARY KEY (teacher_id, subject),
                CONSTRAINT fk_teacher_subject
                    FOREIGN KEY (teacher_id)
                    REFERENCES users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB
        """)


# ---------------------------------------------------------
# SUBJECT HELPERS
# ---------------------------------------------------------

def get_teacher_subjects(cur, user_id):
    cur.execute("""
        SELECT subject FROM teacher_subjects
        WHERE teacher_id = %s
    """, (user_id,))

    taught = {row["subject"] for row in cur.fetchall()}
    return [subject for subject in SUBJECTS if subject in taught]


def subject_teacher_names():
    with db() as cur:
        cur.execute("""
            SELECT ts.subject, u.full_name
            FROM teacher_subjects ts
            JOIN users u ON u.id = ts.teacher_id
            ORDER BY u.full_name
        """)
        rows = cur.fetchall()

    registered = {}
    for row in rows:
        registered.setdefault(row["subject"], []).append(
            row["full_name"]
        )

    return {
        subject: ", ".join(registered[subject])
        if subject in registered
        else SUBJECT_TEACHERS[subject]
        for subject in SUBJECTS
    }


# ---------------------------------------------------------
# ACCESS CONTROL
# ---------------------------------------------------------

def login_required(route_function):
    @wraps(route_function)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "error")
            return redirect(url_for("login_page", form="login"))
        return route_function(*args, **kwargs)
    return wrapper


def teacher_required(route_function):
    @wraps(route_function)
    @login_required
    def wrapper(*args, **kwargs):
        if session.get("role") != "teacher":
            flash("Only teachers can do that.", "error")
            return redirect(url_for("dashboard"))
        return route_function(*args, **kwargs)
    return wrapper


def student_required(route_function):
    @wraps(route_function)
    @login_required
    def wrapper(*args, **kwargs):
        if session.get("role") != "student":
            flash("Only students can submit projects.", "error")
            return redirect(url_for("dashboard"))
        return route_function(*args, **kwargs)
    return wrapper


@app.after_request
def add_no_cache_headers(response):
    if "user_id" in session:
        response.headers["Cache-Control"] = "no-store"
    return response


def back_to_dashboard():
    selected = request.form.get("filter", "")
    if selected not in ("all", *STATUSES):
        selected = "all"
    return redirect(url_for("dashboard", filter=selected))


def check_project_access(cur, project_id):
    cur.execute("""
        SELECT subject FROM projects WHERE id = %s
    """, (project_id,))
    project = cur.fetchone()

    if not project:
        return "missing"

    if project["subject"] not in get_teacher_subjects(
        cur, session["user_id"]
    ):
        return "denied"

    return "ok"


# ---------------------------------------------------------
# PUBLIC PAGES
# ---------------------------------------------------------

@app.route("/")
@app.route("/index.html")
def home():
    return render_template("index.html")


@app.route("/about")
@app.route("/about.html")
def about():
    return render_template(
        "about.html",
        subject_teachers=subject_teacher_names()
    )


@app.route("/login.html")
@app.route("/login", methods=["GET"])
def login_page():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    return render_template(
        "login.html",
        show_form=request.args.get("form", "register"),
        teacher_code_required=bool(TEACHER_ACCESS_CODE),
        subject_teachers=subject_teacher_names(),
    )


# ---------------------------------------------------------
# REGISTRATION
# ---------------------------------------------------------

@app.route("/register", methods=["POST"])
def register():
    role = request.form.get("role", "").strip().lower()
    full_name = request.form.get("full_name", "").strip()
    school_id = request.form.get("school_id", "").strip()
    email = request.form.get("email", "").strip().lower()
    contact = request.form.get("contact", "").strip()
    password = request.form.get("password", "")

    if role not in ("student", "teacher"):
        flash("Please select a valid account role.", "error")
        return redirect(url_for("login_page"))

    if not all([full_name, school_id, email, contact, password]):
        flash("Please complete all registration fields.", "error")
        return redirect(url_for("login_page"))

    if "@" not in email or "." not in email.split("@")[-1]:
        flash("Please enter a valid email address.", "error")
        return redirect(url_for("login_page"))

    if len(password) < 8:
        flash("Password must contain at least 8 characters.", "error")
        return redirect(url_for("login_page"))

    if role == "teacher":
        if TEACHER_ACCESS_CODE:
            supplied_code = request.form.get("teacher_code", "")
            if not hmac.compare_digest(
                supplied_code, TEACHER_ACCESS_CODE
            ):
                flash("Invalid teacher access code.", "error")
                return redirect(url_for("login_page"))

        picked = request.form.getlist("subjects")
        chosen_subjects = [
            subject for subject in SUBJECTS if subject in picked
        ]

        if not chosen_subjects:
            flash("Please select at least one subject.", "error")
            return redirect(url_for("login_page"))
    else:
        chosen_subjects = []

    hashed_password = generate_password_hash(password)

    try:
        with db() as cur:
            cur.execute("""
                INSERT INTO users
                (role, full_name, school_id, email, contact, password)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                role, full_name, school_id,
                email, contact, hashed_password
            ))

            teacher_id = cur.lastrowid

            if chosen_subjects:
                cur.executemany("""
                    INSERT INTO teacher_subjects
                    (teacher_id, subject)
                    VALUES (%s, %s)
                """, [
                    (teacher_id, subject)
                    for subject in chosen_subjects
                ])

    except mysql.connector.IntegrityError:
        flash(
            "That School ID or email is already registered.",
            "error"
        )
        return redirect(url_for("login_page"))

    flash("Registration successful! You can now log in.", "success")
    return redirect(url_for("login_page", form="login"))


# ---------------------------------------------------------
# LOGIN AND LOGOUT
# ---------------------------------------------------------

@app.route("/login", methods=["POST"])
def login():
    school_id = request.form.get("school_id", "").strip()
    password = request.form.get("password", "")

    with db() as cur:
        cur.execute("""
            SELECT * FROM users WHERE school_id = %s
        """, (school_id,))
        user = cur.fetchone()

    if user and check_password_hash(user["password"], password):
        session.clear()
        session["user_id"] = user["id"]
        session["full_name"] = user["full_name"]
        session["role"] = user["role"]
        return redirect(url_for("dashboard"))

    flash("Invalid School ID or password.", "error")
    return redirect(url_for("login_page", form="login"))


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("home"))


# ---------------------------------------------------------
# LOAD PROJECTS
# ---------------------------------------------------------

def load_projects():
    sql = """
        SELECT p.id, p.subject, p.title, p.due_date, p.status,
               u.full_name AS student_name,
               u.school_id AS student_school_id
        FROM projects p
        JOIN users u ON u.id = p.student_id
    """
    params = []

    if session["role"] == "student":
        sql += " WHERE p.student_id = %s"
        params.append(session["user_id"])
    else:
        with db() as cur:
            mine = get_teacher_subjects(cur, session["user_id"])

        if not mine:
            return []

        placeholders = ", ".join(["%s"] * len(mine))
        sql += f" WHERE p.subject IN ({placeholders})"
        params.extend(mine)

    sql += """
        ORDER BY (p.status = 'submitted'),
                 p.due_date, p.subject
    """

    with db() as cur:
        cur.execute(sql, params)
        rows = cur.fetchall()

    teachers = subject_teacher_names()
    today = date.today()
    projects = []

    for row in rows:
        project = dict(row)
        due = project["due_date"]

        if isinstance(due, date):
            due = due.isoformat()
        project["due_date"] = due
        project["teacher"] = teachers.get(project["subject"], "")
        project["overdue"] = (
            project["status"] == "pending" and due < today.isoformat()
        )
        projects.append(project)

    return projects


# ---------------------------------------------------------
# DASHBOARD
# ---------------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    projects = load_projects()

    counts = {
        "all": len(projects),
        "submitted": sum(
            p["status"] == "submitted" for p in projects
        ),
        "pending": sum(
            p["status"] == "pending" for p in projects
        ),
    }

    active_filter = request.args.get("filter", "all")
    if active_filter not in ("all", *STATUSES):
        active_filter = "all"

    if active_filter != "all":
        projects = [
            p for p in projects if p["status"] == active_filter
        ]

    my_subjects = []
    students = []

    if session["role"] == "teacher":
        with db() as cur:
            my_subjects = get_teacher_subjects(
                cur, session["user_id"]
            )
            cur.execute("""
                SELECT id, full_name, school_id
                FROM users
                WHERE role = 'student'
                ORDER BY full_name
            """)
            students = cur.fetchall()

    return render_template(
        "dashboard.html",
        full_name=session["full_name"],
        role=session["role"],
        projects=projects,
        counts=counts,
        active_filter=active_filter,
        students=students,
        subjects=my_subjects,
        my_subjects=my_subjects,
        subject_teachers=subject_teacher_names(),
    )


# ---------------------------------------------------------
# TEACHER: UPDATE SUBJECTS
# ---------------------------------------------------------

@app.route("/teacher/subjects", methods=["POST"])
@teacher_required
def set_teacher_subjects():
    picked = request.form.getlist("subjects")
    chosen = [s for s in SUBJECTS if s in picked]

    if not chosen:
        flash("Please select at least one subject.", "error")
        return back_to_dashboard()

    with db() as cur:
        cur.execute("""
            DELETE FROM teacher_subjects WHERE teacher_id = %s
        """, (session["user_id"],))

        cur.executemany("""
            INSERT INTO teacher_subjects (teacher_id, subject)
            VALUES (%s, %s)
        """, [
            (session["user_id"], subject) for subject in chosen
        ])

    flash("Your subjects were updated.", "success")
    return back_to_dashboard()


# ---------------------------------------------------------
# ADD PROJECT
# ---------------------------------------------------------

@app.route("/projects/add", methods=["POST"])
@teacher_required
def add_project():
    subject = request.form.get("subject", "").strip()
    title = request.form.get("title", "").strip()
    due_date = request.form.get("due_date", "").strip()
    student_choice = request.form.get("student_id", "").strip()

    if subject not in SUBJECTS:
        flash("Please choose a valid subject.", "error")
        return back_to_dashboard()

    if not title or len(title) > 120:
        flash("Project title is required (120 characters maximum).", "error")
        return back_to_dashboard()

    try:
        datetime.strptime(due_date, "%Y-%m-%d")
    except ValueError:
        flash("Please enter a valid due date.", "error")
        return back_to_dashboard()

    with db() as cur:
        if subject not in get_teacher_subjects(
            cur, session["user_id"]
        ):
            flash("You can only add projects for your subjects.", "error")
            return back_to_dashboard()

        if student_choice == "all":
            cur.execute("""
                SELECT id FROM users WHERE role = 'student'
            """)
            student_ids = [r["id"] for r in cur.fetchall()]
        else:
            try:
                chosen_id = int(student_choice)
            except ValueError:
                chosen_id = None

            student_ids = []
            if chosen_id is not None:
                cur.execute("""
                    SELECT id FROM users
                    WHERE id = %s AND role = 'student'
                """, (chosen_id,))
                student = cur.fetchone()
                if student:
                    student_ids = [student["id"]]

        if not student_ids:
            flash("No student found to assign this project to.", "error")
            return back_to_dashboard()

        cur.executemany("""
            INSERT INTO projects
            (student_id, subject, title, due_date)
            VALUES (%s, %s, %s, %s)
        """, [
            (sid, subject, title, due_date) for sid in student_ids
        ])

    if len(student_ids) == 1:
        flash("Project added.", "success")
    else:
        flash(
            f"Project added for {len(student_ids)} students.",
            "success"
        )

    return back_to_dashboard()


# ---------------------------------------------------------
# UPDATE PROJECT STATUS
# ---------------------------------------------------------

@app.route("/projects/<int:project_id>/status", methods=["POST"])
@teacher_required
def update_status(project_id):
    new_status = request.form.get("status", "").strip().lower()

    if new_status not in STATUSES:
        flash("Invalid status.", "error")
        return back_to_dashboard()

    with db() as cur:
        access = check_project_access(cur, project_id)

        if access == "ok":
            cur.execute("""
                UPDATE projects SET status = %s WHERE id = %s
            """, (new_status, project_id))

    if access == "missing":
        flash("Project not found.", "error")
    elif access == "denied":
        flash("You can only update projects for your subjects.", "error")
    else:
        flash(f"Project marked as {new_status}.", "success")

    return back_to_dashboard()


# ---------------------------------------------------------
# EDIT PROJECT
# ---------------------------------------------------------

@app.route("/projects/<int:project_id>/edit", methods=["POST"])
@teacher_required
def edit_project(project_id):
    title = request.form.get("title", "").strip()
    due_date = request.form.get("due_date", "").strip()

    if not title or len(title) > 120:
        flash("Enter a title up to 120 characters.", "error")
        return back_to_dashboard()

    try:
        datetime.strptime(due_date, "%Y-%m-%d")
    except ValueError:
        flash("Please enter a valid due date.", "error")
        return back_to_dashboard()

    with db() as cur:
        access = check_project_access(cur, project_id)

        if access == "ok":
            cur.execute("""
                UPDATE projects
                SET title = %s, due_date = %s
                WHERE id = %s
            """, (title, due_date, project_id))

    if access == "missing":
        flash("Project not found.", "error")
    elif access == "denied":
        flash("You cannot edit this project's subject.", "error")
    else:
        flash("Project updated successfully.", "success")

    return back_to_dashboard()


# ---------------------------------------------------------
# DELETE PROJECT
# ---------------------------------------------------------

@app.route("/projects/<int:project_id>/delete", methods=["POST"])
@teacher_required
def delete_project(project_id):
    with db() as cur:
        access = check_project_access(cur, project_id)

        if access == "ok":
            cur.execute("""
                DELETE FROM projects WHERE id = %s
            """, (project_id,))

    if access == "missing":
        flash("Project not found.", "error")
    elif access == "denied":
        flash("You cannot delete this project.", "error")
    else:
        flash("Project deleted successfully.", "success")

    return back_to_dashboard()


# ---------------------------------------------------------
# START APPLICATION
# ---------------------------------------------------------


if __name__ == "__main__":
    init_db()
    app.run(debug=True)