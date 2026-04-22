import os
import sqlite3
from datetime import datetime
from functools import wraps

from flask import (Flask, flash, jsonify, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "artvault_secret_key_change_in_production"  # Change this in production!

# Where uploaded images will be stored
UPLOAD_FOLDER = os.path.join("static", "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE

# Make sure the uploads folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def get_db():
    """Open a connection to the SQLite database."""
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row   # Rows behave like dicts
    return conn


def init_db():
    """Create all tables if they don't already exist."""
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT    NOT NULL UNIQUE,
            email    TEXT    NOT NULL UNIQUE,
            password TEXT    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS artworks (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            title      TEXT    NOT NULL,
            image_path TEXT    NOT NULL,
            category   TEXT    NOT NULL DEFAULT 'Other',
            created_at TEXT    NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS likes (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            artwork_id INTEGER NOT NULL,
            UNIQUE (user_id, artwork_id),         -- one like per user per artwork
            FOREIGN KEY (user_id)    REFERENCES users(id),
            FOREIGN KEY (artwork_id) REFERENCES artworks(id)
        );

        CREATE TABLE IF NOT EXISTS comments (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER NOT NULL,
            artwork_id   INTEGER NOT NULL,
            comment_text TEXT    NOT NULL,
            created_at   TEXT    NOT NULL,
            FOREIGN KEY (user_id)    REFERENCES users(id),
            FOREIGN KEY (artwork_id) REFERENCES artworks(id)
        );
    """)
    db.commit()
    db.close()

def allowed_file(filename):
    """Return True only if the file has an allowed image extension."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(f):
    """Redirect to login page if the user is not logged in."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Login required"}), 401
        return f(*args, **kwargs)
    return decorated

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login")
def login_page():
    return render_template("login.html")

@app.route("/signup")
def signup_page():
    return render_template("signup.html")

@app.route("/upload")
def upload_page():
    return render_template("upload.html")

@app.route("/profile")
def profile_page():
    return render_template("profile.html")

@app.route("/artwork/<int:artwork_id>")
def artwork_page(artwork_id):
    return render_template("artwork.html", artwork_id=artwork_id)

@app.route("/signup", methods=["POST"])
def signup():
    """
    Register a new user.
    Expects JSON: { username, email, password }
    """
    data = request.get_json()

    username = data.get("username", "").strip()
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")

    # Basic validation
    if not username or not email or not password:
        return jsonify({"error": "All fields are required"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    db = get_db()
    try:
        # Hash the password before storing (never store plain text!)
        hashed_pw = generate_password_hash(password)
        db.execute(
            "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
            (username, email, hashed_pw)
        )
        db.commit()
        return jsonify({"message": "Account created! Please log in."}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username or email already exists"}), 409
    finally:
        db.close()

@app.route("/login", methods=["POST"])
def login():
    """
    Log in an existing user.
    Expects JSON: { email, password }
    Sets session variables on success.
    """
    data = request.get_json()
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    db.close()

    if user and check_password_hash(user["password"], password):
        # Store user info in the session (server-side cookie)
        session["user_id"]  = user["id"]
        session["username"] = user["username"]
        return jsonify({"message": "Login successful", "username": user["username"]})

    return jsonify({"error": "Invalid email or password"}), 401


@app.route("/logout")
def logout():
    """Clear the session and log out."""
    session.clear()
    return redirect(url_for("index"))

@app.route("/me")
def me():
    """Return current session info (used by frontend to check login state)."""
    if "user_id" in session:
        return jsonify({"logged_in": True, "user_id": session["user_id"], "username": session["username"]})
    return jsonify({"logged_in": False})