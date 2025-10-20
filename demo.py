# vuln_demo.py
# INTENTIONAL VULNERABILITIES — FOR EDU/HANDS-ON TESTING ONLY.
# Save this file and run: python vuln_demo.py

from flask import Flask, request, jsonify, render_template_string, send_from_directory
import sqlite3
import os
import pathlib
import subprocess
import json
from markupsafe import Markup

app = Flask(__name__)

# -----------------------------
# Hard-coded secret (insecure)
# -----------------------------
APP_SECRET = "hardcoded_demo_secret_change_me"

# -----------------------------
# Simple SQLite DB (file)
# -----------------------------
DB_PATH = os.path.join(os.path.dirname(__file__), "demo_users.sqlite")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        password TEXT
      )
    """)
    # seed (no hashing) - intentional
    cur.execute("INSERT OR IGNORE INTO users (id, username, password) VALUES (1, 'admin', 'adminpass')")
    conn.commit()
    conn.close()

init_db()

# -----------------------------
# 1) SQL Injection (vulnerable)
# Using string concatenation with untrusted input.
# -----------------------------
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    # VULNERABLE: direct string formatting into SQL
    query = f"SELECT id, username FROM users WHERE username = '{username}' AND password = '{password}'"
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    try:
        cur.execute(query)              # dangerous
        row = cur.fetchone()
    except Exception as e:
        conn.close()
        return f"DB error: {e}", 500
    conn.close()

    if not row:
        return "invalid credentials", 401

    # insecure "token" (not real JWT) using hard-coded secret (for demo)
    token = {"id": row[0], "username": row[1], "secret": APP_SECRET}
    return jsonify(token)

# -----------------------------
# 2) Reflected XSS (vulnerable)
# Renders user input into an HTML template without escaping.
# -----------------------------
@app.route("/search", methods=["GET"])
def search():
    q = request.args.get("q", "")
    # VULNERABLE: using Markup to intentionally bypass escaping (simulates a dev mistake)
    unsafe_q = Markup(q)  # Markup forces rendering as-is (no escaping)
    template = """
    <!doctype html>
    <html>
      <head><meta charset="utf-8"><title>Search</title></head>
      <body>
        <h2>Search results</h2>
        <div>Query: {{ q }}</div>
        <p>No real results — demo only</p>
      </body>
    </html>
    """
    return render_template_string(template, q=unsafe_q)

# -----------------------------
# 3) Path traversal / unsafe file write (vulnerable)
# Writes user-supplied filename without sanitization.
# -----------------------------
STORAGE_DIR = os.path.join(os.path.dirname(__file__), "storage")
os.makedirs(STORAGE_DIR, exist_ok=True)

@app.route("/save", methods=["POST"])
def save_file():
    filename = request.form.get("filename", "out.txt")
    content = request.form.get("content", "")
    # VULNERABLE: joining user-supplied filename directly leads to path traversal
    target_path = os.path.join(STORAGE_DIR, filename)
    try:
        # naive write
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(content)
    except Exception as e:
        return f"write failed: {e}", 500
    return f"Saved to {target_path}"

@app.route("/storage/<path:filename>", methods=["GET"])
def get_storage(filename):
    # intentionally allow serving files from storage directory (insecure)
    return send_from_directory(STORAGE_DIR, filename)

# -----------------------------
# 4) Command injection demo (very dangerous if enabled)
# This endpoint demonstrates what *would* be dangerous:
# it runs a shell command built from user input (uses shell=True).
# Do NOT enable this on any exposed system.
# -----------------------------
@app.route("/runcmd", methods=["GET"])
def runcmd():
    cmd = request.args.get("cmd", "echo hello")
    # VULNERABLE: passing user input into shell=True
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=5, universal_newlines=True)
    except subprocess.CalledProcessError as e:
        output = f"returncode={e.returncode}\n{e.output}"
    except Exception as e:
        output = f"error: {e}"
    # Return output as plain text (could leak)
    return f"<pre>{Markup(output)}</pre>"

# -----------------------------
# Demo index page
# -----------------------------
@app.route("/", methods=["GET"])
def index():
    return """
    <h1>Python Vuln Demo</h1>

    <h3>Login (SQLi demo)</h3>
    <form method="post" action="/login">
      <input name="username" placeholder="username"><br>
      <input name="password" placeholder="password"><br>
      <button type="submit">Login</button>
    </form>

    <h3>Search (Reflected XSS demo)</h3>
    <form method="get" action="/search">
      <input name="q" placeholder="search"><button type="submit">Search</button>
    </form>

    <h3>Save file (Path traversal demo)</h3>
    <form method="post" action="/save">
      <input name="filename" placeholder="filename"><br>
      <textarea name="content" placeholder="content"></textarea><br>
      <button type="submit">Save</button>
    </form>

    <h3>Run command (Command injection demo)</h3>
    <form method="get" action="/runcmd">
      <input name="cmd" placeholder="command (e.g. 'echo hi')"><button type="submit">Run</button>
    </form>
    """

if __name__ == "__main__":
    app.run(port=5000, debug=True)
