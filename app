from flask import Flask, request, jsonify
import sqlite3
import subprocess
import base64
import pickle
import os

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "vuln.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, bio TEXT)")
    cur.execute("INSERT OR IGNORE INTO users (id, username, bio) VALUES (1, 'alice', 'admin user')")
    conn.commit()
    conn.close()

@app.route("/search")
def search():
    # SQL injection: user input is concatenated directly into the query
    q = request.args.get("q", "")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    sql = "SELECT id, username FROM users WHERE username LIKE '%{}%'".format(q)
    rows = cur.execute(sql).fetchall()
    conn.close()
    return jsonify([{"id": r[0], "username": r[1]} for r in rows])

@app.route("/ping")
def ping():
    # Command injection: user input inserted into a shell command with shell=True
    host = request.args.get("host", "127.0.0.1")
    # WARNING: this is intentionally insecure
    out = subprocess.getoutput("ping -c 1 " + host)
    return "<pre>" + out + "</pre>"

@app.route("/display")
def display():
    # Reflected XSS: user input is included directly in HTML
    name = request.args.get("name", "guest")
    return f"<html><body><h1>Welcome {name}</h1></body></html>"

@app.route("/deserialize", methods=["POST"])
def deserialize():
    # Insecure deserialization: loading pickle from client data
    b64 = request.data or b""
    try:
        data = base64.b64decode(b64)
        obj = pickle.loads(data)  # intentionally unsafe
        return jsonify({"type": str(type(obj)), "repr": repr(obj)})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)