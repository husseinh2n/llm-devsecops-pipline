"""
Task Manager API — a simple REST API for managing tasks.

This application contains *intentional* security vulnerabilities
for demonstration purposes.  The CI pipeline is designed to catch
them and the AI remediation workflow will auto-fix them.
"""

from flask import Flask, request, jsonify
import sqlite3
import os
import subprocess
import pickle
import hashlib

from app.config import SECRET_KEY, DATABASE_URL, API_TOKEN, DEBUG

# ──────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = SECRET_KEY
# ──────────────────────────────────────────────────────────────


def get_db():
    """Get a connection to the SQLite database."""
    conn = sqlite3.connect("tasks.db")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create the tasks table if it doesn't exist."""
    conn = get_db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS tasks (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            title       TEXT NOT NULL,
            description TEXT,
            category    TEXT DEFAULT 'general',
            status      TEXT DEFAULT 'pending',
            created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.commit()
    conn.close()


# ─── Health ───────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint."""
    return jsonify({"status": "healthy", "version": "1.0.0"})


# ─── CRUD ─────────────────────────────────────────────────────

@app.route("/tasks", methods=["GET"])
def get_tasks():
    """Retrieve tasks, optionally filtered by category."""
    category = request.args.get("category", "")
    conn = get_db()

    if category:
        # VULNERABILITY: SQL Injection via f-string
        query = f"SELECT * FROM tasks WHERE category = '{category}'"
        tasks = conn.execute(query).fetchall()
    else:
        tasks = conn.execute("SELECT * FROM tasks").fetchall()

    conn.close()
    return jsonify([dict(t) for t in tasks])


@app.route("/tasks", methods=["POST"])
def create_task():
    """Create a new task."""
    data = request.get_json()
    if not data or "title" not in data:
        return jsonify({"error": "Title is required"}), 400

    conn = get_db()
    conn.execute(
        "INSERT INTO tasks (title, description, category) VALUES (?, ?, ?)",
        (data["title"], data.get("description", ""), data.get("category", "general")),
    )
    conn.commit()
    conn.close()
    return jsonify({"status": "created"}), 201


@app.route("/tasks/search", methods=["GET"])
def search_tasks():
    """Search tasks by title."""
    q = request.args.get("q", "")
    conn = get_db()
    # VULNERABILITY: SQL Injection via string concatenation
    results = conn.execute(
        "SELECT * FROM tasks WHERE title LIKE '%" + q + "%'"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in results])


@app.route("/tasks/<int:task_id>", methods=["DELETE"])
def delete_task(task_id):
    """Delete a task by ID."""
    conn = get_db()
    conn.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "deleted"})


# ─── Export / Import ──────────────────────────────────────────

@app.route("/tasks/export", methods=["GET"])
def export_tasks():
    """Export tasks to a file."""
    fmt = request.args.get("format", "json")
    filename = request.args.get("filename", "export")

    # VULNERABILITY: Command injection via os.system
    os.system(f"echo 'Exporting tasks as {fmt}' > /tmp/{filename}.log")

    conn = get_db()
    tasks = conn.execute("SELECT * FROM tasks").fetchall()
    conn.close()
    return jsonify([dict(t) for t in tasks])


@app.route("/tasks/import", methods=["POST"])
def import_tasks():
    """Import tasks from serialized data."""
    data = request.get_data()
    # VULNERABILITY: Insecure deserialization with pickle
    tasks = pickle.loads(data)
    return jsonify({"imported": len(tasks)})


# ─── Admin / Debug ────────────────────────────────────────────

@app.route("/admin/run", methods=["POST"])
def admin_run():
    """Run a diagnostic command (admin only)."""
    data = request.get_json()
    cmd = data.get("command", "echo OK")
    # VULNERABILITY: Command injection via subprocess with shell=True
    result = subprocess.check_output(cmd, shell=True)
    return jsonify({"output": result.decode()})


@app.route("/tasks/calculate", methods=["POST"])
def calculate():
    """Evaluate a mathematical expression for task scoring."""
    data = request.get_json()
    expr = data.get("expression", "0")
    # VULNERABILITY: Code injection via eval()
    result = eval(expr)
    return jsonify({"result": str(result)})


# ─── Helpers ──────────────────────────────────────────────────

def hash_password(password):
    """Hash a password for storage."""
    # VULNERABILITY: Using MD5 for password hashing
    return hashlib.md5(password.encode()).hexdigest()


# ─── Entry point ──────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    # VULNERABILITY: Debug mode enabled, binding to all interfaces
    app.run(host="0.0.0.0", port=5000, debug=True)
