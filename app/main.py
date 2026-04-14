 عباس
Task Manager API — a simple REST API for managing tasks.

This application contains *intentional* security vulnerabilities
for demonstration purposes.  The CI pipeline is designed to catch
them and the AI remediation workflow will auto-fix them.
"""

from flask import Flask, request, jsonify
import sqlite3
import os
import subprocess
import hashlib
import json # Added for import_tasks fix
import ast # Added for calculate fix
import secrets # Added for hash_password fix
import shlex # Added for admin_run fix

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
        # FIX: SQL Injection via f-string - use parameterized query
        query = "SELECT * FROM tasks WHERE category = ?"
        tasks = conn.execute(query, (category,)).fetchall()
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
    # FIX: SQL Injection via string concatenation - use parameterized query
    results = conn.execute(
        "SELECT * FROM tasks WHERE title LIKE ?", ('%' + q + '%',)
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

    # FIX: Command injection via os.system
    # Use subprocess.run with a list of arguments and shell=False
    # Ensure filename and fmt are handled safely.
    log_message = f"Exporting tasks as {fmt}"
    # Basic sanitization for filename to prevent path traversal.
    safe_filename = "".join(c for c in filename if c.isalnum() or c in "._-")
    if not safe_filename:
        safe_filename = "export" # Fallback if filename becomes empty after sanitization

    log_file_path = f"/tmp/{safe_filename}.log"
    try:
        # Using subprocess.run to safely execute the echo command and redirect output
        # The command and arguments are passed as a list, and shell=False is used.
        with open(log_file_path, "w") as log_file:
            subprocess.run(["echo", log_message], stdout=log_file, check=True, shell=False)
    except subprocess.CalledProcessError as e:
        app.logger.error(f"Failed to write log: {e}")
    except Exception as e:
        app.logger.error(f"An unexpected error occurred during logging: {e}")


    conn = get_db()
    tasks = conn.execute("SELECT * FROM tasks").fetchall()
    conn.close()
    return jsonify([dict(t) for t in tasks])


@app.route("/tasks/import", methods=["POST"])
def import_tasks():
    """Import tasks from serialized data."""
    data = request.get_data()
    # FIX: Insecure deserialization with pickle
    # Replace pickle.loads with json.loads. This assumes the client now sends JSON data.
    try:
        tasks = json.loads(data)
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON data"}), 400

    # Ensure tasks is a list, as expected by the original logic
    if not isinstance(tasks, list):
        return jsonify({"error": "Expected a list of tasks"}), 400

    # The original code just returns the count, not actually importing to DB.
    # If it were to import, further validation of 'tasks' content would be needed.
    return jsonify({"imported": len(tasks)})


# ─── Admin / Debug ────────────────────────────────────────────

@app.route("/admin/run", methods=["POST"])
def admin_run():
    """Run a diagnostic command (admin only)."""
    data = request.get_json()
    cmd = data.get("command", "echo OK")
    # FIX: Command injection via subprocess with shell=True
    # Use shlex.split to safely parse the command string into a list of arguments
    # Then use subprocess.run with shell=False
    try:
        cmd_list = shlex.split(cmd)
        # Use subprocess.run for better control and error handling
        result = subprocess.run(cmd_list, capture_output=True, text=True, check=True, shell=False)
        output = result.stdout
    except subprocess.CalledProcessError as e:
        # Command exited with a non-zero status
        output = f"Error executing command: {e.stderr.strip()}"
        return jsonify({"error": output}), 500
    except FileNotFoundError:
        # Command not found
        output = f"Error: Command '{cmd_list[0]}' not found."
        return jsonify({"error": output}), 400
    except Exception as e:
        # Other unexpected errors
        output = f"An unexpected error occurred: {e}"
        return jsonify({"error": output}), 500

    return jsonify({"output": output})


@app.route("/tasks/calculate", methods=["POST"])
def calculate():
    """Evaluate a mathematical expression for task scoring."""
    data = request.get_json()
    expr = data.get("expression", "0")
    # FIX: Code injection via eval()
    # Replace eval with ast.literal_eval for safe evaluation of literals.
    # Raise ValueError if the expression is non-trivial (e.g., contains function calls).
    try:
        result = ast.literal_eval(expr)
        # Ensure the result is a number or simple type, not an object
        if not isinstance(result, (int, float, bool, type(None))):
            raise ValueError("Expression resulted in an unsupported type.")
    except (ValueError, SyntaxError) as e:
        return jsonify({"error": f"Invalid or unsafe expression: {e}"}), 400
    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred: {e}"}), 500

    return jsonify({"result": str(result)})


# ─── Helpers ──────────────────────────────────────────────────

def hash_password(password):
    """Hash a password for storage using SHA256 with a salt."""
    # FIX: Using MD5 for password hashing
    # Replace with hashlib.sha256 and add a salt.
    # In production, bcrypt or Argon2 should be used for password hashing.
    salt = secrets.token_hex(16) # Generate a random 16-byte salt
    salted_password = salt + password
    hashed_password = hashlib.sha256(salted_password.encode()).hexdigest()
    return f"{salt}:{hashed_password}" # Store salt with hash for verification


# ─── Entry point ──────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    # FIX: Debug mode enabled, binding to all interfaces
    # Use DEBUG from config, and bind to localhost by default.
    # In a production environment, DEBUG should be False.
    app.run(host="127.0.0.1", port=5000, debug=DEBUG)
