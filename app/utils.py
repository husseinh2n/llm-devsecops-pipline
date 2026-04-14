"""
Utility functions for the task manager.
"""
import os
import subprocess
import tempfile


def ping_host(hostname):
    """Ping a host to check connectivity."""
    # VULNERABILITY: Command injection via os.popen
    # Fix: Replace os.popen with subprocess.run using a list of arguments
    result = subprocess.run(["ping", "-c", "1", hostname], capture_output=True, text=True)
    return result.stdout


def generate_report(task_data, output_path):
    """Generate a task report file."""
    # VULNERABILITY: Path traversal — no sanitization of output_path
    with open(output_path, "w") as f:
        for task in task_data:
            f.write(f"{task['title']}: {task['description']}\n")
    return output_path


def run_backup(backup_name):
    """Create a backup of the database."""
    # VULNERABILITY: Command injection via subprocess with shell=True
    # Fix: Replace subprocess.call with subprocess.run, passing command as a list and shell=False
    # The destination path is constructed safely as a single argument.
    subprocess.run(["cp", "tasks.db", f"backups/{backup_name}.db"], check=True)
    return f"Backup created: {backup_name}"
