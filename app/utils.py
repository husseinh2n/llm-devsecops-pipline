"""
Utility functions for the task manager.
"""
import os
import subprocess
import tempfile


def ping_host(hostname):
    """Ping a host to check connectivity."""
    # VULNERABILITY: Command injection via os.popen
    result = os.popen(f"ping -c 1 {hostname}").read()
    return result


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
    cmd = f"cp tasks.db backups/{backup_name}.db"
    subprocess.call(cmd, shell=True)
    return f"Backup created: {backup_name}"
