"""
Utility functions for the task manager.
"""
import os
import subprocess
import tempfile


def ping_host(hostname):
    """Ping a host to check connectivity."""
    # VULNERABILITY: Command injection via os.popen
    # FIX: Replaced os.popen with subprocess.run using a list of arguments and capturing output.
    try:
        result = subprocess.run(['ping', '-c', '1', hostname], capture_output=True, text=True, check=False)
        return result.stdout
    except FileNotFoundError:
        return "Error: 'ping' command not found."
    except Exception as e:
        return f"An error occurred: {e}"


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
    # FIX: Replaced subprocess.call with subprocess.run, passing command as a list and setting shell=False.
    try:
        destination_path = os.path.join("backups", f"{backup_name}.db")
        subprocess.run(["cp", "tasks.db", destination_path], check=True, shell=False)
        return f"Backup created: {backup_name}"
    except FileNotFoundError:
        return "Error: 'cp' command not found."
    except subprocess.CalledProcessError as e:
        return f"Backup failed: {e}"
    except Exception as e:
        return f"An error occurred during backup: {e}"
