"""
Unit tests for the Task Manager API.

These tests validate the basic CRUD behaviour of the application.
They intentionally do NOT cover the vulnerable code-paths directly
(no live shell, no SQL injection) but serve as a regression baseline
so the CI build can confirm the app starts and routes respond.
"""

import json
import pytest
import sys
import os

# Allow importing the app package from the repo root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.main import app, init_db


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """Create a test client with an isolated SQLite database."""
    db_path = str(tmp_path / "test_tasks.db")
    # Patch sqlite3.connect to use the temporary DB
    import sqlite3
    original_connect = sqlite3.connect

    def patched_connect(path, *args, **kwargs):
        if "tasks.db" in str(path):
            return original_connect(db_path, *args, **kwargs)
        return original_connect(path, *args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", patched_connect)

    with app.test_client() as client:
        with app.app_context():
            init_db()
        yield client


# ─── Health ───────────────────────────────────────────────────

def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "healthy"


# ─── Task CRUD ────────────────────────────────────────────────

def test_create_task(client):
    resp = client.post(
        "/tasks",
        data=json.dumps({"title": "Write tests", "description": "Important"}),
        content_type="application/json",
    )
    assert resp.status_code == 201
    assert resp.get_json()["status"] == "created"


def test_get_tasks_empty(client):
    resp = client.get("/tasks")
    assert resp.status_code == 200
    assert resp.get_json() == []


def test_get_tasks(client):
    client.post(
        "/tasks",
        data=json.dumps({"title": "First task"}),
        content_type="application/json",
    )
    resp = client.get("/tasks")
    tasks = resp.get_json()
    assert len(tasks) == 1
    assert tasks[0]["title"] == "First task"


def test_create_task_missing_title(client):
    resp = client.post(
        "/tasks",
        data=json.dumps({"description": "No title here"}),
        content_type="application/json",
    )
    assert resp.status_code == 400


def test_delete_task(client):
    client.post(
        "/tasks",
        data=json.dumps({"title": "Delete me"}),
        content_type="application/json",
    )
    # Get the ID
    tasks = client.get("/tasks").get_json()
    task_id = tasks[0]["id"]

    resp = client.delete(f"/tasks/{task_id}")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "deleted"

    tasks_after = client.get("/tasks").get_json()
    assert tasks_after == []


def test_search_tasks(client):
    client.post(
        "/tasks",
        data=json.dumps({"title": "Security audit"}),
        content_type="application/json",
    )
    resp = client.get("/tasks/search?q=Security")
    assert resp.status_code == 200
    results = resp.get_json()
    assert any("Security" in t["title"] for t in results)
