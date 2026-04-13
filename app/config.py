"""
Application configuration.
"""
import os

# ──────────────────────────────────────────────────────────────
#  VULNERABILITY: Hardcoded secrets
#  TruffleHog will flag every credential below.
# ──────────────────────────────────────────────────────────────
SECRET_KEY = "flask-secret-key-do-not-use-in-production-8f3k29d"
DATABASE_URL = "postgresql://admin:SuperSecret123!@db.internal:5432/taskmanager"
API_TOKEN = "ghp_1234567890abcdefABCDEF1234567890abcd"

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# ──────────────────────────────────────────────────────────────
#  Application settings
# ──────────────────────────────────────────────────────────────
DEBUG = True
HOST = "0.0.0.0"
PORT = 5000
