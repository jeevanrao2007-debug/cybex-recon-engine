"""
gunicorn.conf.py
Gunicorn configuration optimized for cloud container platforms like Render.
"""

import os

# Port binding: Render injects the PORT environment variable
port = os.environ.get("PORT", "5000")
bind = f"0.0.0.0:{port}"

# Worker processes and concurrency
# Default to 2 workers and 4 threads to stay well within Render's free tier (512 MB RAM)
workers = int(os.environ.get("WEB_CONCURRENCY", "2"))
worker_class = "gthread"
threads = int(os.environ.get("PYTHON_THREADS", "4"))

# Timeouts: Allow sufficient time for DNS / RDAP lookups and security assessments
timeout = 120
graceful_timeout = 30
keepalive = 5

# Logging: Standard 12-factor logging to stdout/stderr
accesslog = "-"
errorlog = "-"
loglevel = os.environ.get("LOG_LEVEL", "info")
