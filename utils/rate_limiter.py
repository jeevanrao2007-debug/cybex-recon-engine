"""
utils/rate_limiter.py
Memory-based rate limiting utility for Flask endpoints.
"""

import time
from collections import defaultdict
from flask import request
from utils.response import error_response
from config import RATE_LIMIT_COOLDOWN

# Simple in-memory tracker: { "ip:target": last_unix_timestamp }
_last_request_times = defaultdict(float)


def limit_assessment_rate(func):
    """
    Decorator to rate limit requests to the assessment/resolution endpoint.
    Identifies clients by combined IP and target to prevent rapid repeated submissions.
    """
    def wrapper(*args, **kwargs):
        # Retrieve client IP and the request JSON body
        ip = request.remote_addr or "127.0.0.1"
        body = request.get_json(silent=True) or {}
        target = body.get("target", "").strip()

        key = f"{ip}:{target}"
        now = time.time()
        last_time = _last_request_times[key]

        if now - last_time < RATE_LIMIT_COOLDOWN:
            remaining = round(RATE_LIMIT_COOLDOWN - (now - last_time), 1)
            # HTTP 429 Too Many Requests
            return error_response(
                f"Rate limit exceeded. Please wait {remaining}s before resubmitting.",
                429,
            )

        _last_request_times[key] = now
        return func(*args, **kwargs)

    # Maintain original function name for Flask routes
    wrapper.__name__ = func.__name__
    return wrapper
