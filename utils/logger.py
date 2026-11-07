"""
utils/logger.py
Structured JSON logging utility for Cybex Recon Engine.
Logs target assessments without leaking request/response bodies or sensitive payload data.
"""

import json
import logging
import sys
from datetime import datetime, timezone

# Initialize logger
logger = logging.getLogger("cybex_recon")
logger.setLevel(logging.INFO)

# Structured JSON formatter
class StructuredJsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "level": record.levelname,
            "message": record.getMessage(),
        }
        # Safely extract extra fields if present
        if hasattr(record, "extra_fields"):
            log_entry.update(record.extra_fields)
        return json.dumps(log_entry, ensure_ascii=False)


# Clear existing handlers to prevent duplicate formatting output
if logger.hasHandlers():
    logger.handlers.clear()

# Bind stream handler to stdout
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(StructuredJsonFormatter())
logger.addHandler(handler)


def log_assessment(target: str, outcome: str, extra: dict = None) -> None:
    """
    Log target assessment results in a structured format.
    Does NOT log full request/response bodies or any sensitive payload data.

    Parameters
    ----------
    target : str
        The assessed domain, IP, or scenario ID.
    outcome : str
        Outcome of the assessment (e.g., 'success', 'partial', 'failed', 'error').
    extra : dict, optional
        Additional metadata (e.g., scenario, open_services).
    """
    fields = {
        "target": target,
        "outcome": outcome,
    }
    if extra:
        fields.update(extra)

    # Build custom record with extra logging properties
    record = logger.makeRecord(
        name=logger.name,
        level=logging.INFO,
        fn="logger.py",
        lno=0,
        msg=f"Simulated assessment run completed for: {target}",
        args=(),
        exc_info=None,
    )
    record.extra_fields = fields
    logger.handle(record)
