"""
Discoverykastle — Structured Logging Configuration

Priority (all active simultaneously unless explicitly disabled):

  1. Console — always active; human-readable format; respects LOG_LEVEL.

  2. Rotating JSON file — always active unless DKASTLE_LOG_FILE is set to "".
     Default path: discoverykastle.log (20 MB × 10 files).
     Each line is a JSON object with all structured fields, suitable for
     ingestion by any log aggregator (Filebeat, Fluentd, Loki, etc.).

  3. Graylog GELF/UDP — active only when DKASTLE_GRAYLOG_HOST is set.
     Requires: pip install 'discoverykastle-server[graylog]'
     All extra= fields are forwarded as additional GELF fields (prefixed
     with "_" by graypy automatically).

Structured fields convention
─────────────────────────────
Every log call that describes a specific action should include relevant extra
fields so logs can be filtered and aggregated precisely in Graylog / Kibana.

Recommended fields by context:

  Network / inventory events:
    action       — what was done, e.g. "import_prefixes", "host_discovered"
    host_ip      — primary IP of the affected host
    host_fqdn    — FQDN if available
    network_cidr — CIDR of the affected network
    device_name  — hostname of a network device
    count        — number of records created/updated/skipped

  Performance:
    duration_ms  — how long the operation took

  Errors / skips:
    reason       — why something was skipped or failed
    netbox_id    — NetBox object id when relevant

  Module lifecycle:
    module       — module name (set automatically via self.logger)
    event        — lifecycle event (setup, teardown, import, sync)

Example usage in a module:
    import time
    t0 = time.monotonic()
    # ... do work ...
    self.logger.info(
        "NetBox prefixes imported",
        extra={
            "action": "import_prefixes",
            "count_created": 12,
            "count_updated": 3,
            "count_skipped": 1,
            "duration_ms": round((time.monotonic() - t0) * 1000),
        },
    )
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import socket
from datetime import datetime, timezone
from typing import Any


class _JsonFormatter(logging.Formatter):
    """
    Format log records as single-line JSON objects.

    All keys added via extra={...} are included as top-level fields.
    This makes every record self-describing and directly ingestible by
    any log aggregator without needing a custom parser.
    """

    # Internal logging machinery — never include these in the output
    _SKIP = frozenset({
        "args", "created", "exc_info", "exc_text", "filename", "funcName",
        "levelno", "lineno", "module", "msecs", "msg", "pathname",
        "process", "processName", "relativeCreated", "stack_info",
        "thread", "threadName", "taskName",
    })

    def format(self, record: logging.LogRecord) -> str:
        if record.exc_info and not record.exc_text:
            record.exc_text = self.formatException(record.exc_info)

        doc: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Include all extra fields
        for key, val in record.__dict__.items():
            if key not in self._SKIP and not key.startswith("_") and key not in doc:
                doc[key] = val

        if record.exc_text:
            doc["exception"] = record.exc_text

        return json.dumps(doc, default=str, ensure_ascii=False)


def setup_logging() -> None:
    """
    Configure the root logger for Discoverykastle.

    Must be called once, at the very start of main.py, before any other
    module initializes its own logger.
    """
    from server.config import settings

    level = getattr(logging, settings.log_level.upper(), logging.INFO)

    root = logging.getLogger()
    root.setLevel(level)

    # Clear any handlers that may have been added by basicConfig or imports
    root.handlers.clear()

    # ------------------------------------------------------------------ #
    # 1. Console — always active, human-readable
    # ------------------------------------------------------------------ #
    console = logging.StreamHandler()
    console.setLevel(level)
    console.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    ))
    root.addHandler(console)

    _boot = logging.getLogger("dkastle.logging")

    # ------------------------------------------------------------------ #
    # 2. Rotating JSON file — always active unless log_file is ""
    # ------------------------------------------------------------------ #
    if settings.log_file:
        try:
            file_handler = logging.handlers.RotatingFileHandler(
                settings.log_file,
                maxBytes=20 * 1024 * 1024,  # 20 MB per file
                backupCount=10,
                encoding="utf-8",
            )
            file_handler.setLevel(level)
            file_handler.setFormatter(_JsonFormatter())
            root.addHandler(file_handler)
            _boot.info(
                "File logging active",
                extra={"action": "logging_setup", "log_file": settings.log_file},
            )
        except OSError as exc:
            _boot.warning(
                "Cannot open log file '%s' (%s) — file logging disabled.",
                settings.log_file, exc,
                extra={"action": "logging_setup", "reason": str(exc)},
            )

    # ------------------------------------------------------------------ #
    # 3. Graylog GELF/UDP — active only when graylog_host is set
    # ------------------------------------------------------------------ #
    if settings.graylog_host:
        try:
            import graypy  # type: ignore[import-untyped]

            gelf = graypy.GELFUDPHandler(
                host=settings.graylog_host,
                port=settings.graylog_port,
                facility=settings.graylog_facility,
                localname=socket.gethostname(),
                chunk_size=1420,
            )
            gelf.setLevel(level)
            root.addHandler(gelf)
            _boot.info(
                "Graylog GELF logging active",
                extra={
                    "action": "logging_setup",
                    "graylog_host": settings.graylog_host,
                    "graylog_port": settings.graylog_port,
                    "facility": settings.graylog_facility,
                },
            )
        except ImportError:
            _boot.warning(
                "DKASTLE_GRAYLOG_HOST is set but 'graypy' is not installed. "
                "Run: pip install 'discoverykastle-server[graylog]'",
                extra={"action": "logging_setup", "reason": "graypy_not_installed"},
            )
        except Exception as exc:
            _boot.warning(
                "Failed to configure Graylog handler: %s — Graylog disabled.",
                exc,
                extra={"action": "logging_setup", "reason": str(exc)},
            )

    # ------------------------------------------------------------------ #
    # Silence noisy third-party loggers that pollute the output
    # ------------------------------------------------------------------ #
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
