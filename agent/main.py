"""
DK Agent — entry point.

Usage:
  python -m agent                         # run with default config
  python -m agent --config /path/to/conf  # explicit config file
  python -m agent --enroll                # force re-enrollment
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import logging.handlers
import sys
from pathlib import Path

from agent.config import AgentConfig
from agent.core import DKAgent


def _setup_logging(cfg: AgentConfig) -> None:
    root = logging.getLogger()
    root.setLevel(getattr(logging, cfg.log_level, logging.INFO))

    fmt = logging.Formatter(
        "%(asctime)s %(levelname)-8s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    root.addHandler(console)

    # Rotating file handler
    log_path = Path(cfg.log_file)
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=10 * 1024 * 1024,   # 10 MB
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setFormatter(fmt)
        root.addHandler(file_handler)
    except OSError as exc:
        logging.warning("Could not open log file %s: %s", log_path, exc)


async def _main(args: argparse.Namespace) -> None:
    cfg = AgentConfig(config_path=args.config)
    _setup_logging(cfg)

    logger = logging.getLogger("agent")
    logger.info("Discoverykastle agent starting…")

    if not cfg.server_url:
        logger.error(
            "DKASTLE_SERVER_URL is not configured. "
            "Set it in %s or as an environment variable.",
            cfg.config_path,
        )
        sys.exit(1)

    agent = DKAgent(cfg)

    if args.enroll:
        # Force re-enrollment even if already registered
        await agent.enroll()
        logger.info("Enrollment complete. Restart the agent to begin collecting.")
        return

    await agent.run()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="dkagent",
        description="Discoverykastle agent — runs natively on Ubuntu, Debian, Windows",
    )
    parser.add_argument(
        "--config", "-c",
        metavar="PATH",
        type=Path,
        default=None,
        help="Path to the agent config file (default: platform-specific)",
    )
    parser.add_argument(
        "--enroll",
        action="store_true",
        help="Force enrollment with the DK server and exit",
    )
    args = parser.parse_args()

    try:
        asyncio.run(_main(args))
    except KeyboardInterrupt:
        print("\nAgent stopped.")


if __name__ == "__main__":
    main()
