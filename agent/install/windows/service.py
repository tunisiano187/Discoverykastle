"""
Discoverykastle agent — Windows Service wrapper.

Registers the DK agent as a Windows Service named "DiscoverykastleAgent"
so it runs automatically in the background as SYSTEM (or a dedicated user).

Requirements:
  pip install pywin32

Usage (run as Administrator):
  python service.py install    # install the service
  python service.py start      # start it
  python service.py stop       # stop it
  python service.py remove     # uninstall the service
  python service.py debug      # run in console for troubleshooting

The service reads its config from:
  C:\\ProgramData\\Discoverykastle\\Agent\\agent.conf
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import threading
import time
from pathlib import Path

# pywin32 is Windows-only
try:
    import win32event
    import win32service
    import win32serviceutil
    import servicemanager
except ImportError:
    print("pywin32 is required on Windows. Install it with: pip install pywin32")
    sys.exit(1)


SERVICE_NAME = "DiscoverykastleAgent"
SERVICE_DISPLAY_NAME = "Discoverykastle Agent"
SERVICE_DESCRIPTION = (
    "Discoverykastle discovery agent — sends host and Puppet inventory "
    "data to the DK server."
)
DEFAULT_CONFIG = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / \
    "Discoverykastle" / "Agent" / "agent.conf"


class DiscoverykastleAgentService(win32serviceutil.ServiceFramework):
    _svc_name_ = SERVICE_NAME
    _svc_display_name_ = SERVICE_DISPLAY_NAME
    _svc_description_ = SERVICE_DESCRIPTION

    def __init__(self, args: list[str]) -> None:
        win32serviceutil.ServiceFramework.__init__(self, args)
        self._stop_event = win32event.CreateEvent(None, 0, 0, None)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    # Service control
    # ------------------------------------------------------------------

    def SvcStop(self) -> None:
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self._stop_event)
        if self._loop and not self._loop.is_closed():
            self._loop.call_soon_threadsafe(self._loop.stop)

    def SvcDoRun(self) -> None:
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ""),
        )
        self._thread = threading.Thread(target=self._run_agent, daemon=True)
        self._thread.start()

        # Block until stop event is signalled
        win32event.WaitForSingleObject(self._stop_event, win32event.INFINITE)

        if self._thread.is_alive():
            self._thread.join(timeout=15)

        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STOPPED,
            (self._svc_name_, ""),
        )

    # ------------------------------------------------------------------
    # Agent runner (in its own thread so the service framework stays responsive)
    # ------------------------------------------------------------------

    def _run_agent(self) -> None:
        # Ensure the agent source directory is on the path
        agent_src = Path(sys.executable).parent.parent / "src"
        if str(agent_src) not in sys.path:
            sys.path.insert(0, str(agent_src))

        os.environ.setdefault("DKASTLE_AGENT_CONFIG", str(DEFAULT_CONFIG))

        from agent.config import AgentConfig
        from agent.core import DKAgent

        cfg = AgentConfig()
        _setup_win_logging(cfg)

        logger = logging.getLogger("agent.service")
        logger.info("Discoverykastle agent service starting…")

        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            agent = DKAgent(cfg)
            self._loop.run_until_complete(agent.run())
        except Exception:
            logger.exception("Agent crashed — service will restart it")
        finally:
            self._loop.close()


def _setup_win_logging(cfg: "AgentConfig") -> None:  # type: ignore[name-defined]
    import logging.handlers

    log_path = Path(cfg.log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger()
    root.setLevel(getattr(logging, cfg.log_level, logging.INFO))

    fmt = logging.Formatter(
        "%(asctime)s %(levelname)-8s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    fh = logging.handlers.RotatingFileHandler(
        log_path, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    fh.setFormatter(fmt)
    root.addHandler(fh)

    # Also send to Windows Event Log
    try:
        evh = logging.handlers.NTEventLogHandler(SERVICE_NAME)
        evh.setFormatter(fmt)
        root.addHandler(evh)
    except Exception:
        pass


if __name__ == "__main__":
    if len(sys.argv) == 1:
        # Launched by SCM
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(DiscoverykastleAgentService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(DiscoverykastleAgentService)
