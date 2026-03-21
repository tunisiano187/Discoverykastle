"""
Module Loader — discovers and loads modules from two sources:

  1. Python entry points (pip-installed packages that declare
     discoverykastle.modules entry point group)

  2. Local directory — $DKASTLE_MODULES_DIR (default: ./modules/)
     Each subdirectory must contain a `module.py` with a class that
     subclasses BaseModule and is named `Module`.

Built-in modules are always registered first, then external ones.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import importlib.util
import logging
import os
import sys
from pathlib import Path

from server.modules.base import BaseModule
from server.modules.registry import registry

logger = logging.getLogger(__name__)

ENTRY_POINT_GROUP = "discoverykastle.modules"
DEFAULT_MODULES_DIR = Path("modules")

_BUILTIN_MODULES = [
    "server.modules.builtin.alerts.module",
    "server.modules.builtin.inventory.module",
    "server.modules.builtin.topology.module",
    "server.modules.builtin.netbox.module",
    # DNS enrichment — reverse PTR lookups + SOA domain detection.
    # Controlled by DKASTLE_DNS_RESOLVE_ENABLED (default: true).
    "server.modules.builtin.dns.module",
    # Puppet integration — imports node facts from PuppetDB.
    # Disabled by default; requires DKASTLE_PUPPETDB_ENABLED=true.
    "server.modules.builtin.puppet.module",
    # Ansible integration — imports facts from AWX/Tower or fact-cache.
    # Disabled by default; requires DKASTLE_ANSIBLE_ENABLED=true.
    "server.modules.builtin.ansible.module",
    # AI enrichment — disabled by default; activates only when
    # DKASTLE_AI_ENABLED=true and DKASTLE_ANTHROPIC_API_KEY is set.
    "server.modules.builtin.ai.module",
]


def load_all(modules_dir: Path | None = None) -> None:
    """Load built-in modules, then entry-point modules, then directory modules."""
    _load_builtins()
    _load_entry_points()
    _load_from_directory(modules_dir or DEFAULT_MODULES_DIR)


def _load_builtins() -> None:
    for dotpath in _BUILTIN_MODULES:
        try:
            mod = importlib.import_module(dotpath)
            klass = getattr(mod, "Module", None)
            if klass is None or not issubclass(klass, BaseModule):
                logger.warning("Built-in module '%s' has no valid Module class.", dotpath)
                continue
            registry.register(klass())
        except Exception:
            logger.exception("Failed to load built-in module '%s'", dotpath)


def _load_entry_points() -> None:
    try:
        eps = importlib.metadata.entry_points(group=ENTRY_POINT_GROUP)
    except Exception:
        logger.debug("entry_points lookup failed (Python < 3.12 fallback may be needed)")
        return

    for ep in eps:
        try:
            klass = ep.load()
            if not issubclass(klass, BaseModule):
                logger.warning("Entry point '%s' is not a BaseModule subclass.", ep.name)
                continue
            registry.register(klass())
            logger.info("Loaded module from entry point: %s", ep.name)
        except Exception:
            logger.exception("Failed to load entry point module '%s'", ep.name)


def _load_from_directory(modules_dir: Path) -> None:
    if not modules_dir.exists():
        return

    for subdir in sorted(modules_dir.iterdir()):
        if not subdir.is_dir():
            continue
        module_file = subdir / "module.py"
        if not module_file.exists():
            logger.warning(
                "Directory '%s' in modules/ has no module.py — skipping.", subdir.name
            )
            continue

        try:
            spec = importlib.util.spec_from_file_location(
                f"dkastle_ext_{subdir.name}", module_file
            )
            if spec is None or spec.loader is None:
                continue
            mod = importlib.util.module_from_spec(spec)
            sys.modules[f"dkastle_ext_{subdir.name}"] = mod
            spec.loader.exec_module(mod)  # type: ignore[arg-type]

            klass = getattr(mod, "Module", None)
            if klass is None or not issubclass(klass, BaseModule):
                logger.warning(
                    "Module directory '%s/module.py' has no valid Module class.", subdir.name
                )
                continue

            # Pass optional config from env or a config.yaml in the directory
            config = _read_module_config(subdir)
            registry.register(klass(config=config))
            logger.info("Loaded external module from directory: %s", subdir.name)
        except Exception:
            logger.exception("Failed to load module from directory '%s'", subdir.name)


def _read_module_config(module_dir: Path) -> dict:
    """Optionally load a config.yaml from the module directory."""
    config_file = module_dir / "config.yaml"
    if not config_file.exists():
        return {}
    try:
        import yaml  # type: ignore[import]
        with config_file.open() as f:
            return yaml.safe_load(f) or {}
    except ImportError:
        logger.debug("PyYAML not installed — skipping config.yaml for module '%s'", module_dir.name)
    except Exception:
        logger.exception("Failed to read config.yaml for module '%s'", module_dir.name)
    return {}
