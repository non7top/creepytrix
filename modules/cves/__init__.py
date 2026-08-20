#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Per-CVE plugin registry.

Auto-discovers every ``cve_*.py`` module in this package and collects its
module-level ``PLUGIN`` instance. Add a new CVE by dropping a new
``cve_<id>.py`` file here -- no other file needs to change.
"""

import importlib
import pkgutil
from typing import List

from .base import CVECheck, CheckResult

__all__ = ['CVECheck', 'CheckResult', 'load_plugins']


def load_plugins() -> List[CVECheck]:
    """Discover and instantiate all CVE plugins, sorted by CVE id."""
    plugins: List[CVECheck] = []
    for _finder, name, _ispkg in pkgutil.iter_modules(__path__):
        if not name.startswith('cve_'):
            continue
        module = importlib.import_module(f'{__name__}.{name}')
        plugin = getattr(module, 'PLUGIN', None)
        if plugin is not None:
            plugins.append(plugin)
    plugins.sort(key=lambda p: p.cve_id)
    return plugins
