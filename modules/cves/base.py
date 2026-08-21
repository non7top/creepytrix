#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Base classes for per-CVE plugins.

Each real Bitrix CVE lives in its own ``cve_*.py`` module that defines a
subclass of :class:`CVECheck` and exposes it as a module-level ``PLUGIN``
instance. The registry in ``modules/cves/__init__.py`` auto-discovers them.

A plugin's ``check()`` returns a :class:`CheckResult` (or ``None`` when nothing
was observed). The default implementation performs a non-destructive
*reachability* probe: it requests the vulnerable endpoint and looks for a
tell-tale ``marker`` in the response. Reachability is NOT proof of
exploitation -- a plugin that implements a real (still non-destructive) proof
should override ``check()`` and return ``confidence='confirmed'``.
"""

from dataclasses import dataclass
from typing import Optional, List, Dict, Any
from urllib.parse import urljoin


@dataclass
class CheckResult:
    """Outcome of a single CVE check."""
    detected: bool
    confidence: str          # 'reachable' | 'confirmed'
    evidence: str = ''
    detail: str = ''
    severity: Optional[str] = None   # optional per-result override (else derived)


class CVECheck:
    """
    Base class for a per-CVE plugin.

    Subclasses set the class attributes below. For simple cases that is all
    that is needed -- the default :meth:`check` handles the reachability probe.
    Override :meth:`check` to implement a richer (non-destructive) proof.
    """

    cve_id: str = ''
    title: str = ''
    affected: str = ''            # affected product / version range
    # Marketplace module code this plugin authoritatively covers (e.g.
    # 'intec.core'). When set, the data-driven vul_dev registry check skips this
    # code so the module is not reported twice (once by the plugin, once by the
    # generic registry). None => the registry check owns it.
    module_code: Optional[str] = None
    severity: str = 'high'        # critical | high | medium | low
    auth: str = 'unauth'          # unauth | authenticated | admin
    disputed: bool = False        # vendor disputes the classification
    references: List[str] = []

    # Defaults used by the built-in reachability probe:
    endpoint: Optional[str] = None
    method: str = 'GET'
    payload: Optional[Dict[str, Any]] = None
    marker: Optional[str] = None  # substring in response => reachable
    notes: str = ''

    def check(self, requester, base_url: str) -> Optional[CheckResult]:
        """Default non-destructive reachability probe."""
        if not self.endpoint:
            return None
        url = urljoin(base_url, self.endpoint)
        if self.method.upper() == 'POST':
            resp = requester.post(url, data=self.payload or {})
        else:
            resp = requester.get(url, params=self.payload or None)
        if not resp:
            return None
        if self.marker and self.marker in resp.text:
            return CheckResult(
                detected=True,
                confidence='reachable',
                evidence=resp.text[:200],
                detail=f'{self.cve_id} endpoint reachable (not confirmed exploitable)',
            )
        return None

    def local_check(self, host):
        """Host-side confirmation for local mode. Default: not implemented.

        ``host`` is a :class:`utils.localhost.LocalHost`. Override to inspect
        installed package versions / on-disk config and return a
        :class:`CheckResult` with confidence ``'confirmed'`` (vulnerable) or
        ``'not_affected'`` (patched), or ``None`` when inconclusive / N/A.
        """
        return None
