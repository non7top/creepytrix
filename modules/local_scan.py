#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Local (on-host) scanner.

Runs on the target host itself -- with authorization -- to answer what remote
black-box scanning cannot: the exact Bitrix platform + module versions, exact
installed web-server package versions, and on-disk config permissions. It then
runs every CVE plugin's host-side ``local_check`` for precise, version-based
confirmation instead of remote guesswork. Read-only and non-destructive.
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any

from utils.localhost import LocalHost

# Bitrix modules worth reporting the exact version of when present.
_MODULES_OF_INTEREST = [
    'main', 'vote', 'translate', 'sale', 'catalog', 'iblock',
    'crm', 'socialnetwork', 'security', 'bitrix24',
]

# Sensitive config files that must not be world-readable / web-exposed.
_SENSITIVE_FILES = [
    'bitrix/.settings.php',
    'bitrix/php_interface/dbconn.php',
    'bitrix/php_interface/after_connect.php',
]


@dataclass
class LocalFinding:
    severity: str                      # critical | high | medium | low | info
    category: str                      # cve | version | permission
    title: str
    detail: str = ''
    evidence: Optional[str] = None
    cve_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LocalResult:
    web_root: Optional[str] = None
    distro: Optional[str] = None
    bitrix_version: Optional[str] = None
    module_versions: Dict[str, str] = field(default_factory=dict)
    findings: List[LocalFinding] = field(default_factory=list)

    def add(self, finding: LocalFinding):
        self.findings.append(finding)

    def _count(self, sev: str) -> int:
        return sum(1 for f in self.findings if f.severity == sev)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'web_root': self.web_root,
            'distro': self.distro,
            'bitrix_version': self.bitrix_version,
            'module_versions': self.module_versions,
            'summary': {
                'total_findings': len(self.findings),
                'critical': self._count('critical'),
                'high': self._count('high'),
                'medium': self._count('medium'),
                'low': self._count('low'),
                'info': self._count('info'),
                'confirmed_vulnerable': sum(
                    1 for f in self.findings
                    if f.category == 'cve' and f.severity in ('critical', 'high')),
            },
            'all_findings': [f.to_dict() for f in self.findings],
        }


class BitrixLocalScanner:
    """Host-side Bitrix / web-server inspection."""

    def __init__(self, logger, web_root: Optional[str] = None):
        self.logger = logger
        self.explicit_root = web_root
        self.host = LocalHost(logger)

    def scan(self, aggressive: bool = False) -> LocalResult:
        result = LocalResult()
        result.distro = self.host.distro_family()

        # 1. Locate the Bitrix document root.
        web_root = self.host.find_web_root(self.explicit_root)
        result.web_root = web_root
        self.host.web_root = web_root
        if not web_root:
            self.logger.warning(
                "No Bitrix web root found (looked for bitrix/modules/main). "
                "Use --web-root to point at the document root.")
        else:
            self.logger.success(f"Bitrix web root: {web_root}")

        # 2. Exact versions (the headline of local mode).
        if web_root:
            version = self.host.bitrix_version(web_root)
            result.bitrix_version = version
            if version:
                self.logger.success(f"Bitrix platform version: {version}")
                result.add(LocalFinding(
                    severity='info', category='version',
                    title='Bitrix platform version',
                    detail=f'Exact installed version: {version}',
                    evidence=version))
            for module in _MODULES_OF_INTEREST:
                mv = self.host.bitrix_module_version(web_root, module)
                if mv:
                    result.module_versions[module] = mv
            if result.module_versions:
                self.logger.info("Module versions: " + ", ".join(
                    f"{k}={v}" for k, v in result.module_versions.items()))

        # 3. CVE plugins' host-side confirmation.
        self._run_plugin_local_checks(result)

        # 4. Config-file permission hygiene (local-only visibility).
        if web_root:
            self._check_permissions(web_root, result)

        return result

    def _run_plugin_local_checks(self, result: LocalResult):
        try:
            from modules.cves import load_plugins
        except Exception as e:  # pragma: no cover
            self.logger.debug(f"CVE plugin registry unavailable: {e}")
            return
        for plugin in load_plugins():
            try:
                outcome = plugin.local_check(self.host)
            except Exception as e:
                self.logger.debug(f"local_check error for {plugin.cve_id}: {e}")
                continue
            if outcome is None:
                continue
            severity = outcome.severity or (
                'critical' if outcome.detected else 'info')
            result.add(LocalFinding(
                severity=severity,
                category='cve',
                title=f'{plugin.cve_id} ({outcome.confidence})',
                detail=outcome.detail,
                evidence=outcome.evidence,
                cve_id=plugin.cve_id))
            if outcome.confidence == 'confirmed' and outcome.detected:
                self.logger.critical(f"CONFIRMED {plugin.cve_id}: {outcome.detail}")
            elif outcome.confidence == 'not_affected':
                self.logger.success(f"{plugin.cve_id}: not affected ({outcome.evidence})")
            else:
                self.logger.warning(f"{plugin.cve_id}: {outcome.detail}")

    def _check_permissions(self, web_root: str, result: LocalResult):
        import os
        for rel in _SENSITIVE_FILES:
            path = os.path.join(web_root, rel)
            wr = self.host.world_readable(path)
            if wr is None:
                continue  # absent
            if wr:
                mode = self.host.mode_octal(path)
                result.add(LocalFinding(
                    severity='high', category='permission',
                    title=f'World-readable config: {rel}',
                    detail=f'{rel} is world-readable (mode {mode}); may leak DB '
                           f'credentials. Restrict to the web-server user.',
                    evidence=f'mode {mode}'))
                self.logger.error(f"World-readable: {rel} (mode {mode})")
