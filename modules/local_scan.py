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
    'intec.core', 'intec.universe', 'intec.garderob', 'intec.startshop',
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

    def __init__(self, logger, web_root: Optional[str] = None, db_scan: bool = False):
        self.logger = logger
        self.explicit_root = web_root
        self.db_scan = db_scan
        self.host = LocalHost(logger)

    def scan(self, aggressive: bool = False) -> LocalResult:
        result = LocalResult()
        result.distro = self.host.distro_family()

        # 1. Locate the Bitrix document root. Bail out if this is not a Bitrix
        #    installation -- local mode only makes sense against one.
        web_root = self.host.find_web_root(self.explicit_root)
        result.web_root = web_root
        self.host.web_root = web_root
        if not web_root:
            if self.explicit_root:
                self.logger.error(
                    f"Not a Bitrix installation: {self.explicit_root} "
                    "(no bitrix/modules/main found). Aborting local scan.")
            else:
                self.logger.error(
                    "No Bitrix web root found (looked for bitrix/modules/main in "
                    "common document roots). Point at it with --web-root PATH. "
                    "Aborting local scan.")
            return result

        # 2. Exact versions (the headline of local mode). The web root, platform
        #    version and full module inventory are reported once, together, in
        #    the results summary (print_local_results) rather than logged live
        #    here -- that keeps the scan stream to findings/verdicts only.
        version = self.host.bitrix_version(web_root)
        result.bitrix_version = version
        if version:
            result.add(LocalFinding(
                severity='info', category='version',
                title='Bitrix platform version',
                detail=f'Exact installed version: {version}',
                evidence=version))
        for module in _MODULES_OF_INTEREST:
            mv = self.host.bitrix_module_version(web_root, module)
            if mv:
                result.module_versions[module] = mv

        # 3. CVE plugins' host-side confirmation.
        covered_codes = self._run_plugin_local_checks(result)

        # 3b. Data-driven marketplace-module version check (1C-Bitrix vul_dev).
        #     Skip modules a dedicated CVE plugin already reported (avoids
        #     double-flagging, e.g. intec.core via both BDU:2026-05967 and here).
        self._check_vuln_modules(web_root, result, skip_codes=covered_codes)

        # 4. Config-file permission hygiene (local-only visibility).
        if web_root:
            self._check_permissions(web_root, result)

        # 5. Optional DB scan for injected eval() (--db-scan). DB restores are
        #    commonly skipped, so injected code often survives a webroot restore.
        if self.db_scan:
            self._scan_database(web_root, result)

        # If anything serious turned up, point at the cleanup tool.
        if any(f.severity in ('critical', 'high') and f.category in ('cve', 'db', 'module')
               for f in result.findings):
            self.logger.warning(
                f"Cleanup tool available: php tools/bitrix_cleanup.php --root={web_root} "
                "(dry-run by default; add --fix to quarantine + remove backdoors)")

        return result

    def _check_vuln_modules(self, web_root: str, result: LocalResult,
                            skip_codes: Optional[set] = None) -> set:
        """Flag installed marketplace modules older than their fixed version.

        Data-driven from data/bitrix_vuln_modules.json (synced from the
        1C-Bitrix vul_dev registry). ``skip_codes`` are module codes already
        reported by a dedicated CVE plugin -- skipped here to avoid duplicates.
        """
        import json
        import os
        skip_codes = skip_codes or set()
        path = os.path.join(os.path.dirname(__file__), '..', 'data', 'bitrix_vuln_modules.json')
        try:
            with open(path, encoding='utf-8') as f:
                registry = json.load(f)
        except Exception as e:
            self.logger.debug(f"vuln-module registry unavailable: {e}")
            return set()
        mod_list = registry.get('modules', [])
        installed_count = 0
        vulnerable_count = 0
        checked_codes = set()

        for mod in mod_list:
            code = mod.get('code')
            fixed = mod.get('fixed')
            if not code or not fixed:
                continue
            if code in skip_codes:
                continue  # already covered by a dedicated CVE plugin
            installed = self.host.bitrix_module_version(web_root, code)
            if not installed:
                continue
            installed_count += 1
            checked_codes.add(code)
            result.module_versions[code] = installed
            name = mod.get('name', '')
            published = mod.get('published', '')
            fix_link = mod.get('fix_link', '')

            if self.host.version_tuple(installed) < self.host.version_tuple(fixed):
                vulnerable_count += 1
                result.add(LocalFinding(
                    severity='high', category='module',
                    title=f'Vulnerable module: {code} {installed} < {fixed}',
                    detail=f'{name} -- installed {installed}, fixed in {fixed} '
                           f'(1C-Bitrix vul_dev, {published}). Update it. {fix_link}',
                    evidence=f'{code} {installed}'))
                self.logger.error(f"Vulnerable module: {code}={installed} < fixed {fixed} ({name})")
            # Patched modules aren't logged per-module (the version shows in the
            # inventory; the aggregate line below confirms they're up to date).

        if vulnerable_count == 0:
            if installed_count > 0:
                self.logger.success(f"Checked vul_dev registry: {installed_count} marketplace module(s) installed, all up to date")
            else:
                self.logger.info(f"Checked vul_dev registry ({len(mod_list)} rules): none installed on target")
        return checked_codes

    def _run_plugin_local_checks(self, result: LocalResult) -> set:
        """Run every CVE plugin's host-side check. Returns the set of
        marketplace module codes a plugin authoritatively covered, so the
        registry check can skip them and not report the same module twice."""
        covered_codes = set()
        try:
            from modules.cves import load_plugins
        except Exception as e:  # pragma: no cover
            self.logger.debug(f"CVE plugin registry unavailable: {e}")
            return covered_codes
        for plugin in load_plugins():
            try:
                outcome = plugin.local_check(self.host)
            except Exception as e:
                self.logger.debug(f"local_check error for {plugin.cve_id}: {e}")
                continue
            if outcome is None:
                continue
            code = getattr(plugin, 'module_code', None)
            if code:
                covered_codes.add(code)
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
                self.logger.critical(f"CONFIRMED {outcome.detail}")
            elif outcome.confidence == 'not_affected':
                self.logger.success(f"{plugin.cve_id}: not affected ({outcome.evidence})")
            else:
                self.logger.warning(outcome.detail)
        return covered_codes

    def _scan_database(self, web_root: str, result: LocalResult):
        import os
        import subprocess
        from utils.db_scan import scan_dump, known_eval_table

        cfg = self.host.bitrix_db_config(web_root)
        if not cfg:
            self.logger.warning("DB scan skipped: could not read DB config (php/.settings.php).")
            return
        if not self.host.has('mysqldump'):
            self.logger.warning("DB scan skipped: mysqldump not found.")
            return

        self.logger.info(f"Scanning database '{cfg['database']}' for injected eval()/webshell code...")
        env = dict(os.environ, MYSQL_PWD=cfg['password'])
        cmd = ['mysqldump', '--single-transaction', '--no-tablespaces',
               '--skip-lock-tables', '--hex-blob',
               '-h', cfg['host'] or 'localhost', '-u', cfg['login'], cfg['database']]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, env=env,
                                    text=True, errors='replace', bufsize=1)
        except Exception as e:
            self.logger.warning(f"DB scan failed to start mysqldump: {e}")
            return

        per_table = {}
        strong_shown = 0
        for table, severity, snippet in scan_dump(iter(proc.stdout.readline, '')):
            per_table.setdefault(table, {'critical': 0, 'high': 0})[severity] += 1
            if severity == 'critical' and strong_shown < 20:
                loc = ' [known code-exec table]' if known_eval_table(table) else ''
                result.add(LocalFinding(
                    severity='critical', category='db',
                    title=f'Injected code in DB table {table}{loc}',
                    detail=snippet, evidence=table))
                self.logger.critical(f"DB INJECTION in {table}{loc}: {snippet[:120]}")
                strong_shown += 1
        proc.wait()

        if not per_table:
            self.logger.success("DB scan: no eval/webshell signatures found.")
            return
        for table, counts in sorted(per_table.items(), key=lambda x: -(x[1]['critical'] * 100 + x[1]['high'])):
            loc = ' (known code-exec location)' if known_eval_table(table) else ''
            self.logger.info(f"  DB signatures in {table}: "
                             f"{counts['critical']} strong / {counts['high']} weak{loc}")
        # Weak-only tables still warrant a single medium finding to review.
        weak_tables = [t for t, c in per_table.items() if c['critical'] == 0 and c['high'] > 0]
        if weak_tables:
            result.add(LocalFinding(
                severity='medium', category='db',
                title='Weak eval/base64 signatures in DB (review)',
                detail='Tables with weak signatures (may be legitimate): '
                       + ', '.join(sorted(weak_tables)[:15]),
                evidence=str(len(weak_tables)) + ' tables'))

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
