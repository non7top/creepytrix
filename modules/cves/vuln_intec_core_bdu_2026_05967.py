#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BDU:2026-05967 -- INTEC:Ядро (intec.core) unauthenticated RCE (CWE-94, CVSS 9.8).

INTEC is a third-party 1C-Bitrix marketplace vendor. Its intec.core module
exposes template AJAX/component entry points (e.g. templates' request.php) that
load via prolog_before.php instead of prolog_admin_before.php -- so they run
WITHOUT an admin-rights check. That lets an unauthenticated attacker drive
arbitrary Bitrix components (bitrix:main.file.input to upload, bitrix:main.include
to include the upload as PHP), or inject PHP that is eval'd on render -> RCE.

No CVE (Russian-ecosystem vendor); tracked as BDU:2026-05967 (FSTEC).
Affected: intec.core <= 1.2.29. Fixed: 1.2.30 (30.04.2026, changelog labelled
only "правки и улучшения" -- a silently-disclosed critical fix).

This plugin is PASSIVE:
- local_check(): authoritative -- reads the installed intec.core version and
  compares against 1.2.30. No requests, no writes.
- check() [remote]: detects that the intec component-runner is EXPOSED (the
  attack surface) with a harmless GET that renders the file-input widget -- it
  uploads nothing and executes nothing. Remote can't read the version, so it
  reports surface-reachable, not a confirmed version.
"""

from urllib.parse import urljoin

from .base import CVECheck, CheckResult
from utils.http_heuristics import is_denied_or_login


class VULN_IntecCore_BDU_2026_05967(CVECheck):
    cve_id = 'BDU:2026-05967'
    title = 'INTEC intec.core unauthenticated RCE (arbitrary IncludeComponent)'
    affected = 'INTEC intec.core <= 1.2.29 (fixed 1.2.30)'
    severity = 'critical'
    auth = 'unauth'
    references = [
        'https://bdu.fstec.ru/vul/2026-05967',
        'https://www.cyberok.ru/news/2026-05-20/',
        'https://sp.intecweb.ru/kb/articles/371265-uyazvimost-saytov-k-virusam-obnovlenie-bezopasnosti-dlya-resheniy-universe/',
        'https://www.1c-bitrix.ru/vul_dev/',
    ]

    FIXED_VERSION = (1, 2, 30)

    # A harmless GET that renders the file-input component via the intec runner.
    # Uploads nothing (uploads require a multipart POST to the ajax endpoint).
    _PROBE_TOKEN = 'ct_probe_le0'
    _PROBE_PARAMS = {
        'page[request]': 'y',
        'page[page]': 'components.get',
        'component': 'bitrix:main.file.input',
        'parameters[INPUT_NAME]': _PROBE_TOKEN,
        'parameters[ALLOW_UPLOAD]': 'A',
        'parameters[ALLOW_UPLOAD_EXT]': '',
        'parameters[MODULE_ID]': 'main',
        'parameters[MULTIPLE]': 'N',
    }

    # ---- local (authoritative) ----
    def local_check(self, host):
        if not host.web_root:
            return None
        ver = host.bitrix_module_version(host.web_root, 'intec.core')
        if not ver:
            return None  # module not installed -> not applicable
        vulnerable = host.version_tuple(ver) < self.FIXED_VERSION
        return CheckResult(
            detected=vulnerable,
            confidence='confirmed' if vulnerable else 'not_affected',
            severity='critical' if vulnerable else 'info',
            evidence=f'intec.core {ver}',
            detail=(f'{self.cve_id}: {"VULNERABLE" if vulnerable else "patched"} '
                    f'-- intec.core {ver} vs fixed 1.2.30. '
                    + ('Unauthenticated RCE (CVSS 9.8, CWE-94), ACTIVELY EXPLOITED '
                       'IN THE WILD (mass web-shell campaigns; ~12k sites per '
                       'CyberOK/СКИПА). Update to >= 1.2.30, redeploy templates, '
                       'remove backdoors, and check the DB for injected eval() code.'
                       if vulnerable else '')),
        )

    # ---- remote (passive surface detection) ----
    def check(self, requester, base_url):
        resp = requester.get(urljoin(base_url, '/'), params=self._PROBE_PARAMS)
        if not resp or getattr(resp, 'status_code', None) != 200:
            return None
        body = getattr(resp, 'text', '') or ''
        if not body.strip() or is_denied_or_login(body):
            return None
        # The intec runner rendered the file-input widget: our INPUT_NAME token
        # is reflected and file-input markers are present.
        token_reflected = self._PROBE_TOKEN in body
        widget_marker = any(m in body.lower() for m in (
            'main.file.input', 'bx-input-file', 'bx-file', 'mfi_mode', 'input-file'))
        if not (token_reflected and widget_marker):
            return None
        return CheckResult(
            detected=True,
            confidence='reachable',
            severity='high',
            evidence=body[:160],
            detail=(f'{self.cve_id}: intec component-runner is EXPOSED -- unauthenticated '
                    'RCE surface (arbitrary IncludeComponent), CVSS 9.8, ACTIVELY '
                    'EXPLOITED IN THE WILD. Version not remotely visible -- confirm '
                    'with local check / update intec.core to >= 1.2.30.'),
        )


PLUGIN = VULN_IntecCore_BDU_2026_05967()
