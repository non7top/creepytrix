#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE-2026-42945 -- nginx "NGINX Rift" ngx_http_rewrite_module heap overflow.

This is a WEB-SERVER-layer vulnerability, not a Bitrix application bug, but it
is highly relevant to Bitrix targets: the VMBitrix appliance ships ``bx-nginx``
with the rewrite (urlrewrite) module enabled by default. Unauthenticated heap
buffer overflow -> DoS / potential RCE. Affects nginx 0.6.27 through 1.30.0;
fixed upstream in 1.30.1 / 1.31.0 and in ``bx-nginx 1.30.2``.

Remote detection here is a non-destructive VERSION INFERENCE from the ``Server``
response header. It cannot confirm that a vulnerable ``rewrite``/``set``
directive is actually reachable, so confidence stays 'reachable'.
"""

import re
from urllib.parse import urljoin

from .base import CVECheck, CheckResult

# Last vulnerable version (inclusive). Anything <= this is flagged.
_LAST_VULNERABLE = (1, 30, 0)
_VERSION_RE = re.compile(r'nginx/(\d+)\.(\d+)\.(\d+)', re.IGNORECASE)


class CVE_2026_42945(CVECheck):
    cve_id = 'CVE-2026-42945'
    title = 'nginx "NGINX Rift" rewrite-module heap overflow (unauth RCE/DoS)'
    affected = 'nginx 0.6.27 - 1.30.0 (bx-nginx < 1.30.2); rewrite module enabled'
    severity = 'critical'
    auth = 'unauth'
    references = [
        'https://my.f5.com/manage/s/article/K000161019',
        'https://thehackernews.com/2026/05/18-year-old-nginx-rewrite-module-flaw.html',
    ]
    endpoint = '/'
    notes = (
        'Web-server layer, not Bitrix app code. Detection is Server-header '
        'version inference; it does not prove the rewrite directive is '
        'reachable. VMBitrix ships bx-nginx with rewrite enabled by default.'
    )

    def check(self, requester, base_url):
        resp = requester.get(urljoin(base_url, self.endpoint))
        if not resp:
            return None
        server = ''
        try:
            server = resp.headers.get('Server', '') or ''
        except Exception:
            return None
        m = _VERSION_RE.search(server)
        if not m:
            # nginx present but version suppressed -> report as unknown, not vuln.
            if 'nginx' in server.lower():
                return CheckResult(
                    detected=True,
                    confidence='reachable',
                    evidence=f'Server: {server}',
                    detail=(f'{self.cve_id}: nginx detected but version hidden -- '
                            'cannot determine if patched; verify manually'),
                )
            return None
        version = tuple(int(x) for x in m.groups())
        if version <= _LAST_VULNERABLE:
            return CheckResult(
                detected=True,
                confidence='reachable',
                evidence=f'Server: {server}',
                detail=(f'{self.cve_id}: nginx {".".join(map(str, version))} is '
                        f'<= 1.30.0 (vulnerable range); patch to 1.30.1/1.31.0 or '
                        f'bx-nginx 1.30.2'),
            )
        return None


PLUGIN = CVE_2026_42945()
