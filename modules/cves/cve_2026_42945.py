#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE-2026-42945 -- nginx "NGINX Rift" ngx_http_rewrite_module heap overflow.

Web-SERVER-layer vulnerability (not Bitrix app code) but relevant to Bitrix
targets: the VMBitrix appliance ships ``bx-nginx`` with the rewrite (urlrewrite)
module enabled by default. Unauthenticated heap buffer overflow -> DoS /
potential RCE. Affects nginx 0.6.27 through 1.30.0; fixed upstream in
1.30.1 / 1.31.0 and in ``bx-nginx 1.30.2``.

Remote detection is fundamentally weak and this plugin is honest about it:

* ``server_tokens off`` (common in hardened / VMBitrix configs) strips the
  version from both the ``Server`` header and the default error pages, so most
  of the time there is NO version to read -- only "nginx".
* On Debian/Ubuntu/RHEL the fix is BACKPORTED into the same upstream version
  (e.g. ``1.18.0-6ubuntu14.11``), so even a visible ``1.18.0`` does not tell
  you the patch level.

Therefore this check never asserts "vulnerable" from the header alone. It emits
an advisory to verify on the host (``dpkg -s nginx-core`` / ``rpm -q bx-nginx``
against the distro's fixed version), and at most a low-confidence hint when an
in-range version string is actually exposed.
"""

import re
from urllib.parse import urljoin

from .base import CVECheck, CheckResult

_LAST_VULNERABLE = (1, 30, 0)
_VERSION_RE = re.compile(r'nginx/(\d+)\.(\d+)\.(\d+)', re.IGNORECASE)

_HOST_CHECK = (
    'Verify on host: Debian/Ubuntu `dpkg-query -W -f=\'${Version}\' nginx-core` '
    'then `dpkg --compare-versions <ver> ge <distro-fixed-ver>` (see '
    'ubuntu.com/security/CVE-2026-42945); RHEL/VMBitrix `rpm -q bx-nginx` '
    '(need >= 1.30.2).'
)


class CVE_2026_42945(CVECheck):
    cve_id = 'CVE-2026-42945'
    title = 'nginx "NGINX Rift" rewrite-module heap overflow (unauth RCE/DoS)'
    affected = 'nginx 0.6.27 - 1.30.0 (bx-nginx < 1.30.2); rewrite module enabled'
    severity = 'critical'
    auth = 'unauth'
    references = [
        'https://my.f5.com/manage/s/article/K000161019',
        'https://thehackernews.com/2026/05/18-year-old-nginx-rewrite-module-flaw.html',
        'https://ubuntu.com/security/CVE-2026-42945',
    ]
    endpoint = '/'
    notes = (
        'Web-server layer, not Bitrix app code. Remote header inference is '
        'unreliable: server_tokens often hides the version, and distros '
        'backport the fix without bumping the upstream version. Confirm on host.'
    )

    def _server(self, requester, base_url):
        resp = requester.get(urljoin(base_url, self.endpoint))
        if not resp:
            return None
        try:
            return resp.headers.get('Server', '') or ''
        except Exception:
            return ''

    def check(self, requester, base_url):
        server = self._server(requester, base_url)
        if server is None or 'nginx' not in server.lower():
            return None  # nginx not identifiable -> nothing to advise on

        m = _VERSION_RE.search(server)
        if not m:
            # Common case: server_tokens off -> "nginx" with no version.
            return CheckResult(
                detected=True,
                confidence='reachable',
                severity='info',
                evidence=f'Server: {server}',
                detail=(f'{self.cve_id}: nginx present but version not exposed '
                        f'-- remote assessment impossible. {_HOST_CHECK}'),
            )

        version = tuple(int(x) for x in m.groups())
        if version <= _LAST_VULNERABLE:
            return CheckResult(
                detected=True,
                confidence='reachable',
                severity='medium',   # in-range, but backports may already patch it
                evidence=f'Server: {server}',
                detail=(f'{self.cve_id}: nginx {".".join(map(str, version))} is in '
                        f'the vulnerable upstream range (<= 1.30.0), BUT distro '
                        f'backports keep this version string after patching, so '
                        f'this is not proof. {_HOST_CHECK}'),
            )
        # Version above the vulnerable range -> not affected upstream.
        return None


PLUGIN = CVE_2026_42945()
