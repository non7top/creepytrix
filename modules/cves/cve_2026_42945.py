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

# Ubuntu per-release fixed package versions (from ubuntu.com/security).
_UBUNTU_FIXED = {
    'noble': '1.24.0-2ubuntu7.8',
    'jammy': '1.18.0-6ubuntu14.11',
    'focal': '1.18.0-0ubuntu1.7+esm1',
}
# bx-nginx (RHEL/VMBitrix) is fixed in this build.
_BXNGINX_FIXED = (1, 30, 2)

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


    def local_check(self, host):
        """Confirm on-host by resolving the installed package version."""
        family = host.distro_family()

        # Debian / Ubuntu: compare nginx-core against the release's fixed rev.
        deb_ver = host.dpkg_version('nginx-core') or host.dpkg_version('nginx')
        if deb_ver:
            codename = host.os_codename()
            fixed = _UBUNTU_FIXED.get(codename)
            if fixed:
                ge = host.compare_deb(deb_ver, 'ge', fixed)
                if ge is True:
                    return CheckResult(
                        detected=False, confidence='not_affected', severity='info',
                        evidence=f'nginx-core {deb_ver} (>= {fixed})',
                        detail=(f'{self.cve_id}: patched -- installed {deb_ver} '
                                f'>= {codename} fixed {fixed}.'))
                if ge is False:
                    return CheckResult(
                        detected=True, confidence='confirmed', severity='critical',
                        evidence=f'nginx-core {deb_ver} (< {fixed})',
                        detail=(f'{self.cve_id}: VULNERABLE -- installed {deb_ver} '
                                f'< {codename} fixed {fixed}. Run apt-get update && '
                                f'apt-get install --only-upgrade nginx-core.'))
            # Unknown release or dpkg unavailable: report the version, no verdict.
            return CheckResult(
                detected=True, confidence='reachable', severity='medium',
                evidence=f'nginx-core {deb_ver}',
                detail=(f'{self.cve_id}: nginx {deb_ver} installed but no known '
                        f'fixed version for release "{codename}" -- check '
                        f'ubuntu.com/security/CVE-2026-42945.'))

        # RHEL / VMBitrix: bx-nginx must be >= 1.30.2.
        rpm_ver = host.rpm_version('bx-nginx') or host.rpm_version('nginx')
        if rpm_ver:
            m = _VERSION_RE.search('nginx/' + rpm_ver) or re.match(r'(\d+)\.(\d+)\.(\d+)', rpm_ver)
            if m:
                version = tuple(int(x) for x in m.groups())
                vulnerable = version < _BXNGINX_FIXED
                return CheckResult(
                    detected=vulnerable,
                    confidence='confirmed' if vulnerable else 'not_affected',
                    severity='critical' if vulnerable else 'info',
                    evidence=f'rpm {rpm_ver}',
                    detail=(f'{self.cve_id}: {"VULNERABLE" if vulnerable else "patched"} '
                            f'-- installed {rpm_ver} vs bx-nginx fixed 1.30.2.'))
            return CheckResult(
                detected=True, confidence='reachable', severity='medium',
                evidence=f'rpm {rpm_ver}',
                detail=f'{self.cve_id}: bx-nginx {rpm_ver} installed; verify >= 1.30.2.')

        # nginx not found via either package manager.
        if family == 'unknown':
            return None
        return None


PLUGIN = CVE_2026_42945()
