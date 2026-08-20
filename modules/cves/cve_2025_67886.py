#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2025-67886 -- Bitrix24 Translate module RCE (vendor-disputed)."""

from .base import CVECheck, CheckResult


class CVE_2025_67886(CVECheck):
    cve_id = 'CVE-2025-67886'
    title = 'Translate module .htaccess+.php upload RCE'
    affected = 'Bitrix24 through 25.100.300'
    severity = 'high'          # NVD/OpenCVE: 6.3
    auth = 'authenticated'     # requires SOURCE/WRITE on the Translate module
    disputed = True
    references = [
        'https://nvd.nist.gov/vuln/detail/CVE-2025-67886',
        'https://www.sentinelone.com/vulnerability-database/cve-2025-67886/',
    ]

    # NOTE: admin path below is a best-guess module entry point and is
    # UNVERIFIED against a live install. Confirm before relying on detection.
    endpoint = '/bitrix/admin/translate.php'
    method = 'GET'
    payload = None
    marker = 'translate'
    notes = (
        'Vendor-disputed (intended behaviour for high-privileged users). An '
        'actor with SOURCE/WRITE on the Translate module uploads a PHP file plus '
        'a .htaccess to gain code execution. Endpoint path is UNVERIFIED.'
    )

    # Affected through platform version 25.100.300 (disputed; needs SOURCE/WRITE).
    AFFECTED_MAX = (25, 100, 300)

    def local_check(self, host):
        if not host.web_root:
            return None
        ver = host.bitrix_version(host.web_root)
        if not ver:
            return None
        affected = host.version_tuple(ver) <= self.AFFECTED_MAX
        if not affected:
            return CheckResult(
                detected=False, confidence='not_affected', severity='info',
                evidence=f'platform {ver}',
                detail=f'{self.cve_id}: platform {ver} > 25.100.300 (above affected range).')
        return CheckResult(
            detected=True, confidence='confirmed', severity='medium',
            evidence=f'platform {ver}',
            detail=(f'{self.cve_id}: platform {ver} <= 25.100.300 (affected range). '
                    f'Vendor-disputed; exploit needs Translate SOURCE/WRITE rights.'))


PLUGIN = CVE_2025_67886()
