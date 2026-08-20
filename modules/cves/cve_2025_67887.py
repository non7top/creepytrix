#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2025-67887 -- 1C-Bitrix Translate module RCE (vendor-disputed)."""

from .base import CVECheck, CheckResult


class CVE_2025_67887(CVECheck):
    cve_id = 'CVE-2025-67887'
    title = 'Translate module improper archive validation RCE'
    affected = '1C-Bitrix through 25.100.500'
    severity = 'critical'      # NVD/OpenCVE: 9.8 (SentinelOne rates it lower)
    auth = 'authenticated'     # requires SOURCE/WRITE on the Translate module
    disputed = True
    references = [
        'https://nvd.nist.gov/vuln/detail/CVE-2025-67887',
        'https://karmainsecurity.com/KIS-2025-08',
        'https://github.com/advisories/GHSA-2636-hvcv-37w8',
    ]

    # NOTE: admin path below is a best-guess module entry point and is
    # UNVERIFIED against a live install. Confirm before relying on detection.
    endpoint = '/bitrix/admin/translate_edit.php'
    method = 'GET'
    payload = None
    marker = 'translate'
    notes = (
        'Vendor-disputed. Improper archive validation in the Translate module: '
        'an uploaded archive with a PHP file + .htaccess executes on extraction. '
        'CVSS 9.8 (NVD/GHSA, vector PR:N -- scored as unauthenticated) conflicts '
        'with the advisory text (requires Translate SOURCE/WRITE), hence the '
        '9.8-vs-~6.3 split. No fixed version published. Endpoint path UNVERIFIED.'
    )

    # Affected through platform version 25.100.500 (disputed; needs SOURCE/WRITE).
    AFFECTED_MAX = (25, 100, 500)

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
                detail=f'{self.cve_id}: platform {ver} > 25.100.500 (above affected range).')
        return CheckResult(
            detected=True, confidence='confirmed', severity='medium',
            evidence=f'platform {ver}',
            detail=(f'{self.cve_id}: platform {ver} <= 25.100.500 (affected range). '
                    f'Vendor-disputed; exploit needs Translate SOURCE/WRITE rights.'))


PLUGIN = CVE_2025_67887()
