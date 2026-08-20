#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2025-67887 -- 1C-Bitrix Translate module RCE (vendor-disputed)."""

from .base import CVECheck


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
        'CVSS is reported as 9.8 (NVD/OpenCVE) vs ~6.3 elsewhere. Endpoint path '
        'is UNVERIFIED.'
    )


PLUGIN = CVE_2025_67887()
