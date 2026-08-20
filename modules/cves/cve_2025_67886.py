#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2025-67886 -- Bitrix24 Translate module RCE (vendor-disputed)."""

from .base import CVECheck


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


PLUGIN = CVE_2025_67886()
