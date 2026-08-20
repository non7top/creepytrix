#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2023-1713 -- Bitrix24 insecure temporary file handling RCE."""

from .base import CVECheck


class CVE_2023_1713(CVECheck):
    cve_id = 'CVE-2023-1713'
    title = 'Insecure temporary file creation RCE (Instagram import)'
    affected = 'Bitrix24 22.0.300'
    severity = 'critical'
    auth = 'authenticated'
    references = [
        'https://nvd.nist.gov/vuln/detail/CVE-2023-1713',
        'https://starlabs.sg/advisories/23/23-1713/',
    ]

    endpoint = '/bitrix/services/main/ajax.php'
    method = 'POST'
    payload = {
        'mode': 'class',
        'c': 'bitrix:crm.order.import.instagram.view',
        'action': 'importAjax',
    }
    marker = 'items'
    notes = (
        'Authenticated (any user). Downloads attacker-controlled URLs to a '
        'predictable /upload/tmp/xxx/ path; a .htaccess payload plus temp-dir '
        'bruteforce yields RCE. Probe checks the ajax action is reachable.'
    )


PLUGIN = CVE_2023_1713()
