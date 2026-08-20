#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2023-1714 -- Bitrix24 unsafe variable extraction RCE."""

from .base import CVECheck


class CVE_2023_1714(CVECheck):
    cve_id = 'CVE-2023-1714'
    title = 'Unsafe variable extraction RCE (file append / PHAR deserialization)'
    affected = 'Bitrix24 22.0.300'
    severity = 'critical'
    auth = 'authenticated'
    references = [
        'https://nvd.nist.gov/vuln/detail/CVE-2023-1714',
        'https://starlabs.sg/advisories/23/23-1714/',
    ]

    endpoint = '/bitrix/services/main/ajax.php'
    method = 'POST'
    payload = {'action': 'bitrix:crm.api.export.export'}
    marker = 'PROCESS_TOKEN'
    notes = (
        'Authenticated. Two vectors: file-append via crm.api.export.export '
        '(filePath in user options) and PHAR deserialization via '
        'crm.contact.list/stexport.ajax.php (FILE_PATH in BITRIX_SM_LAST_SETTINGS '
        'cookie). Probe checks the export action is reachable.'
    )


PLUGIN = CVE_2023_1714()
