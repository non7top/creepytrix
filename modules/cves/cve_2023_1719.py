#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2023-1719 -- Bitrix24 insecure global variable extraction (IDOR + XSS->RCE)."""

from urllib.parse import urljoin

from .base import CVECheck, CheckResult


class CVE_2023_1719(CVECheck):
    cve_id = 'CVE-2023-1719'
    title = 'Insecure variable extraction: IDOR + reflected XSS -> PHP RCE'
    affected = 'Bitrix24 22.0.300'
    severity = 'high'
    auth = 'authenticated'   # IDOR is unauth; XSS->RCE fires in an admin session
    references = [
        'https://nvd.nist.gov/vuln/detail/CVE-2023-1719',
        'https://starlabs.sg/advisories/23/23-1719/',
    ]
    endpoint = '/pub/im.file.php'
    notes = (
        'FormDecode() in bitrix/modules/main/tools.php extracts request vars into '
        '$GLOBALS. Two effects: unauthenticated attachment IDOR at /pub/im.file.php '
        '(diskFileId/sign), and a reflected XSS at socialnetwork.events_dyn/'
        'get_message_2.php (log_cnt, Unicode-paragraph-separator bypass) that '
        'reaches PHP RCE via the admin command line. Probe checks reachability.'
    )

    # Second surface (the XSS -> RCE vector).
    XSS_ENDPOINT = ('/bitrix/components/bitrix/socialnetwork.events_dyn/'
                    'get_message_2.php')

    @staticmethod
    def _reachable(resp):
        # Present if the handler answers with something other than a hard 404.
        return resp is not None and getattr(resp, 'status_code', 404) != 404

    def check(self, requester, base_url):
        idor = requester.get(urljoin(base_url, self.endpoint))
        xss = requester.get(urljoin(base_url, self.XSS_ENDPOINT))
        hits = []
        if self._reachable(idor):
            hits.append(f'IDOR endpoint {self.endpoint} (HTTP {idor.status_code})')
        if self._reachable(xss):
            hits.append(f'XSS endpoint {self.XSS_ENDPOINT} (HTTP {xss.status_code})')
        if not hits:
            return None
        return CheckResult(
            detected=True,
            confidence='reachable',
            evidence='; '.join(hits),
            detail=(f'{self.cve_id}: reachable surface(s): {"; ".join(hits)}. '
                    'Not confirmed exploitable (needs Bitrix24 22.0.300 + admin '
                    'for the RCE path).'),
        )


PLUGIN = CVE_2023_1719()
