#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bitrix html_editor_action object-injection RCE (no CVE assigned).

A widely-exploited-in-the-wild vector: the visual-editor upload handler at
/bitrix/tools/html_editor_action.php processes bxu_files[<name>] where the
<name> carries null bytes + path traversal (../iblock), triggering PHP object
injection / unauthorized file write during deserialization. Unauthenticated on
older builds; later versions added an authorization check. Commonly used to
drop webshells on Bitrix sites.
"""

from urllib.parse import urljoin

from .base import CVECheck, CheckResult
from utils.http_heuristics import is_denied_or_login


class VULN_HtmlEditorAction(CVECheck):
    cve_id = 'BITRIX-html_editor_action'   # no CVE; sorts by this label
    title = 'html_editor_action object-injection RCE (webshell upload)'
    affected = 'Bitrix Site Manager (older builds; unauth before auth-check fix)'
    severity = 'critical'
    auth = 'unauth'
    references = [
        'https://github.com/M4tir/CVE-2022-27228',
        'https://onelab.kz/en/articles/bezopasnost/bitrix-is-in-trouble-malware-code-has-been-uploaded-to-the-website/',
    ]
    endpoint = '/bitrix/tools/html_editor_action.php'
    method = 'POST'
    payload = {'action': 'uploadfile'}
    notes = (
        'Full exploit: GET bitrix_sessid from /bitrix/tools/composite_data.php, '
        'then POST action=uploadfile with bxu_files[<name>] where <name> uses '
        'null byte + ../iblock traversal to force object injection / arbitrary '
        'write. This plugin only probes reachability -- it uploads nothing.'
    )

    def check(self, requester, base_url):
        url = urljoin(base_url, self.endpoint)
        resp = requester.post(url, data=self.payload)
        if not resp:
            return None
        body = getattr(resp, 'text', '') or ''
        # The core file exists on EVERY Bitrix install, so "not 404" is
        # meaningless. Patched builds require auth: an unauthenticated POST
        # returns an empty body (PHP executed) or a login/denial page -- neither
        # is the vulnerable condition. Only flag when the upload handler actually
        # responds unauthenticated (bxu / JSON upload response).
        if not body.strip() or is_denied_or_login(body):
            return None
        handler_response = 'bxu' in body.lower() or body.lstrip().startswith('{')
        if not handler_response:
            return None
        return CheckResult(
            detected=True,
            confidence='reachable',
            evidence=f'HTTP {getattr(resp, "status_code", "?")}: {body[:120]}',
            detail=(f'{self.cve_id}: html_editor_action upload handler responds to an '
                    'UNAUTHENTICATED upload (object-injection surface). Investigate.'),
        )


PLUGIN = VULN_HtmlEditorAction()
