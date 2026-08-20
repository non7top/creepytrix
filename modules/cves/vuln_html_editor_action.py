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
        reachable = getattr(resp, 'status_code', 404) != 404 or 'bxu' in resp.text
        if not reachable:
            return None
        return CheckResult(
            detected=True,
            confidence='reachable',
            evidence=f'HTTP {getattr(resp, "status_code", "?")}',
            detail=(f'{self.cve_id}: html_editor_action upload handler reachable '
                    '(object-injection surface). Confirm auth requirement + build.'),
        )


PLUGIN = VULN_HtmlEditorAction()
