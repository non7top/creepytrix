#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2022-27228 -- Bitrix vote ("Polls, Votes") module unauthenticated RCE."""

from urllib.parse import urljoin

from .base import CVECheck, CheckResult


class CVE_2022_27228(CVECheck):
    cve_id = 'CVE-2022-27228'
    title = 'Vote module unauthenticated RCE (CopyDataToFile / PHAR)'
    affected = 'Bitrix Site Manager -- vote module before 21.0.100'
    severity = 'critical'
    auth = 'unauth'
    references = [
        'https://nvd.nist.gov/vuln/detail/CVE-2022-27228',
        'https://github.com/M4tir/CVE-2022-27228',
    ]

    endpoint = '/bitrix/tools/vote/uf.php'
    method = 'POST'
    payload = {'action': 'uploadfile', 'sessid': 'x'}
    marker = 'bxu'
    notes = (
        'Full exploit: GET bitrix_sessid from /bitrix/tools/composite_data.php, '
        'then multipart upload (bxu_info[]/bxu_files[]) of a .htaccess + PHP/PHAR '
        'payload to uf.php. This plugin only probes reachability -- it uploads '
        'nothing.'
    )

    # Source of the bitrix_sessid a real exploit needs.
    SESSID_ENDPOINT = '/bitrix/tools/composite_data.php'

    def check(self, requester, base_url):
        # 1. Is the vulnerable upload endpoint present?
        uf_url = urljoin(base_url, self.endpoint)
        resp = requester.post(uf_url, data=self.payload)
        if not resp or self.marker not in resp.text:
            return None

        # 2. Corroborate: does the sessid source respond as expected? This
        #    raises confidence that this is a real Bitrix vote surface, but the
        #    check remains non-destructive (no upload attempted).
        sessid_url = urljoin(base_url, self.SESSID_ENDPOINT)
        sessid_resp = requester.get(sessid_url)
        corroborated = bool(sessid_resp and 'bitrix_sessid' in sessid_resp.text)

        detail = f'{self.cve_id} vote upload endpoint reachable'
        if corroborated:
            detail += ' (bitrix_sessid source also present)'
        return CheckResult(
            detected=True,
            confidence='reachable',
            evidence=resp.text[:200],
            detail=detail,
        )

    # Vote module is fixed in 21.0.100.
    FIXED_MODULE_VERSION = (21, 0, 100)

    def local_check(self, host):
        if not host.web_root:
            return None
        ver = host.bitrix_module_version(host.web_root, 'vote')
        if not ver:
            return None
        vulnerable = host.version_tuple(ver) < self.FIXED_MODULE_VERSION
        return CheckResult(
            detected=vulnerable,
            confidence='confirmed' if vulnerable else 'not_affected',
            severity='critical' if vulnerable else 'info',
            evidence=f'vote module {ver}',
            detail=(f'{self.cve_id}: {"VULNERABLE" if vulnerable else "patched"} '
                    f'-- vote module {ver} vs fixed 21.0.100.'),
        )


PLUGIN = CVE_2022_27228()
