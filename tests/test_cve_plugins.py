#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for the per-CVE plugin registry, remote/local checks, and the local
scanner. Runs inside the container (all runtime deps installed); on a bare host
without deps the package imports will fail -- use `make test`.
"""

import os
import tempfile
import unittest

from modules.cves import load_plugins, CheckResult
from modules.local_scan import BitrixLocalScanner
from utils.localhost import LocalHost

EXPECTED = [
    'BITRIX-html_editor_action',
    'CVE-2022-27228', 'CVE-2023-1713', 'CVE-2023-1714', 'CVE-2023-1719',
    'CVE-2025-67886', 'CVE-2025-67887', 'CVE-2026-42945',
]


class _Resp:
    def __init__(self, text='', server=None, status_code=200):
        self.text = text
        self.status_code = status_code
        self.headers = {'Server': server} if server is not None else {}


class _Req:
    """Requester stub returning a fixed body/Server/status for every call."""
    def __init__(self, text='', server=None, status_code=200):
        self._t, self._s, self._sc = text, server, status_code
    def get(self, url, **k):
        return _Resp(self._t, self._s, self._sc)
    def post(self, url, **k):
        return _Resp(self._t, self._s, self._sc)


class _NullLog:
    def __getattr__(self, _):
        return lambda *a, **k: None


class TestRegistry(unittest.TestCase):
    def test_expected_plugins_load(self):
        ids = sorted(p.cve_id for p in load_plugins())
        self.assertEqual(ids, EXPECTED)

    def test_no_smarty_xss_present(self):
        self.assertNotIn('CVE-2023-28447', [p.cve_id for p in load_plugins()])


class TestRemoteChecks(unittest.TestCase):
    def setUp(self):
        self.plugins = {p.cve_id: p for p in load_plugins()}

    def test_reachability_positive_and_negative(self):
        p = self.plugins['CVE-2023-1713']
        self.assertIsNone(p.check(_Req('nothing'), 'https://t/'))
        self.assertEqual(p.check(_Req('{"items":[]}'), 'https://t/').confidence, 'reachable')

    def test_nginx_hidden_version_is_info_advisory(self):
        r = self.plugins['CVE-2026-42945'].check(_Req(server='nginx'), 'https://t/')
        self.assertEqual(r.severity, 'info')
        self.assertIn('not exposed', r.detail)

    def test_nginx_inrange_version_is_medium_with_caveat(self):
        r = self.plugins['CVE-2026-42945'].check(_Req(server='nginx/1.18.0'), 'https://t/')
        self.assertEqual(r.severity, 'medium')
        self.assertIn('backports', r.detail)

    def test_nginx_patched_and_nonnginx_are_none(self):
        n = self.plugins['CVE-2026-42945']
        self.assertIsNone(n.check(_Req(server='nginx/1.30.1'), 'https://t/'))
        self.assertIsNone(n.check(_Req(server='Apache/2.4'), 'https://t/'))


class _FakeHost:
    """Host stub for nginx local_check (no real dpkg/rpm)."""
    def __init__(self, fam='debian', deb=None, codename=None, rpm=None, ge=None):
        self._fam, self._deb, self._codename, self._rpm, self._ge = fam, deb, codename, rpm, ge
        self.web_root = None
    def distro_family(self): return self._fam
    def dpkg_version(self, pkg): return self._deb if pkg in ('nginx-core', 'nginx') else None
    def os_codename(self): return self._codename
    def compare_deb(self, v1, op, v2): return self._ge
    def rpm_version(self, pkg): return self._rpm if pkg in ('bx-nginx', 'nginx') else None


class TestNginxLocalCheck(unittest.TestCase):
    def setUp(self):
        self.n = {p.cve_id: p for p in load_plugins()}['CVE-2026-42945']

    def test_patched_debian(self):
        r = self.n.local_check(_FakeHost(deb='1.18.0-6ubuntu14.20', codename='jammy', ge=True))
        self.assertEqual(r.confidence, 'not_affected')

    def test_vulnerable_debian(self):
        r = self.n.local_check(_FakeHost(deb='1.18.0-6ubuntu14.5', codename='jammy', ge=False))
        self.assertEqual(r.confidence, 'confirmed')
        self.assertTrue(r.detected)

    def test_bxnginx_old_and_fixed(self):
        self.assertEqual(self.n.local_check(_FakeHost('rhel', rpm='1.30.0-1.el8')).confidence, 'confirmed')
        self.assertEqual(self.n.local_check(_FakeHost('rhel', rpm='1.30.2-1.el8')).confidence, 'not_affected')

    def test_no_package_is_none(self):
        self.assertIsNone(self.n.local_check(_FakeHost('debian')))


def _make_bitrix_root(main_ver, vote_ver=None, settings_mode=0o600):
    d = tempfile.mkdtemp()
    def w(rel, content, mode=0o644):
        full = os.path.join(d, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, 'w') as f:
            f.write(content)
        os.chmod(full, mode)
    w('bitrix/modules/main/install/version.php', f'<?\n$arModuleVersion=array("VERSION"=>"{main_ver}");\n')
    w('bitrix/modules/main/classes/general/version.php', f'<?\ndefine("SM_VERSION","{main_ver}");\n')
    if vote_ver:
        w('bitrix/modules/vote/install/version.php', f'<?\n$arModuleVersion=array("VERSION"=>"{vote_ver}");\n')
    w('bitrix/.settings.php', '<? return array();', mode=settings_mode)
    return d


class TestLocalScanner(unittest.TestCase):
    def test_version_parsing_and_vote_confirmed(self):
        root = _make_bitrix_root('25.100.500', vote_ver='20.5.400', settings_mode=0o644)
        res = BitrixLocalScanner(_NullLog(), web_root=root).scan()
        self.assertEqual(res.bitrix_version, '25.100.500')
        self.assertEqual(res.module_versions.get('vote'), '20.5.400')
        cve = {f.cve_id: f for f in res.findings if f.category == 'cve'}
        self.assertEqual(cve['CVE-2022-27228'].severity, 'critical')
        self.assertIn('VULNERABLE', cve['CVE-2022-27228'].detail)
        # Translate discrimination: 25.100.500 affected by 67887, not by 67886.
        self.assertEqual(cve['CVE-2025-67887'].severity, 'medium')
        self.assertIn('not_affected', cve['CVE-2025-67886'].title)
        # world-readable .settings.php flagged
        self.assertTrue(any(f.category == 'permission' for f in res.findings))

    def test_patched_host_all_not_affected(self):
        root = _make_bitrix_root('25.100.600', vote_ver='21.0.100', settings_mode=0o600)
        res = BitrixLocalScanner(_NullLog(), web_root=root).scan()
        cve = {f.cve_id: f for f in res.findings if f.category == 'cve'}
        self.assertIn('not_affected', cve['CVE-2022-27228'].title)
        self.assertIn('not_affected', cve['CVE-2025-67887'].title)
        self.assertEqual(res.to_dict()['summary']['confirmed_vulnerable'], 0)

    def test_no_web_root_is_graceful(self):
        res = BitrixLocalScanner(_NullLog(), web_root='/nonexistent-xyz').scan()
        self.assertIsNone(res.web_root)
        self.assertIsNone(res.bitrix_version)


class TestBitrixSourceParsing(unittest.TestCase):
    def test_version_tuple_ordering(self):
        h = LocalHost()
        self.assertLess(h.version_tuple('20.5.400'), h.version_tuple('21.0.100'))
        self.assertLessEqual(h.version_tuple('25.100.500'), h.version_tuple('25.100.500'))


class TestNewVectors(unittest.TestCase):
    def setUp(self):
        self.plugins = {p.cve_id: p for p in load_plugins()}

    def test_translate_cves_no_remote_false_positive(self):
        # Login page contains "translate" -> must NOT produce a remote finding.
        for cid in ('CVE-2025-67886', 'CVE-2025-67887'):
            self.assertIsNone(
                self.plugins[cid].check(_Req(text='...translate module...', status_code=200), 'https://t/'),
                f'{cid} produced a remote false positive')

    def test_cve_2023_1719_reachable_when_endpoints_exist(self):
        r = self.plugins['CVE-2023-1719'].check(_Req(status_code=200), 'https://t/')
        self.assertIsNotNone(r)
        self.assertEqual(r.confidence, 'reachable')

    def test_cve_2023_1719_none_on_404(self):
        self.assertIsNone(self.plugins['CVE-2023-1719'].check(_Req(status_code=404), 'https://t/'))

    def test_html_editor_action_flags_real_handler_response(self):
        # Only when the upload handler actually responds unauthenticated.
        r = self.plugins['BITRIX-html_editor_action'].check(
            _Req(text='{"bxu": "upload"}', status_code=200), 'https://t/')
        self.assertIsNotNone(r)
        self.assertEqual(r.confidence, 'reachable')

    def test_html_editor_action_none_on_empty_body(self):
        # Real patched-box result: 200 + 0 bytes (PHP executed) -> not vulnerable.
        self.assertIsNone(self.plugins['BITRIX-html_editor_action'].check(_Req(text='', status_code=200), 'https://t/'))

    def test_html_editor_action_none_on_login_page(self):
        body = '<link href="/bitrix/panel/main/login.min.css"><input name="USER_LOGIN">'
        self.assertIsNone(self.plugins['BITRIX-html_editor_action'].check(_Req(text=body, status_code=200), 'https://t/'))


class TestWebRootDetection(unittest.TestCase):
    def test_detects_root_without_install_version_php(self):
        # Real installs may lack main/install/version.php; the SM_VERSION file
        # and the main/ directory are enough.
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, 'bitrix', 'modules', 'main', 'classes', 'general'))
        with open(os.path.join(d, 'bitrix', 'modules', 'main', 'classes', 'general', 'version.php'), 'w') as f:
            f.write('<?\ndefine("SM_VERSION","24.500.0");\n')
        h = LocalHost()
        self.assertEqual(h.find_web_root(d), os.path.abspath(d))
        self.assertEqual(h.bitrix_version(h.find_web_root(d)), '24.500.0')

    def test_detects_docroot_nested_under_web(self):
        parent = tempfile.mkdtemp()
        os.makedirs(os.path.join(parent, 'web', 'bitrix', 'modules', 'main'))
        h = LocalHost()
        self.assertEqual(h.find_web_root(parent), os.path.join(os.path.abspath(parent), 'web'))

    def test_trailing_slash_is_handled(self):
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, 'bitrix', 'modules', 'main'))
        h = LocalHost()
        self.assertEqual(h.find_web_root(d + '/'), os.path.abspath(d))


if __name__ == '__main__':
    unittest.main()
