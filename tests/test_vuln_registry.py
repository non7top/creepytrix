#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the vul_dev RSS parser and the data-driven module check."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))
import update_vuln_registry as upd  # noqa: E402

from modules.local_scan import BitrixLocalScanner  # noqa: E402

_RSS = b'''<?xml version="1.0" encoding="utf-8"?><rss version="2.0"><channel>
<item><title>Universal Import</title><code>acrit.import</code>
<version>\xd0\xb4\xd0\xbe 1.79.0</version><pubDate>29.06.2026</pubDate>
<src_link>s</src_link><fix_link>f</fix_link></item>
<item><title>No version here</title><code>foo.bar</code><version>latest</version></item>
</channel></rss>'''


class _NullLog:
    def __getattr__(self, _):
        return lambda *a, **k: None


class TestParser(unittest.TestCase):
    def test_parses_version_and_skips_unparseable(self):
        mods = upd.parse(_RSS)
        self.assertEqual(len(mods), 1)  # foo.bar has no dotted version -> skipped
        self.assertEqual(mods[0]['code'], 'acrit.import')
        self.assertEqual(mods[0]['fixed'], '1.79.0')
        self.assertEqual(mods[0]['version_raw'], 'до 1.79.0')


class TestModuleCheck(unittest.TestCase):
    def _root_with_module(self, code, version):
        d = tempfile.mkdtemp()
        moddir = os.path.join(d, 'bitrix', 'modules', code, 'install')
        os.makedirs(moddir)
        with open(os.path.join(moddir, 'version.php'), 'w') as f:
            f.write(f'<?\n$arModuleVersion=array("VERSION"=>"{version}");\n')
        # minimal bitrix marker so find_web_root succeeds
        os.makedirs(os.path.join(d, 'bitrix', 'modules', 'main'))
        return d

    def test_flags_outdated_module(self):
        # acrit.import fixed 1.79.0 -> installed 1.78.0 is vulnerable
        root = self._root_with_module('acrit.import', '1.78.0')
        res = BitrixLocalScanner(_NullLog(), web_root=root).scan()
        mods = [f for f in res.findings if f.category == 'module']
        self.assertTrue(any('acrit.import' in f.title for f in mods))

    def test_patched_module_not_flagged(self):
        root = self._root_with_module('acrit.import', '1.79.0')
        res = BitrixLocalScanner(_NullLog(), web_root=root).scan()
        self.assertFalse([f for f in res.findings if f.category == 'module'])

    def test_flags_withdrawn_module_at_any_version(self):
        # aspro.priority is 'снято с публикации' (withdrawn) -> flagged critical
        # regardless of installed version; remediation is removal, not update.
        root = self._root_with_module('aspro.priority', '99.99.99')
        res = BitrixLocalScanner(_NullLog(), web_root=root).scan()
        mods = [f for f in res.findings if f.category == 'module']
        self.assertTrue(any('aspro.priority' in f.title and f.severity == 'critical'
                            for f in mods))


_GRID = '''
<tr class="main-grid-row main-grid-row-body" data-id="1">
<td data-column-id="vul_module"><div class="main-grid-cell-inner"><a href="https://marketplace.1c-bitrix.ru/solutions/acme.mod/">Acme: Mod</a></div></td>
<td data-column-id="vul_issue_version"><div class="main-grid-cell-inner">до 1.2.3</div></td>
<td data-column-id="vul_date_publication2"><div class="main-grid-cell-inner">01.02.2025</div></td>
</tr>
<tr class="main-grid-row main-grid-row-body" data-id="2">
<td data-column-id="vul_module"><div class="main-grid-cell-inner"><span>Аспро: Приорити</span></div></td>
<td data-column-id="vul_issue_version"><div class="main-grid-cell-inner">снято с публикации</div></td>
</tr>
'''


class TestParseHtml(unittest.TestCase):
    def test_splits_matched_and_unmatched(self):
        matched, unmatched = upd.parse_html(_GRID)
        self.assertEqual([m['code'] for m in matched], ['acme.mod'])
        self.assertEqual(matched[0]['fixed'], '1.2.3')
        self.assertEqual(len(unmatched), 1)
        self.assertEqual(unmatched[0]['name'], 'Аспро: Приорити')
        self.assertIsNone(unmatched[0]['code'])          # no marketplace link
        self.assertIn('снято', unmatched[0]['status'])


class TestReportUnmatched(unittest.TestCase):
    def test_covered_row_is_not_a_gap(self):
        _matched, unmatched = upd.parse_html(_GRID)
        manual = [{'code': 'aspro.priority', 'name': 'Аспро: Приорити'}]
        self.assertEqual(upd.report_unmatched(unmatched, manual), [])

    def test_uncovered_row_is_a_gap(self):
        _matched, unmatched = upd.parse_html(_GRID)
        gaps = upd.report_unmatched(unmatched, manual_mods=[])
        self.assertEqual([g['name'] for g in gaps], ['Аспро: Приорити'])


class TestReduceLatest(unittest.TestCase):
    def test_withdrawn_supersedes_versioned(self):
        rows = [
            {'code': 'x.y', 'fixed': '1.0.0'},
            {'code': 'x.y', 'fixed': None, 'withdrawn': True},
        ]
        out = upd.reduce_latest(rows)
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0].get('withdrawn'))

    def test_keeps_highest_fixed(self):
        rows = [
            {'code': 'a.b', 'fixed': '1.2.0'},
            {'code': 'a.b', 'fixed': '1.10.0'},
        ]
        out = upd.reduce_latest(rows)
        self.assertEqual(out[0]['fixed'], '1.10.0')


if __name__ == '__main__':
    unittest.main()
