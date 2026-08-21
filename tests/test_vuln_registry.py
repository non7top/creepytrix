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


if __name__ == '__main__':
    unittest.main()
