#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the content-based exposure heuristics (real false positives from a live scan)."""

import unittest
from utils.http_heuristics import looks_exposed, is_denied_or_login


class _R:
    def __init__(self, text, status=200):
        self.text = text
        self.status_code = status


class TestHeuristics(unittest.TestCase):
    def test_settings_php_empty_is_not_exposed(self):
        # PHP executed -> 200 with 0 bytes (the real .settings.php result).
        self.assertFalse(looks_exposed(_R('', 200), want_source=True))
        self.assertFalse(looks_exposed(_R('   \n', 200), want_source=True))

    def test_backup_meta_refresh_is_not_exposed(self):
        body = '<head><meta http-equiv="REFRESH" content="0;URL=/bitrix/admin/index.php"></head>'
        self.assertTrue(is_denied_or_login(body))
        self.assertFalse(looks_exposed(_R(body, 200)))

    def test_admin_login_page_is_not_exposed(self):
        body = ('<!DOCTYPE html><link href="/bitrix/panel/main/login.min.css" rel="stylesheet">'
                '<form><input name="USER_LOGIN"></form>')
        self.assertFalse(looks_exposed(_R(body, 200)))

    def test_real_served_config_is_exposed(self):
        body = '<?php\nreturn array("connections" => array("default" => array("host" => "x", "DBPassword" => "s")));'
        self.assertTrue(looks_exposed(_R(body, 200), want_source=True))

    def test_rendered_html_is_not_source(self):
        self.assertFalse(looks_exposed(_R('<html><body>Welcome</body></html>', 200), want_source=True))

    def test_non_200_and_none(self):
        self.assertFalse(looks_exposed(_R('data', 404)))
        self.assertFalse(looks_exposed(None))

    def test_genuine_listing_is_exposed(self):
        self.assertTrue(looks_exposed(_R('<html><title>Index of /backup</title>Parent Directory', 200)))


if __name__ == '__main__':
    unittest.main()
