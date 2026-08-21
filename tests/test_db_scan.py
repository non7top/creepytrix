#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the DB dump signature scanner (pure functions, no database)."""

import unittest
from utils.db_scan import scan_dump, known_eval_table


class TestDbScan(unittest.TestCase):
    def _hits(self, lines):
        return list(scan_dump(lines))

    def test_attributes_hits_to_current_table(self):
        lines = [
            '-- Table structure for table `b_option`\n',
            "INSERT INTO `b_option` VALUES (1,'main','x','eval(base64_decode($_REQUEST[\"id\"]))','');\n",
        ]
        hits = self._hits(lines)
        self.assertEqual(len(hits), 1)  # only the INSERT matches; struct line sets table
        table, sev, snip = hits[-1]
        self.assertEqual(table, 'b_option')
        self.assertEqual(sev, 'critical')

    def test_strong_vs_weak(self):
        strong = list(scan_dump(["INSERT INTO `b_agent` VALUES ('eval(gzinflate(base64_decode(...)))');\n"]))
        self.assertEqual(strong[0][1], 'critical')
        weak = list(scan_dump(["INSERT INTO `b_stat_event` VALUES ('...base64_decode(...)...');\n"]))
        self.assertEqual(weak[0][1], 'high')

    def test_real_iocs_from_incident(self):
        for ioc in ('accesson', '0dcbfc9f86f6', '17028f487cb2a84607646da3ad3878ec', '409723*20'):
            hits = list(scan_dump([f"INSERT INTO `b_option` VALUES ('{ioc}');\n"]))
            self.assertTrue(hits and hits[0][1] == 'critical', ioc)

    def test_clean_dump_no_hits(self):
        lines = [
            '-- Table structure for table `b_user`\n',
            "INSERT INTO `b_user` VALUES (1,'admin','Normal content here');\n",
        ]
        self.assertEqual(self._hits(lines), [])

    def test_known_eval_tables(self):
        self.assertTrue(known_eval_table('b_option'))
        self.assertTrue(known_eval_table('b_agent'))
        self.assertTrue(known_eval_table('b_intec_core_settings'))
        self.assertFalse(known_eval_table('b_user'))


if __name__ == '__main__':
    unittest.main()
