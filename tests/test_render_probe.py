#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for scripts/render_probe.py."""

import base64
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))
import render_probe as rp  # noqa: E402


class TestRenderProbe(unittest.TestCase):
    def test_embeds_registry_and_leaves_token_slot_alone(self):
        template = (
            "<?php\n"
            "$REGISTRY_B64 = '__CREEPYTRIX_REGISTRY_B64__';\n"
            "$EXPECTED_TOKEN = '__CREEPYTRIX_TOKEN__';\n"
        )
        registry = {'version': 7, 'modules': [{'code': 'acrit.bonus', 'fixed': '3.1'}]}
        registry_json = json.dumps(registry)

        rendered = rp.render(template, registry_json)

        # Token slot is untouched -- it's a per-dispatch secret, never baked in here.
        self.assertIn("'__CREEPYTRIX_TOKEN__'", rendered)
        self.assertNotIn('__CREEPYTRIX_REGISTRY_B64__', rendered)

        # The embedded slot decodes back to the exact registry payload.
        m = rendered.split("$REGISTRY_B64 = '", 1)[1].split("'", 1)[0]
        decoded = json.loads(base64.b64decode(m).decode('utf-8'))
        self.assertEqual(decoded, registry)

    def test_missing_slot_raises(self):
        with self.assertRaises(ValueError):
            rp.render('<?php\n// no slot here\n', '{}')


if __name__ == '__main__':
    unittest.main()
