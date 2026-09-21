#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Render tools/creepytrix_probe.php into a dispatch-ready artifact by embedding
the current vuln registry.

The skeleton (tools/creepytrix_probe.php) is the committed TEMPLATE and always
keeps its __CREEPYTRIX_REGISTRY_B64__ / __CREEPYTRIX_TOKEN__ placeholders
as-is -- it must stay re-renderable every week. This script substitutes only
the registry slot from data/bitrix_vuln_modules.json and writes the result to
a separate output file; the token slot is left untouched (it's a per-dispatch
secret that wr-util fills in at actual dispatch time, never committed here).

Runnable locally and by the weekly GitHub workflow, right after
update_vuln_registry.py regenerates the registry. Stdlib only.

  python3 scripts/render_probe.py
"""

import base64
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_IN = os.path.join(ROOT, 'tools', 'creepytrix_probe.php')
REGISTRY_IN = os.path.join(ROOT, 'data', 'bitrix_vuln_modules.json')
PHP_OUT = os.path.join(ROOT, 'tools', 'creepytrix_probe.generated.php')

_REGISTRY_SLOT = "'__CREEPYTRIX_REGISTRY_B64__'"


def render(template: str, registry_json: str) -> str:
    if _REGISTRY_SLOT not in template:
        raise ValueError(
            f'{_REGISTRY_SLOT} not found in template -- skeleton was edited, '
            'update the slot marker here too')
    b64 = base64.b64encode(registry_json.encode('utf-8')).decode('ascii')
    return template.replace(_REGISTRY_SLOT, f"'{b64}'")


def main(argv):
    with open(TEMPLATE_IN, 'r', encoding='utf-8') as f:
        template = f.read()
    with open(REGISTRY_IN, 'r', encoding='utf-8') as f:
        registry = json.load(f)  # fail loudly on malformed registry JSON

    # Re-serialize compactly: the embedded copy doesn't need the committed
    # file's pretty-printing, and a smaller payload means a smaller probe.
    registry_json = json.dumps(registry, ensure_ascii=False, separators=(',', ':'))

    rendered = render(template, registry_json)
    with open(PHP_OUT, 'w', encoding='utf-8', newline='\n') as f:
        f.write(rendered)
    print(f"registry version {registry.get('version')} ({len(registry.get('modules', []))} "
          f"modules) embedded -> {PHP_OUT}")
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
