#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fetch the 1C-Bitrix third-party-vulnerability RSS, store a raw snapshot, and
regenerate the vulnerable-module registry JSON that local mode checks against.

Runnable locally and by the weekly GitHub workflow. Stdlib only (works in CI
with no dependencies). Pass a local .xml path as argv[1] to parse offline.

  python3 scripts/update_vuln_registry.py [path/to/rss.xml]
"""

import json
import os
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET

RSS_URL = 'https://www.1c-bitrix.ru/vul_dev/rss/'
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RSS_SNAPSHOT = os.path.join(ROOT, 'data', 'vul_dev_rss.xml')
JSON_OUT = os.path.join(ROOT, 'data', 'bitrix_vuln_modules.json')


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={'User-Agent': 'creepytrix-vuln-registry/1.0'})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()


def parse(xml_bytes: bytes):
    root = ET.fromstring(xml_bytes)
    mods = []
    for item in root.iter('item'):
        code = (item.findtext('code') or '').strip()
        version_raw = (item.findtext('version') or '').strip()
        m = re.search(r'(\d+(?:\.\d+)+)', version_raw)  # first dotted version
        fixed = m.group(1) if m else None
        if not code or not fixed:
            continue
        mods.append({
            'code': code,
            'name': (item.findtext('title') or '').strip(),
            'fixed': fixed,
            'version_raw': version_raw,
            'published': (item.findtext('pubDate') or '').strip(),
            'src_link': (item.findtext('src_link') or '').strip(),
            'fix_link': (item.findtext('fix_link') or '').strip(),
        })
    mods.sort(key=lambda x: x['code'])
    return mods


def main(argv):
    if len(argv) > 1 and os.path.isfile(argv[1]):
        xml_bytes = open(argv[1], 'rb').read()
    else:
        xml_bytes = fetch(RSS_URL)
    mods = parse(xml_bytes)
    os.makedirs(os.path.dirname(JSON_OUT), exist_ok=True)
    # Normalize the snapshot (LF endings, no trailing whitespace) so the
    # committed baseline and CI-written file compare cleanly -- avoids spurious
    # weekly diffs from server-side CRLF/trailing spaces.
    text = xml_bytes.decode('utf-8', 'replace')
    normalized = '\n'.join(line.rstrip() for line in text.splitlines()) + '\n'
    with open(RSS_SNAPSHOT, 'w', encoding='utf-8', newline='\n') as f:
        f.write(normalized)
    payload = {
        'source': RSS_URL,
        'note': ('Auto-generated from the 1C-Bitrix vul_dev RSS by '
                 'scripts/update_vuln_registry.py. A module is vulnerable when its '
                 'installed version is < "fixed".'),
        'modules': mods,
    }
    with open(JSON_OUT, 'w', encoding='utf-8') as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.write('\n')
    print(f"{len(mods)} modules written to {JSON_OUT}")
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
