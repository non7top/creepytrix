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
PAGE_URL = 'https://www.1c-bitrix.ru/vul_dev/'
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RSS_SNAPSHOT = os.path.join(ROOT, 'data', 'vul_dev_rss.xml')
JSON_OUT = os.path.join(ROOT, 'data', 'bitrix_vuln_modules.json')
# Curated entries the grid can't yield (unpublished / withdrawn modules -- see
# the file's own note). Always merged into the generated registry.
MANUAL_IN = os.path.join(ROOT, 'data', 'bitrix_vuln_modules_manual.json')

# Bitrix's own editions appear in the grid but are not third-party modules.
_SKIP_CODES = {'1c', 'enterprise', 'eshop', 'business', 'start', 'standard'}


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={'User-Agent': 'creepytrix-vuln-registry/1.0'})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()


def parse_html(html_bytes):
    """Parse the full vul_dev registry page (a Bitrix main-grid table).

    The RSS carries only recent items; the HTML page has the complete list.
    """
    text = html_bytes.decode('utf-8', 'replace') if isinstance(html_bytes, bytes) else html_bytes
    rows_out = []
    for row in re.split(r'<tr class="main-grid-row main-grid-row-body"', text)[1:]:
        mm = re.search(
            r'data-column-id="vul_module".*?solutions/([a-z0-9._]+)/"[^>]*>(.*?)</a>',
            row, re.S)
        vm = re.search(r'data-column-id="vul_issue_version".*?до\s*([\d]+(?:\.[\d]+)+)', row, re.S)
        if not mm or not vm:
            continue
        code = mm.group(1).lower()
        if code in _SKIP_CODES:
            continue
        name = re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', '', mm.group(2))).strip()
        fixed = vm.group(1)
        dm = re.search(r'data-column-id="vul_date_publication2".*?>\s*([\d]{2}\.[\d]{2}\.[\d]{4})', row, re.S)
        lm = re.search(r'data-column-id="vul_mp_link".*?href="([^"]+)"', row, re.S)
        rows_out.append({
            'code': code,
            'name': name,
            'fixed': fixed,
            'version_raw': 'до ' + fixed,
            'published': dm.group(1) if dm else '',
            'src_link': 'https://marketplace.1c-bitrix.ru/solutions/%s/' % code,
            'fix_link': lm.group(1) if lm else '',
        })
    return rows_out


def _vtuple(v):
    out = []
    for p in str(v or '0').split('.'):
        try:
            out.append(int(p))
        except ValueError:
            out.append(0)
    return tuple(out)


def load_manual():
    """Curated entries (unpublished / withdrawn modules) merged into the
    registry. See data/bitrix_vuln_modules_manual.json for why they can't be
    scraped."""
    try:
        with open(MANUAL_IN, encoding='utf-8') as f:
            return json.load(f).get('modules', [])
    except Exception as e:
        print(f"Warning: manual supplement unavailable: {e}", file=sys.stderr)
        return []


def reduce_latest(rows):
    """Keep one row per module code. A withdrawn entry (no fixed version --
    vulnerable at any installed version) always supersedes a versioned one;
    otherwise keep the highest fixed version."""
    by = {}
    for m in rows:
        c = m.get('code')
        if not c:
            continue
        cur = by.get(c)
        if cur is None:
            by[c] = m
        elif m.get('withdrawn'):
            by[c] = m                     # withdrawn supersedes any version
        elif cur.get('withdrawn'):
            continue                      # keep the withdrawn entry
        elif _vtuple(m.get('fixed')) > _vtuple(cur.get('fixed')):
            by[c] = m
    return sorted(by.values(), key=lambda x: x['code'])


def collect_pages():
    """Walk the grid's AJAX pagination until a page adds no new modules."""
    page_tmpl = (PAGE_URL + '?internal=true&grid_id=vul_dev_grid'
                 '&grid_action=pagination&vul_dev_grid=page-%d')
    rows, seen = [], set()
    for n in range(1, 20):  # safety cap; grid wraps after the last page
        try:
            page_rows = parse_html(fetch(page_tmpl % n))
        except Exception:
            break
        fresh = [m for m in page_rows if m['code'] not in seen]
        if not fresh:
            break
        rows.extend(page_rows)
        seen.update(m['code'] for m in page_rows)
    return rows


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


def write_registry(mods):
    payload = {
        'source': RSS_URL,
        'note': ('Auto-generated from the 1C-Bitrix vul_dev registry by '
                 'scripts/update_vuln_registry.py, plus curated withdrawn/unpublished '
                 'modules from bitrix_vuln_modules_manual.json. A module is vulnerable '
                 'when its installed version is < "fixed", or unconditionally when '
                 '"withdrawn": true (removed from the marketplace -- no fix; remove it).'),
        'modules': mods,
    }
    os.makedirs(os.path.dirname(JSON_OUT), exist_ok=True)
    with open(JSON_OUT, 'w', encoding='utf-8') as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.write('\n')


def load_existing():
    try:
        with open(JSON_OUT, encoding='utf-8') as f:
            return json.load(f).get('modules', [])
    except Exception:
        return []


def main(argv):
    manual_mods = load_manual()

    # Local, no-network mode: fold the curated manual entries into the EXISTING
    # generated registry without re-fetching (keeps scraped entries intact).
    if '--merge-manual' in argv:
        mods = reduce_latest(load_existing() + manual_mods)
        write_registry(mods)
        print(f"{len(mods)} modules after manual merge -> {JSON_OUT}")
        return 0

    if len(argv) > 1 and os.path.isfile(argv[1]):
        xml_bytes = open(argv[1], 'rb').read()
        page_rows = []
    else:
        xml_bytes = fetch(RSS_URL)
        try:
            page_rows = collect_pages()
        except Exception as e:
            print(f"Warning: could not fetch paginated HTML pages: {e}", file=sys.stderr)
            page_rows = []

    rss_mods = parse(xml_bytes)
    mods = reduce_latest(rss_mods + page_rows + manual_mods)
    # Normalize the snapshot (LF endings, no trailing whitespace) so the
    # committed baseline and CI-written file compare cleanly -- avoids spurious
    # weekly diffs from server-side CRLF/trailing spaces.
    text = xml_bytes.decode('utf-8', 'replace')
    normalized = '\n'.join(line.rstrip() for line in text.splitlines()) + '\n'
    os.makedirs(os.path.dirname(RSS_SNAPSHOT), exist_ok=True)
    with open(RSS_SNAPSHOT, 'w', encoding='utf-8', newline='\n') as f:
        f.write(normalized)
    write_registry(mods)
    print(f"{len(mods)} modules written to {JSON_OUT}")
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
