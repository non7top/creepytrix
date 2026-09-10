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
from datetime import datetime, timezone

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


def _cell_text(row, column_id):
    """Plain text of a grid cell by data-column-id (tags stripped)."""
    m = re.search(r'data-column-id="%s".*?<div class="main-grid-cell-inner">(.*?)</div>'
                  % re.escape(column_id), row, re.S)
    if not m:
        return ''
    return re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', '', m.group(1))).strip()


def parse_html(html_bytes):
    """Parse a vul_dev registry grid page.

    Returns (matched, unmatched):
      - matched: rows with a marketplace link AND a "до X.Y.Z" version -- the
        ones we can turn into a version-comparison rule.
      - unmatched: every other row (no link, or no parseable version -- e.g.
        withdrawn "снято с публикации" modules). The grid gives these neither a
        module code nor a fixed version, so they can only be covered by the
        curated manual supplement. Reported so a human can add the missing slug.
    """
    text = html_bytes.decode('utf-8', 'replace') if isinstance(html_bytes, bytes) else html_bytes
    matched, unmatched = [], []
    for row in re.split(r'<tr class="main-grid-row main-grid-row-body"', text)[1:]:
        mcell = re.search(
            r'data-column-id="vul_module".*?<div class="main-grid-cell-inner">(.*?)</div>',
            row, re.S)
        if not mcell:
            continue
        cell = mcell.group(1)
        name = re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', '', cell)).strip()
        link = re.search(r'solutions/([a-z0-9._]+)/', cell)
        vm = re.search(r'до\s*([\d]+(?:\.[\d]+)+)', _cell_text(row, 'vul_issue_version'))
        code = link.group(1).lower() if link else None

        if code and code in _SKIP_CODES:
            continue  # Bitrix's own editions -- not third-party modules

        if link and vm:
            dm = re.search(r'([\d]{2}\.[\d]{2}\.[\d]{4})', _cell_text(row, 'vul_date_publication2'))
            lm = re.search(r'data-column-id="vul_mp_link".*?href="([^"]+)"', row, re.S)
            matched.append({
                'code': code,
                'name': name,
                'fixed': vm.group(1),
                'version_raw': 'до ' + vm.group(1),
                'published': dm.group(1) if dm else '',
                'src_link': 'https://marketplace.1c-bitrix.ru/solutions/%s/' % code,
                'fix_link': lm.group(1) if lm else '',
            })
        elif name:
            unmatched.append({
                'name': name,
                'code': code,   # None when the row has no marketplace link
                'status': _cell_text(row, 'vul_issue_version'),
                'published': _cell_text(row, 'vul_date_publication2'),
            })
    return matched, unmatched


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


# A well-formed Bitrix marketplace module code: vendor.module, lowercase.
_VALID_CODE = re.compile(r'^[a-z0-9._]+$')


def reduce_latest(rows):
    """Keep one row per module code. A withdrawn entry (no fixed version --
    vulnerable at any installed version) always supersedes a versioned one;
    otherwise keep the highest fixed version.

    Also a garbage guard: any row whose code isn't a clean module code
    ([a-z0-9._]+) is dropped, so malformed codes from a polluted RSS <code>
    (e.g. a URL query/fragment) never reach the registry regardless of source.
    """
    by = {}
    for m in rows:
        c = m.get('code')
        if not c or not _VALID_CODE.match(c):
            if c:
                print(f"Dropping malformed module code: {c!r}", file=sys.stderr)
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
    """Walk the grid's AJAX pagination until a page adds no new rows.

    Returns (matched_rows, unmatched_rows). The stop condition counts BOTH kinds
    of new rows -- otherwise a trailing page that holds only unmatched
    (withdrawn) rows would be missed once the matched codes are exhausted.
    """
    page_tmpl = (PAGE_URL + '?internal=true&grid_id=vul_dev_grid'
                 '&grid_action=pagination&vul_dev_grid=page-%d')
    rows, unmatched = [], []
    seen_codes, seen_unmatched = set(), set()
    for n in range(1, 20):  # safety cap; grid wraps after the last page
        try:
            page_rows, page_unmatched = parse_html(fetch(page_tmpl % n))
        except Exception:
            break
        new = False
        for m in page_rows:
            if m['code'] not in seen_codes:
                seen_codes.add(m['code'])
                rows.append(m)
                new = True
        for u in page_unmatched:
            key = (u['name'], u.get('code'))
            if key not in seen_unmatched:
                seen_unmatched.add(key)
                unmatched.append(u)
                new = True
        if not new:
            break
    return rows, unmatched


def report_unmatched(unmatched, manual_mods):
    """Warn about grid rows we can't turn into a rule and that the manual
    supplement doesn't cover yet -- typically a newly withdrawn module whose
    slug still needs adding to data/bitrix_vuln_modules_manual.json.

    Emits a GitHub Actions ::warning:: annotation and a run-summary block so the
    gap is visible on the weekly sync PR. Returns the list of gaps.
    """
    covered_codes = {m.get('code') for m in manual_mods}
    covered_names = {(m.get('name') or '').strip() for m in manual_mods}
    gaps = [u for u in unmatched
            if u['name'] not in covered_names and u.get('code') not in covered_codes]
    if not gaps:
        return gaps

    lines = [f"{len(gaps)} vul_dev row(s) could not be matched to a module and "
             "are NOT in the manual supplement -- add each slug to "
             "data/bitrix_vuln_modules_manual.json:"]
    for g in gaps:
        code = g.get('code') or '(no marketplace link -- find the slug)'
        lines.append(f"  - {g['name']} [{g.get('status', '')}] -> code: {code}")
    block = '\n'.join(lines)

    print('\n' + block, file=sys.stderr)
    # GitHub Actions annotation (one line; newlines encoded so it stays intact).
    print('::warning title=Unmatched vul_dev rows::'
          + block.replace('\n', '%0A'))
    # Append to the job's run summary when running under Actions.
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        try:
            with open(summary, 'a', encoding='utf-8') as f:
                f.write('### ⚠️ Unmatched vul_dev rows\n\n')
                for g in gaps:
                    f.write(f"- **{g['name']}** ({g.get('status','')}) — "
                            f"code: `{g.get('code') or 'unknown — add slug'}`\n")
                f.write('\nAdd each to `data/bitrix_vuln_modules_manual.json`.\n')
        except OSError:
            pass
    return gaps


def parse(xml_bytes: bytes):
    root = ET.fromstring(xml_bytes)
    mods = []
    for item in root.iter('item'):
        raw_code = (item.findtext('code') or '').strip().lower()
        src_link = (item.findtext('src_link') or '').strip()
        # The RSS <code> can be polluted with a URL query string / fragment --
        # observed: 'komtet.delivery?update_sys=Y#tab-about-link'. A real module
        # code is only [a-z0-9._], so keep the leading valid run and drop the
        # rest; fall back to the code embedded in src_link if <code> is unusable.
        mc = re.match(r'[a-z0-9._]+', raw_code)
        code = mc.group(0) if mc else ''
        if not code:
            ms = re.search(r'solutions/([a-z0-9._]+)/', src_link)
            code = ms.group(1).lower() if ms else ''
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
            'src_link': src_link,
            'fix_link': (item.findtext('fix_link') or '').strip(),
        })
    mods.sort(key=lambda x: x['code'])
    return mods


def write_registry(mods, version, generated):
    payload = {
        'source': RSS_URL,
        # Monotonic revision, bumped every sync run (even a no-change re-verify),
        # plus the UTC date the registry was last regenerated.
        'version': version,
        'generated': generated,
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


def load_existing_payload():
    try:
        with open(JSON_OUT, encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def load_existing():
    return load_existing_payload().get('modules', [])


def next_version(existing_payload):
    """Monotonic registry revision: existing 'version' + 1 (first run -> 1)."""
    try:
        return int(existing_payload.get('version', 0)) + 1
    except (TypeError, ValueError):
        return 1


def _rule_key(m):
    """Detection-relevant identity of a module rule -- what actually matters for
    flagging. Cosmetic fields (name, dates, links) are ignored so a pure
    metadata refresh doesn't read as a vulnerability change."""
    return (m.get('code'), m.get('fixed'), bool(m.get('withdrawn')))


def modules_changed(old_mods, new_mods):
    """True if the set of module rules differs (order-independent)."""
    return sorted(map(_rule_key, old_mods)) != sorted(map(_rule_key, new_mods))


def _today_utc():
    return datetime.now(timezone.utc).strftime('%Y-%m-%d')


def _emit_output(name, value):
    """Expose a value to later workflow steps via $GITHUB_OUTPUT (no-op locally)."""
    path = os.environ.get('GITHUB_OUTPUT')
    if not path:
        return
    try:
        with open(path, 'a', encoding='utf-8') as f:
            f.write(f"{name}={value}\n")
    except OSError:
        pass


def main(argv):
    manual_mods = load_manual()

    # Local, no-network mode: fold the curated manual entries into the EXISTING
    # generated registry without re-fetching (keeps scraped entries intact).
    if '--merge-manual' in argv:
        existing = load_existing_payload()
        mods = reduce_latest(existing.get('modules', []) + manual_mods)
        write_registry(mods, next_version(existing), _today_utc())
        print(f"{len(mods)} modules after manual merge -> {JSON_OUT}")
        return 0

    if len(argv) > 1 and os.path.isfile(argv[1]):
        xml_bytes = open(argv[1], 'rb').read()
        page_rows, unmatched = [], []
    else:
        xml_bytes = fetch(RSS_URL)
        try:
            page_rows, unmatched = collect_pages()
        except Exception as e:
            print(f"Warning: could not fetch paginated HTML pages: {e}", file=sys.stderr)
            page_rows, unmatched = [], []

    # Warn about grid rows we can't scrape a rule from that the manual supplement
    # doesn't cover yet (newly withdrawn modules needing a slug). Non-fatal -- the
    # sync still runs and the weekly PR is still opened.
    report_unmatched(unmatched, manual_mods)

    existing = load_existing_payload()
    rss_mods = parse(xml_bytes)
    mods = reduce_latest(rss_mods + page_rows + manual_mods)
    changed = modules_changed(existing.get('modules', []), mods)
    version = next_version(existing)

    # Normalize the snapshot (LF endings, no trailing whitespace) so the
    # committed baseline and CI-written file compare cleanly -- avoids spurious
    # weekly diffs from server-side CRLF/trailing spaces.
    text = xml_bytes.decode('utf-8', 'replace')
    normalized = '\n'.join(line.rstrip() for line in text.splitlines()) + '\n'
    os.makedirs(os.path.dirname(RSS_SNAPSHOT), exist_ok=True)
    with open(RSS_SNAPSHOT, 'w', encoding='utf-8', newline='\n') as f:
        f.write(normalized)
    write_registry(mods, version, _today_utc())

    # Tell the workflow whether real module rules changed. False => it's just a
    # version/freshness bump the workflow can auto-merge without review.
    _emit_output('modules_changed', 'true' if changed else 'false')
    _emit_output('version', str(version))
    print(f"{len(mods)} modules, registry version {version} "
          f"({'module changes' if changed else 'no module changes -- version bump'}) "
          f"-> {JSON_OUT}")
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
