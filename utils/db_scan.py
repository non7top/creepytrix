#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Scan a MySQL dump stream for injected PHP / webshell signatures.

Bitrix RCEs (e.g. the intec.core BDU:2026-05967 chain) can write PHP into the
DATABASE, which is eval'd on render -- and a webroot-only restore never removes
it. This module scans a mysqldump stream line-by-line, attributing hits to the
table they appear in, and grading each hit strong (near-certain backdoor) vs
weak (a signature that also occurs in legitimate Bitrix data).

Pure functions only (no I/O) so they are unit-testable without a database.
"""

import re

# Generic signatures -- present in backdoors, but some also occur in legit code.
_GENERIC = re.compile(
    r'eval\s*\(|base64_decode\s*\(|gzinflate|gzuncompress|str_rot13|'
    r'create_function\s*\(|assert\s*\(|\$_(REQUEST|COOKIE|GET|POST|SERVER)\b|'
    r'passthru\s*\(|shell_exec\s*\(|\bsystem\s*\(|preg_replace\s*\([^)]*/e|'
    r'FilesMan|409723\s*\*\s*20|accesson|0dcbfc9f86f6|'
    r'17028f487cb2a84607646da3ad3878ec',
    re.I)

# Strong signatures -- near-certain webshell/backdoor.
_STRONG = re.compile(
    r'\$_(REQUEST|COOKIE|GET|POST)\s*\[[^\]]*\]\s*\(|'
    r'eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|\$_)|'
    r'create_function\s*\(|preg_replace\s*\([^)]*/e|'
    r'\b(FilesMan|c99|r57|b374k|WSO|IndoXploit)\b|'
    r'409723\s*\*\s*20|accesson|0dcbfc9f86f6|17028f487cb2a84607646da3ad3878ec',
    re.I)

# Tables that are known code-execution locations in Bitrix.
KNOWN_EVAL_TABLES = (
    'b_option', 'b_agent', 'b_event_message', 'b_iblock_element',
    'b_landing_block', 'b_learn_lesson', 'b_user_field', 'b_composite',
)

_INSERT_RE = re.compile(r'INSERT INTO `([^`]+)`')
_STRUCT_RE = re.compile(r'Table structure for table `([^`]+)`')


def known_eval_table(table: str) -> bool:
    t = (table or '').lower()
    return t in KNOWN_EVAL_TABLES or t.startswith('b_intec')


def scan_dump(lines, max_snippet: int = 220):
    """Yield (table, severity, snippet) for each signature hit in a dump stream.

    severity is 'critical' for a strong match, else 'high'.
    """
    table = '?'
    for line in lines:
        if line.startswith('INSERT INTO '):
            m = _INSERT_RE.match(line)
            if m:
                table = m.group(1)
        elif 'Table structure for table' in line:
            m = _STRUCT_RE.search(line)
            if m:
                table = m.group(1)
        if _GENERIC.search(line):
            severity = 'critical' if _STRONG.search(line) else 'high'
            snippet = re.sub(r'\s+', ' ', line).strip()[:max_snippet]
            yield (table, severity, snippet)
