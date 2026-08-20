#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Content-based heuristics to decide whether a 200 response is a REAL exposure.

Bitrix routinely answers with HTTP 200 for things that are NOT exposed:
- a PHP file that executed and returned an empty body (0 bytes),
- a meta-refresh / JS redirect to the admin login,
- the admin login page itself.

A status-code-only check flags all of these as "exposed", producing false
positives. These helpers look at the body instead.
"""

# Markers that identify a Bitrix login / auth page.
_LOGIN_MARKERS = (
    'user_login', 'user_password', 'login.min.css', 'panel/main/login',
    'auth_form', 'bx-authform', 'authorize', 'name="login"', 'bitrix_login',
)

# Raw PHP / Bitrix-config source markers (a served, unexecuted source file).
_SOURCE_MARKERS = (
    '<?php', '<?=', 'dbpassword', 'dblogin', 'dbname', 'return array',
    "'debug'", 'define(', '$db',
)


def is_denied_or_login(text: str) -> bool:
    """True if the body is a login page or a client-side redirect (not exposure)."""
    if not text:
        return True
    low = text.lower()
    if 'http-equiv="refresh"' in low or "http-equiv='refresh'" in low:
        return True
    if 'window.location' in low and ('login' in low or 'auth' in low):
        return True
    return any(m in low for m in _LOGIN_MARKERS)


def looks_exposed(resp, want_source: bool = False) -> bool:
    """
    True only if a 200 response is a genuine exposure.

    - non-empty body,
    - not a login page / redirect,
    - when want_source: the body must actually look like served source/config
      (raw PHP tags, DB-config keys), not rendered HTML.
    """
    if not resp or getattr(resp, 'status_code', None) != 200:
        return False
    body = getattr(resp, 'text', '') or ''
    if not body.strip():
        return False
    if is_denied_or_login(body):
        return False
    if want_source:
        low = body.lower()
        return body.lstrip().startswith('<?') or any(m in low for m in _SOURCE_MARKERS)
    return True
