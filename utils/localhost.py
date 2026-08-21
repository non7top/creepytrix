#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Host inspection helper for the tool's local mode.

Local mode runs ON the target host (with the operator's authorization) and can
answer questions remote black-box scanning cannot: exact installed package
versions, distro identity, and on-disk config/permissions. Everything here is
read-only and non-destructive -- it queries the package database and reads
files, it never installs, modifies, or executes target code.

Commands are run WITHOUT a shell (list argv only) so there is no injection
surface, and a missing binary is a soft failure (returns None), not a crash.
"""

import os
import re
import shutil
import subprocess
from typing import List, Optional, Tuple


class LocalHost:
    """Read-only inspection primitives for the machine we are running on."""

    def __init__(self, logger=None):
        self.logger = logger
        self._os_release: Optional[dict] = None
        self.web_root: Optional[str] = None  # set by the local scanner

    # -- process execution ------------------------------------------------
    def run(self, cmd: List[str], timeout: int = 10) -> Tuple[Optional[int], str, str]:
        """Run argv (no shell). Returns (returncode, stdout, stderr).

        returncode is None when the binary is missing or the call times out.
        """
        if not cmd or shutil.which(cmd[0]) is None:
            return None, '', f'{cmd[0] if cmd else "?"}: not found'
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, check=False,
            )
            return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
        except subprocess.TimeoutExpired:
            return None, '', 'timeout'
        except Exception as e:  # pragma: no cover - defensive
            return None, '', str(e)

    def has(self, binary: str) -> bool:
        return shutil.which(binary) is not None

    # -- filesystem -------------------------------------------------------
    def exists(self, path: str) -> bool:
        return os.path.exists(path)

    def read_file(self, path: str, max_bytes: int = 65536) -> Optional[str]:
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                return f.read(max_bytes)
        except OSError:
            return None

    def world_readable(self, path: str) -> Optional[bool]:
        """True if others (o+r) can read the file. None if it does not exist."""
        try:
            mode = os.stat(path).st_mode
        except OSError:
            return None
        return bool(mode & 0o004)

    def mode_octal(self, path: str) -> Optional[str]:
        try:
            return oct(os.stat(path).st_mode & 0o777)
        except OSError:
            return None

    # -- distro identity --------------------------------------------------
    def os_release(self) -> dict:
        if self._os_release is None:
            data = {}
            content = self.read_file('/etc/os-release') or ''
            for line in content.splitlines():
                if '=' in line:
                    k, _, v = line.partition('=')
                    data[k.strip()] = v.strip().strip('"')
            self._os_release = data
        return self._os_release

    def distro_family(self) -> str:
        """'debian', 'rhel', or 'unknown' (from ID / ID_LIKE)."""
        rel = self.os_release()
        ident = (rel.get('ID', '') + ' ' + rel.get('ID_LIKE', '')).lower()
        if any(x in ident for x in ('debian', 'ubuntu')):
            return 'debian'
        if any(x in ident for x in ('rhel', 'fedora', 'centos', 'rocky', 'alma')):
            return 'rhel'
        return 'unknown'

    def os_codename(self) -> Optional[str]:
        rel = self.os_release()
        return rel.get('VERSION_CODENAME') or None

    # -- package queries --------------------------------------------------
    def dpkg_version(self, pkg: str) -> Optional[str]:
        rc, out, _ = self.run(['dpkg-query', '-W', "-f=${Version}", pkg])
        return out if rc == 0 and out else None

    def rpm_version(self, pkg: str) -> Optional[str]:
        rc, out, _ = self.run(['rpm', '-q', '--qf', '%{VERSION}-%{RELEASE}', pkg])
        return out if rc == 0 and out and 'not installed' not in out else None

    def compare_deb(self, v1: str, op: str, v2: str) -> Optional[bool]:
        """Compare Debian versions via dpkg. op in lt/le/eq/ne/ge/gt.

        Returns True/False, or None if dpkg is unavailable.
        """
        rc, _, _ = self.run(['dpkg', '--compare-versions', v1, op, v2])
        if rc is None:
            return None
        return rc == 0

    # -- Bitrix source inspection -----------------------------------------
    # Common document roots to probe when --web-root is not given.
    WEB_ROOT_CANDIDATES = [
        '/home/bitrix/www', '/var/www/html', '/var/www/bitrix', '/var/www', '.',
    ]

    _MODULE_VER_RE = re.compile(r'["\']VERSION["\']\s*=>\s*["\']([\d.]+)["\']')
    _SM_VERSION_RE = re.compile(r'SM_VERSION["\']?\s*,\s*["\']([\d.]+)["\']')

    # A document root may be the path itself or nested under one of these.
    _DOCROOT_SUBDIRS = ('', 'web', 'www', 'public_html', 'httpdocs', 'public')

    def find_web_root(self, explicit: Optional[str] = None) -> Optional[str]:
        """Locate a Bitrix document root (one containing bitrix/modules/main).

        Detection is directory-based (not tied to a specific version.php path,
        which varies between editions/versions). If the given path is a parent,
        common docroot subdirs (web/, www/, ...) are also checked.
        """
        candidates = [explicit] if explicit else list(self.WEB_ROOT_CANDIDATES)
        for root in candidates:
            if not root:
                continue
            root = os.path.abspath(os.path.expanduser(root))
            for sub in self._DOCROOT_SUBDIRS:
                base = os.path.join(root, sub) if sub else root
                if os.path.isdir(os.path.join(base, 'bitrix', 'modules', 'main')):
                    return base
        return None

    def bitrix_module_version(self, web_root: str, module: str) -> Optional[str]:
        """Exact installed version of a Bitrix module (from install/version.php).

        Checks local/modules first (custom/overriding), then bitrix/modules.
        """
        for base in ('local', 'bitrix'):
            path = os.path.join(web_root, base, 'modules', module, 'install', 'version.php')
            content = self.read_file(path)
            if content:
                m = self._MODULE_VER_RE.search(content)
                if m:
                    return m.group(1)
        return None

    def list_installed_modules(self, web_root: str) -> dict:
        """Every installed module and its version, discovered by scanning both
        module trees: local/modules (custom/overriding) and bitrix/modules.

        Returns an ordered {code: version} dict sorted by code. A module code
        may contain a dot (e.g. 'intec.core'). local/ overrides bitrix/ when a
        module exists in both. Modules with no readable version.php are omitted.
        """
        codes = set()
        for base in ('bitrix', 'local'):
            moddir = os.path.join(web_root, base, 'modules')
            if not os.path.isdir(moddir):
                continue
            try:
                entries = os.listdir(moddir)
            except OSError:
                continue
            for name in entries:
                if name.startswith('.'):
                    continue
                if os.path.isdir(os.path.join(moddir, name)):
                    codes.add(name)
        modules = {}
        for code in sorted(codes):
            ver = self.bitrix_module_version(web_root, code)  # local-first
            if ver:
                modules[code] = ver
        return modules

    def bitrix_version(self, web_root: str) -> Optional[str]:
        """Platform (main module) version -- the exact SM_VERSION."""
        # Prefer the canonical SM_VERSION define, fall back to the main module.
        content = self.read_file(os.path.join(
            web_root, 'bitrix', 'modules', 'main', 'classes', 'general', 'version.php'))
        if content:
            m = self._SM_VERSION_RE.search(content)
            if m:
                return m.group(1)
        return self.bitrix_module_version(web_root, 'main')

    def bitrix_db_config(self, web_root: str):
        """Read the default DB connection from bitrix/.settings.php via php.

        Returns {host, database, login, password} or None. Uses the php CLI to
        evaluate the config (reliable) rather than regex-parsing PHP.
        """
        settings = os.path.join(web_root, 'bitrix', '.settings.php')
        if not os.path.exists(settings) or not self.has('php'):
            return None
        code = ('$c=(include %r)["connections"]["value"]["default"];'
                'echo $c["host"]."\n".$c["database"]."\n".$c["login"]."\n".$c["password"];'
                ) % settings
        rc, out, _ = self.run(['php', '-r', code], timeout=15)
        if rc != 0 or not out:
            return None
        parts = out.split('\n')
        if len(parts) < 4:
            return None
        return {'host': parts[0] or 'localhost', 'database': parts[1],
                'login': parts[2], 'password': parts[3]}

    @staticmethod
    def version_tuple(version: str) -> tuple:
        """Parse a dotted Bitrix version into an int tuple for comparison."""
        parts = []
        for chunk in version.split('.'):
            try:
                parts.append(int(chunk))
            except ValueError:
                parts.append(0)
        return tuple(parts)
