<?php
/**
 * creepytrix_probe.php — self-contained, read-only Bitrix vulnerability probe.
 *
 * A throwaway one-off probe: a dispatcher (e.g. wr-util) populates the two
 * __CREEPYTRIX_*__ slots below, uploads this single file into a site, triggers
 * it over HTTP (or runs it via CLI on the host), reads the output, and deletes
 * it. The file also deletes ITSELF as its first action.
 *
 * What it does: reads installed Bitrix module versions (by PARSING each
 * modules/<code>/install/version.php as text -- never include()) and the
 * platform SM_VERSION, compares them against an embedded snapshot of the
 * creepytrix vulnerable-module registry (data/bitrix_vuln_modules.json), and
 * reports findings. Read-only: it never writes, executes, or modifies anything
 * on the target, and makes no outbound network calls.
 *
 * OUTPUT: first line is a sentinel `CREEPYTRIX 1 registry=<v>`; the second line
 * is a single-line JSON payload. A caller matches the sentinel by prefix; if
 * it is absent the probe did not execute (treat as inconclusive).
 *
 * The two slots, substituted at dispatch time:
 *   __CREEPYTRIX_REGISTRY_B64__  base64 of the registry JSON (inline, no escaping
 *                                surface -- never string-concatenate JSON here)
 *   __CREEPYTRIX_TOKEN__         shared secret; required (via header/POST) when
 *                                triggered over HTTP. CLI runs skip the check.
 */

/* 1) Remove ourselves FIRST -- before any work -- so a fatal midway can never
 *    strand an executable probe in a live docroot. The dispatcher's FTP remove
 *    is only a backstop (it covers a fatal that happens before this line). */
@unlink(__FILE__);

/* 2) Silence PHP diagnostics BEFORE anything else can emit. A stray notice or
 *    warning printed ahead of the JSON corrupts it and the caller's parse dies
 *    on an unrelated-looking error. */
@ini_set('display_errors', '0');
@ini_set('html_errors', '0');
error_reporting(0);

define('CREEPYTRIX_PROBE_SCHEMA', 1);

$REGISTRY_B64 = '__CREEPYTRIX_REGISTRY_B64__';
$EXPECTED_TOKEN = '__CREEPYTRIX_TOKEN__';

$IS_CLI = (php_sapi_name() === 'cli');

/* ?ping answers BEFORE the token check, so a dispatcher can confirm the probe
 *  executed separately from confirming it authenticated. */
if (!$IS_CLI && isset($_GET['ping'])) {
    echo "CREEPYTRIX " . CREEPYTRIX_PROBE_SCHEMA . " ping\n";
    exit;
}

/* Token guard for HTTP triggers only. Read from a header or POST body, never
 * $_GET (a $_GET secret is written to the plaintext access log on every call). */
if (!$IS_CLI) {
    $got = '';
    if (isset($_SERVER['HTTP_X_CREEPYTRIX_TOKEN'])) $got = $_SERVER['HTTP_X_CREEPYTRIX_TOKEN'];
    elseif (isset($_POST['token'])) $got = $_POST['token'];
    $slot_unpopulated = (strpos($EXPECTED_TOKEN, '__CREEPYTRIX') === 0);
    if ($EXPECTED_TOKEN === '' || $slot_unpopulated || !ct_hash_equals($EXPECTED_TOKEN, (string)$got)) {
        if (!headers_sent()) header('HTTP/1.1 403 Forbidden');
        echo "CREEPYTRIX " . CREEPYTRIX_PROBE_SCHEMA . " forbidden\n";
        exit;
    }
}

/* ---- helpers -------------------------------------------------------------- */

function ct_hash_equals($a, $b) {
    if (function_exists('hash_equals')) return hash_equals($a, $b);  // PHP >= 5.6
    if (strlen($a) !== strlen($b)) return false;
    $r = 0;
    for ($i = 0, $n = strlen($a); $i < $n; $i++) $r |= (ord($a[$i]) ^ ord($b[$i]));
    return $r === 0;
}

/* Locate the Bitrix document root. The probe may have landed in the docroot OR
 * in a fallback subdir (public/, files/, ...), so cwd is not necessarily the
 * root: prefer DOCUMENT_ROOT, then walk up from the probe's own directory. */
function ct_find_web_root() {
    $cands = array();
    if (!empty($_SERVER['DOCUMENT_ROOT'])) $cands[] = rtrim($_SERVER['DOCUMENT_ROOT'], '/');
    $d = __DIR__;
    for ($i = 0; $i < 8; $i++) {
        $cands[] = $d;
        $parent = dirname($d);
        if ($parent === $d) break;
        $d = $parent;
    }
    foreach ($cands as $c) {
        if ($c !== '' && is_dir($c . '/bitrix/modules/main')) return $c;
    }
    return null;
}

/* Read a module's VERSION by PARSING version.php as text. Never include(): many
 * modules set the same $arModuleVersion, and anything under a module can pull in
 * Bitrix's prolog and spew HTML into our output. local/ overrides bitrix/. */
function ct_module_version($web_root, $code) {
    foreach (array('local', 'bitrix') as $base) {
        $path = $web_root . '/' . $base . '/modules/' . $code . '/install/version.php';
        $c = @file_get_contents($path);
        if ($c !== false && preg_match('/["\']VERSION["\']\s*=>\s*["\']([\d.]+)["\']/', $c, $m)) {
            return $m[1];
        }
    }
    return null;
}

function ct_platform_version($web_root) {
    $p = $web_root . '/bitrix/modules/main/classes/general/version.php';
    $c = @file_get_contents($p);
    if ($c !== false && preg_match('/SM_VERSION["\']?\s*,\s*["\']([\d.]+)["\']/', $c, $m)) {
        return $m[1];
    }
    return ct_module_version($web_root, 'main');
}

function ct_installed_modules($web_root) {
    $codes = array();
    foreach (array('bitrix', 'local') as $base) {
        $dir = $web_root . '/' . $base . '/modules';
        if (!is_dir($dir)) continue;
        $entries = @scandir($dir);
        if ($entries === false) continue;
        foreach ($entries as $e) {
            if ($e === '.' || $e === '..' || $e[0] === '.') continue;
            if (is_dir($dir . '/' . $e)) $codes[$e] = true;
        }
    }
    $out = array();
    foreach (array_keys($codes) as $code) {
        $v = ct_module_version($web_root, $code);
        if ($v !== null) $out[$code] = $v;
    }
    ksort($out);
    return $out;
}

function ct_emit($result) {
    $rv = isset($result['registry_version']) ? $result['registry_version'] : '?';
    echo "CREEPYTRIX " . CREEPYTRIX_PROBE_SCHEMA . " registry=" . $rv . "\n";
    echo json_encode($result, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n";
    exit;
}

/* ---- main ----------------------------------------------------------------- */

$result = array(
    'tool' => 'creepytrix_probe',
    'schema' => CREEPYTRIX_PROBE_SCHEMA,
    'registry_version' => null,
    'web_root' => null,
    'bitrix_version' => null,
    'module_versions' => array(),
    'summary' => array(
        'total_findings' => 0, 'critical' => 0, 'high' => 0,
        'medium' => 0, 'low' => 0, 'info' => 0, 'confirmed_vulnerable' => 0,
    ),
    'all_findings' => array(),
    'error' => null,
);

/* Decode the embedded registry (inline base64 -> JSON). */
$registry = null;
if (strpos($REGISTRY_B64, '__CREEPYTRIX') !== 0) {
    $decoded = base64_decode($REGISTRY_B64, true);
    if ($decoded !== false) $registry = json_decode($decoded, true);
}
// Fail closed: an unfilled slot, a decode failure, OR an empty ruleset must
// refuse -- a vuln scanner that reports a clean bill because its rules never
// loaded is the one wrong answer that matters.
if (!is_array($registry) || empty($registry['modules'])) {
    $result['error'] = 'embedded vuln registry not populated or empty';
    ct_emit($result);
}
$result['registry_version'] = isset($registry['version']) ? $registry['version'] : null;

$web_root = ct_find_web_root();
if ($web_root === null) {
    $result['error'] = 'not a Bitrix web root (no bitrix/modules/main found)';
    ct_emit($result);
}
$result['web_root'] = $web_root;
$result['bitrix_version'] = ct_platform_version($web_root);
$result['module_versions'] = ct_installed_modules($web_root);

$findings = array();

/* Registry check: installed module below its fixed version, or a withdrawn
 * module installed at ANY version (removed from the marketplace -> remove it). */
foreach ($registry['modules'] as $mod) {
    if (empty($mod['code'])) continue;
    $code = $mod['code'];
    $installed = isset($result['module_versions'][$code])
        ? $result['module_versions'][$code]
        : ct_module_version($web_root, $code);
    if ($installed === null) continue;  // not installed
    $result['module_versions'][$code] = $installed;
    $name = isset($mod['name']) ? $mod['name'] : '';
    $fix_link = isset($mod['fix_link']) ? $mod['fix_link'] : '';

    if (!empty($mod['withdrawn'])) {
        $findings[] = array(
            'severity' => 'critical', 'category' => 'module', 'code' => $code,
            'installed' => $installed, 'fixed' => null,
            'title' => "Withdrawn module installed: $code $installed",
            'detail' => trim("$name -- removed from the marketplace for security "
                . "(withdrawn). No fixed version; REMOVE it. $fix_link"),
        );
    } elseif (!empty($mod['fixed']) && version_compare($installed, $mod['fixed'], '<')) {
        $findings[] = array(
            'severity' => 'high', 'category' => 'module', 'code' => $code,
            'installed' => $installed, 'fixed' => $mod['fixed'],
            'title' => "Vulnerable module: $code $installed < {$mod['fixed']}",
            'detail' => trim("$name -- installed $installed, fixed in {$mod['fixed']}. "
                . "Update it. $fix_link"),
        );
    }
}

/* Config-permission hygiene (read-only stat; no contents read). */
foreach (array('bitrix/.settings.php', 'bitrix/php_interface/dbconn.php') as $rel) {
    $p = $web_root . '/' . $rel;
    if (!is_file($p)) continue;
    $perms = @fileperms($p);
    if ($perms !== false && ($perms & 0x0004)) {  // world-readable
        $findings[] = array(
            'severity' => 'high', 'category' => 'permission', 'code' => $rel,
            'installed' => null, 'fixed' => null,
            'title' => "World-readable config: $rel",
            'detail' => sprintf('mode %04o -- may leak DB credentials; restrict to the web-server user.', $perms & 0777),
        );
    }
}

foreach ($findings as $f) {
    $result['all_findings'][] = $f;
    $sev = $f['severity'];
    if (isset($result['summary'][$sev])) $result['summary'][$sev]++;
    if (($sev === 'critical' || $sev === 'high') && $f['category'] === 'module') {
        $result['summary']['confirmed_vulnerable']++;
    }
}
$result['summary']['total_findings'] = count($result['all_findings']);

ct_emit($result);
