<?php
/**
 * creepytrix — bitrix_cleanup.php
 *
 * Detect and (with --fix) remove DB-resident + on-disk backdoors from a
 * compromised 1C-Bitrix site -- e.g. the intec.core / BDU:2026-05967 chain,
 * where a PHP loader is injected into b_site_template.CONDITION and the
 * gz-compressed payload hides in an otherwise-empty table (b_forum_menu, ...),
 * cached to /bitrix/cache/<n> and eval'd on every render. Webroot-only restores
 * never remove it because it lives in the DATABASE.
 *
 * Run ON the host:
 *   php bitrix_cleanup.php [--root=/path/to/webroot] [--fix] [--yes]
 *
 * DRY-RUN by default (reports only). --fix quarantines then removes.
 * Auto-fix touches only high-confidence items: the b_site_template loader
 * rows and the stage-2 payload tables they reference, confirmed shell files,
 * and the dropped cache. DB agents/options/content are REPORTED, never
 * auto-deleted (higher false-positive risk -- review by hand).
 *
 * ALWAYS back up the database and site before running with --fix.
 * After cleanup you MUST also: update intec.core >= 1.2.30, redeploy the
 * template, and rotate DB + admin credentials -- or the site re-infects.
 */

error_reporting(E_ALL & ~E_DEPRECATED & ~E_NOTICE & ~E_WARNING);

$o = getopt('', ['root::', 'fix', 'yes', 'help']);
if (isset($o['help'])) {
    fwrite(STDERR, "Usage: php bitrix_cleanup.php [--root=/webroot] [--fix] [--yes]\n");
    exit(0);
}
$FIX = isset($o['fix']);

function say($s)  { echo $s . "\n"; }
function warn($s) { fwrite(STDERR, $s . "\n"); }

/* ---------------- 1. locate the web root ---------------- */
$cands = [];
if (!empty($o['root'])) $cands[] = rtrim($o['root'], '/');
else foreach (['.', '/home/bitrix/www', '/var/www/html'] as $c) $cands[] = $c;
$ROOT = null;
foreach ($cands as $c) {
    foreach (['', '/web', '/www', '/public_html', '/httpdocs'] as $sub) {
        $b = $c . $sub;
        if (is_dir($b . '/bitrix/modules/main')) { $ROOT = realpath($b); break 2; }
    }
}
if (!$ROOT) { warn("Not a Bitrix web root. Use --root=/path/to/webroot"); exit(2); }
$ACCOUNT = dirname($ROOT);   // parent, so backup/ cgi-bin/ tmp/ are also swept
say("Web root : $ROOT");
say("Mode     : " . ($FIX ? "FIX (quarantine + remove)" : "DRY-RUN (report only)"));

/* ---------------- 2. DB connection from .settings.php ---------------- */
$settings = $ROOT . '/bitrix/.settings.php';
if (!is_file($settings)) { warn("Missing $settings"); exit(2); }
$cfg = include $settings;
$c = isset($cfg['connections']['value']['default']) ? $cfg['connections']['value']['default'] : null;
if (!$c) { warn("Cannot read DB connection from .settings.php"); exit(2); }
$db = @new mysqli($c['host'] ?: 'localhost', $c['login'], $c['password'], $c['database']);
if ($db->connect_errno) { warn("DB connect failed: " . $db->connect_error); exit(2); }
$db->set_charset('utf8mb4');
say("Database : {$c['database']}");
say(str_repeat('-', 64));

/* ---------------- signatures ---------------- */
$STRONG = '/\$_(REQUEST|COOKIE|GET|POST)\s*\[[^\]]*\]\s*\(|'
        . 'eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|\$_)|'
        . 'create_function\s*\(|preg_replace\s*\([^)]*\/e|'
        . '\b(FilesMan|c99|r57|b374k|WSO|IndoXploit)\b|'
        . '409723\s*\*\s*20|accesson|0dcbfc9f86f6|17028f487cb2a84607646da3ad3878ec/i';
$COND   = '/eval\s*\(|gzinflate|gzuncompress|base64_decode|file_get_contents|\$_(GET|POST|REQUEST|COOKIE|SERVER)/i';

$QDIR = null;
function quarantine() {
    global $QDIR, $ACCOUNT;
    if ($QDIR === null) {
        $QDIR = $ACCOUNT . '/creepytrix_quarantine_' . date('Ymd_His');
        @mkdir($QDIR, 0700, true);
    }
    return $QDIR;
}
function backup_row($table, $row) {
    $f = quarantine() . '/removed_db_rows.jsonl';
    file_put_contents($f, json_encode(['table' => $table, 'row' => $row]) . "\n", FILE_APPEND);
}

$found = 0; $removed_db = 0; $removed_files = 0; $review = 0;
$stage2 = []; $cache_files = [];

/* ---------------- 3. b_site_template CONDITION loaders ---------------- */
$r = $db->query("SELECT ID, SITE_ID, `CONDITION` FROM b_site_template");
if ($r) foreach ($r as $row) {
    if ($row['CONDITION'] !== '' && preg_match($COND, $row['CONDITION'])) {
        $found++;
        say("[DB] b_site_template id={$row['ID']} — backdoor loader in CONDITION:");
        say("      " . substr(preg_replace('/\s+/', ' ', $row['CONDITION']), 0, 180));
        if (preg_match('/FROM\s+`?([a-z0-9_]+)`?/i', $row['CONDITION'], $m)) $stage2[strtolower($m[1])] = 1;
        if (preg_match('/DOCUMENT_ROOT["\']\s*\.\s*["\']([^"\']+)/', $row['CONDITION'], $m)) $cache_files[$m[1]] = 1;
        if ($FIX) {
            backup_row('b_site_template', $row);
            $db->query("DELETE FROM b_site_template WHERE ID=" . (int)$row['ID']);
            $removed_db++; say("      -> DELETED");
        }
    }
}

/* ---------------- 4. stage-2 payload tables the loader references ---------------- */
foreach (array_keys($stage2) as $t) {
    if (!preg_match('/^[a-z0-9_]+$/', $t)) continue;
    $r = $db->query("SELECT * FROM `$t`");
    if (!$r) continue;
    foreach ($r as $row) {
        $found++;
        $id = isset($row['ID']) ? $row['ID'] : '?';
        say("[DB] stage-2 payload in `$t` id=$id (" . strlen(json_encode($row)) . " bytes)");
        if ($FIX) {
            backup_row($t, $row);
            if (isset($row['ID'])) $db->query("DELETE FROM `$t` WHERE ID=" . (int)$row['ID']);
            $removed_db++; say("      -> DELETED");
        }
    }
}

/* ---------------- 5. report-only DB locations (review by hand) ---------------- */
$review_q = [
    'b_agent'         => "SELECT ID,NAME AS V FROM b_agent",
    'b_option'        => "SELECT NAME AS ID,VALUE AS V FROM b_option",
    'b_event_message' => "SELECT ID,BODY AS V FROM b_event_message",
];
foreach ($review_q as $table => $q) {
    $r = $db->query($q);
    if (!$r) continue;
    foreach ($r as $row) {
        if (preg_match($STRONG, (string)$row['V'])) {
            $review++;
            say("[DB][REVIEW] $table id={$row['ID']} — suspicious code (not auto-removed):");
            say("      " . substr(preg_replace('/\s+/', ' ', $row['V']), 0, 160));
        }
    }
}

/* ---------------- 6. filesystem sweep (whole account) ---------------- */
say(str_repeat('-', 64));
$it = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($ACCOUNT, FilesystemIterator::SKIP_DOTS)
);
foreach ($it as $f) {
    if (!$f->isFile()) continue;
    $path = $f->getPathname();
    $name = $f->getFilename();
    $lower = strtolower($name);
    $is_php = preg_match('/\.(php|phtml|php[0-9]|phps|phar)$/i', $name);
    // PHP where it must never live:
    $bad_dir = preg_match('#/(upload|bitrix/tmp|bitrix/cache|bitrix/managed_cache|bitrix/stack_cache)/#', $path);
    $hit = false;
    if ($is_php && $bad_dir) $hit = 'php-in-static-dir';
    elseif ($is_php && $f->getSize() < 1500000) {
        $data = @file_get_contents($path, false, null, 0, 1500000);
        if ($data !== false && preg_match($STRONG, $data)) $hit = 'webshell-signature';
    } elseif ($lower === '.htaccess' || $lower === '.user.ini') {
        $data = @file_get_contents($path);
        if ($data !== false && preg_match('/auto_prepend_file|auto_append_file|AddHandler[^\n]*php|SetHandler[^\n]*php/i', $data)) $hit = 'htaccess-persistence';
    }
    if ($hit) {
        $found++;
        say("[FILE] $hit: $path");
        if ($FIX && $hit !== 'htaccess-persistence') {  // never auto-edit .htaccess
            $q = quarantine() . '/files' . dirname(str_replace($ACCOUNT, '', $path));
            @mkdir($q, 0700, true);
            @copy($path, $q . '/' . $name);
            if (@unlink($path)) { $removed_files++; say("      -> QUARANTINED + removed"); }
        }
    }
}

/* ---------------- 7. purge caches + dropped payload files (fix only) ---------------- */
if ($FIX) {
    foreach (array_keys($cache_files) as $rel) {
        $p = $ROOT . '/' . ltrim($rel, '/');
        if (is_file($p) && @unlink($p)) say("[FIX] removed dropped payload cache: $p");
    }
    foreach (['bitrix/cache', 'bitrix/managed_cache', 'bitrix/stack_cache', 'bitrix/html_pages'] as $d) {
        $full = $ROOT . '/' . $d;
        if (is_dir($full)) { rrmdir_contents($full); say("[FIX] purged $d/"); }
    }
}

function rrmdir_contents($dir) {
    foreach (scandir($dir) as $e) {
        if ($e === '.' || $e === '..') continue;
        $p = $dir . '/' . $e;
        if (is_dir($p)) { rrmdir_contents($p); @rmdir($p); } else @unlink($p);
    }
}

/* ---------------- summary ---------------- */
say(str_repeat('=', 64));
say("Findings         : $found");
say("Review-only (DB) : $review  (b_agent/b_option/b_event_message — inspect manually)");
if ($FIX) {
    say("DB rows removed  : $removed_db");
    say("Files quarantined: $removed_files");
    if ($QDIR) say("Quarantine dir   : $QDIR");
} else {
    say("");
    say("DRY-RUN: nothing changed. Re-run with --fix to quarantine + remove.");
}
say("");
say("!!! Cleanup does NOT close the entry hole. You MUST also:");
say("    1) update intec.core to >= 1.2.30 and redeploy the template,");
say("    2) rotate DB + Bitrix admin credentials,");
say("    3) then lift any IP block.");
