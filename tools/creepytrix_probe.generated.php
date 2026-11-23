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

$REGISTRY_B64 = 'eyJzb3VyY2UiOiJodHRwczovL3d3dy4xYy1iaXRyaXgucnUvdnVsX2Rldi9yc3MvIiwidmVyc2lvbiI6MTAsImdlbmVyYXRlZCI6IjIwMjYtMTEtMjMiLCJub3RlIjoiQXV0by1nZW5lcmF0ZWQgZnJvbSB0aGUgMUMtQml0cml4IHZ1bF9kZXYgcmVnaXN0cnkgYnkgc2NyaXB0cy91cGRhdGVfdnVsbl9yZWdpc3RyeS5weSwgcGx1cyBjdXJhdGVkIHdpdGhkcmF3bi91bnB1Ymxpc2hlZCBtb2R1bGVzIGZyb20gYml0cml4X3Z1bG5fbW9kdWxlc19tYW51YWwuanNvbi4gQSBtb2R1bGUgaXMgdnVsbmVyYWJsZSB3aGVuIGl0cyBpbnN0YWxsZWQgdmVyc2lvbiBpcyA8IFwiZml4ZWRcIiwgb3IgdW5jb25kaXRpb25hbGx5IHdoZW4gXCJ3aXRoZHJhd25cIjogdHJ1ZSAocmVtb3ZlZCBmcm9tIHRoZSBtYXJrZXRwbGFjZSAtLSBubyBmaXg7IHJlbW92ZSBpdCkuIiwibW9kdWxlcyI6W3siY29kZSI6ImFjcml0LmJvbnVzIiwibmFtZSI6ItCh0LjRgdGC0LXQvNCwINCx0L7QvdGD0YHQvtCyLiDQn9GA0L7Qs9GA0LDQvNC80Ysg0LvQvtGP0LvRjNC90L7RgdGC0LgiLCJmaXhlZCI6IjMuNC45IiwidmVyc2lvbl9yYXciOiLQtNC+IDMuNC45IiwicHVibGlzaGVkIjoiMTAuMDkuMjAyNSIsInNyY19saW5rIjoiaHR0cHM6Ly9tYXJrZXRwbGFjZS4xYy1iaXRyaXgucnUvc29sdXRpb25zL2Fjcml0LmJvbnVzLyIsImZpeF9saW5rIjoiaHR0cHM6Ly90Lm1lL2N5YmVyb2tfbmV3cy8xNDAifSx7ImNvZGUiOiJhY3JpdC5pbXBvcnQiLCJuYW1lIjoi0KPQvdC40LLQtdGA0YHQsNC70YzQvdGL0Lkg0LjQvNC/0L7RgNGCIiwiZml4ZWQiOiIxLjc5LjAiLCJ2ZXJzaW9uX3JhdyI6ItC00L4gMS43OS4wIiwicHVibGlzaGVkIjoiMjkuMDYuMjAyNiIsInNyY19saW5rIjoiaHR0cHM6Ly9tYXJrZXRwbGFjZS4xYy1iaXRyaXgucnUvc29sdXRpb25zL2Fjcml0LmltcG9ydC8iLCJmaXhfbGluayI6Imh0dHBzOi8vd3d3LmFjcml0LXN0dWRpby5ydS90ZWNobmljYWwtc3VwcG9ydC9uYXN0cm95a2EtbW9kdWx5YS11bml2ZXJzYWxueXktaW1wb3J0L3VzdHJhbmVubnllLXV5YXp2aW1vc3RpLXYtdmVyc2lpLXYxLTc5LTAvIn0seyJjb2RlIjoiYXNwcm8uYWxsY29ycCIsIm5hbWUiOiLQkNGB0L/RgNC+OiDQmtC+0YDQv9C+0YDQsNGC0LjQstC90YvQuSDRgdCw0LnRgiIsImZpeGVkIjoiMS4xLjE3IiwidmVyc2lvbl9yYXciOiLQtNC+IDEuMS4xNyIsInB1Ymxpc2hlZCI6IjA2LjAyLjIwMjUiLCJzcmNfbGluayI6Imh0dHBzOi8vbWFya2V0cGxhY2UuMWMtYml0cml4LnJ1L3NvbHV0aW9ucy9hc3Byby5hbGxjb3JwLyIsImZpeF9saW5rIjoiaHR0cHM6Ly9hc3Byby5ydS9uZXdzL3Z6bG9teS1zYXl0b3YtYXNwcm8vIn0seyJjb2RlIjoiYXNwcm8uYWxsY29ycDIiLCJuYW1lIjoi0JDRgdC/0YDQvjog0JrQvtGA0L/QvtGA0LDRgtC40LLQvdGL0Lkg0YHQsNC50YIgMi4wIiwiZml4ZWQiOiIxLjIuMjUiLCJ2ZXJzaW9uX3JhdyI6ItC00L4gMS4yLjI1IiwicHVibGlzaGVkIjoiMDYuMDIuMjAyNSIsInNyY19saW5rIjoiaHR0cHM6Ly9tYXJrZXRwbGFjZS4xYy1iaXRyaXgucnUvc29sdXRpb25zL2FzcHJvLmFsbGNvcnAyLyIsImZpeF9saW5rIjoiaHR0cHM6Ly9hc3Byby5ydS9uZXdzL3Z6bG9teS1zYXl0b3YtYXNwcm8vIn0seyJjb2RlIjoiYXNwcm8uYWxsY29ycDMiLCJuYW1lIjoi0JDRgdC/0YDQvjog0JrQvtGA0L/QvtGA0LDRgtC40LLQvdGL0Lkg0YHQsNC50YIgMy4wIiwiZml4ZWQiOiIxLjIuMTEiLCJ2ZXJzaW9uX3JhdyI6ItC00L4gMS4yLjExIiwicHVibGlzaGVkIjoiMDYuMDIuMjAyNSIsInNyY19saW5rIjoiaHR0cHM6Ly9tYXJrZXRwbGFjZS4xYy1iaXRyaXgucnUvc29sdXRpb25zL2FzcHJvLmFsbGNvcnAzLyIsImZpeF9saW5rIjoiaHR0cHM6Ly9hc3Byby5ydS9uZXdzL3Z6bG9teS1zYXl0b3YtYXNwcm8vIn0seyJjb2RlIjoiYXNwcm8uYWxsY29ycDNkaWdpdGFsIiwibmFtZSI6ItCQ0YHQv9GA0L46IERpZ2l0YWwgMi4wIiwiZml4ZWQiOiIxLjAuMTciLCJ2ZXJzaW9uX3JhdyI6ItC00L4gMS4wLjE3IiwicHVibGlzaGVkIjoiMDYuMDIuMjAyNSIsInNyY19saW5rIjoiaHR0cHM6Ly9tYXJrZXRwbGFjZS4xYy1iaXRyaXgucnUvc29sdXRpb25zL2FzcHJvLmFsbGNvcnAzZGlnaXRhbC8iLCJmaXhfbGluayI6Imh0dHBzOi8vYXNwcm8ucnUvbmV3cy92emxvbXktc2F5dG92LWFzcHJvLyJ9LHsiY29kZSI6ImFzcHJvLmFsbGNvcnAzbGFuZHNjYXBlIiwibmFtZSI6ItCQ0YHQv9GA0L46INCb0LDQvdC00YjQsNGE0YIgMi4wIiwiZml4ZWQiOiIxLjAuNiIsInZlcnNpb25fcmF3Ijoi0LTQviAxLjAuNiIsInB1Ymxpc2hlZCI6IjA2LjAyLjIwMjUiLCJzcmNfbGluayI6Imh0dHBzOi8vbWFya2V0cGxhY2UuMWMtYml0cml4LnJ1L3NvbHV0aW9ucy9hc3Byby5hbGxjb3JwM2xhbmRzY2FwZS8iLCJmaXhfbGluayI6Imh0dHBzOi8vYXNwcm8ucnUvbmV3cy92emxvbXktc2F5dG92LWFzcHJvLyJ9LHsiY29kZSI6ImFzcHJvLmFsbGNvcnAzbWVkYyIsIm5hbWUiOiLQkNGB0L/RgNC+OiDQnNC10LTQuNGG0LjQvdGB0LrQuNC5INGG0LXQvdGC0YAgMy4wIiwiZml4ZWQiOiIxLjAuMjEiLCJ2ZXJzaW9uX3JhdyI6ItC00L4gMS4wLjIxIiwicHVibGlzaGVkIjoiMDYuMDIuMjAyNSIsInNyY19saW5rIjoiaHR0cHM6Ly9tYXJrZXRwbGFjZS4xYy1iaXRyaXgucnUvc29sdXRpb25zL2FzcHJvLmFsbGNvcnAzbWVkYy8iLCJmaXhfbGluayI6Imh0dHBzOi8vYXNwcm8ucnUvbmV3cy92emxvbXktc2F5dG92LWFzcHJvLyJ9LHsiY29kZSI6ImFzcHJvLmFsbGNvcnAzbWV0YWwiLCJuYW1lIjoi0JDRgdC/0YDQvjog0JzQtdGC0LDQu9C7IiwiZml4ZWQiOiIxLjAuMjEiLCJ2ZXJzaW9uX3JhdyI6ItC00L4gMS4wLjIxIiwicHVibGlzaGVkIjoiMDYuMDIuMjAyNSIsInNyY19saW5rIjoiaHR0cHM6Ly9tYXJrZXRwbGFjZS4xYy1iaXRyaXgucnUvc29sdXRpb25zL2FzcHJvLmFsbGNvcnAzbWV0YWwvIiwiZml4X2xpbmsiOiJodHRwczovL2FzcHJvLnJ1L25ld3Mvdnpsb215LXNheXRvdi1hc3Byby8ifSx7ImNvZGUiOiJhc3Byby5hbGxjb3JwM3Jlc29ydCIsIm5hbWUiOiLQkNGB0L/RgNC+OiDQmtGD0YDQvtGA0YIgMi4wIiwiZml4ZWQiOiIxLjAuMTAiLCJ2ZXJzaW9uX3JhdyI6ItC00L4gMS4wLjEwIiwicHVibGlzaGVkIjoiMDYuMDIuMjAyNSIsInNyY19saW5rIjoiaHR0cHM6Ly9tYXJrZXRwbGFjZS4xYy1iaXRyaXgucnUvc29sdXRpb25zL2FzcHJvLmFsbGNvcnAzcmVzb3J0LyIsImZpeF9saW5rIjoiaHR0cHM6Ly9hc3Byby5ydS9uZXdzL3Z6bG9teS1zYXl0b3YtYXNwcm8vIn0seyJjb2RlIjoiYXNwcm8uYWxsY29ycDNzdHJveSIsIm5hbWUiOiLQkNGB0L/RgNC+OiDQodGC0YDQvtC50LrQsCAyLjAiLCJmaXhlZCI6IjEuMC4xNiIsInZlcnNpb25fcmF3Ijoi0LTQviAxLjAuMTYiLCJwdWJsaXNoZWQiOiIwNi4wMi4yMDI1Iiwic3JjX2xpbmsiOiJodHRwczovL21hcmtldHBsYWNlLjFjLWJpdHJpeC5ydS9zb2x1dGlvbnMvYXNwcm8uYWxsY29ycDNzdHJveS8iLCJmaXhfbGluayI6Imh0dHBzOi8vYXNwcm8ucnUvbmV3cy92emxvbXktc2F5dG92LWFzcHJvLyJ9LHsiY29kZSI6ImFzcHJvLmRpZ2l0YWwiLCJuYW1lIjoi0JDRgdC/0YDQvjogRGlnaXRhbCIsInBhcnRuZXIiOiLQkNGB0L/RgNC+IiwiZml4ZWQiOm51bGwsIndpdGhkcmF3biI6dHJ1ZSwidmVyc2lvbl9yYXciOiLRgdC90Y/RgtC+INGBINC/0YPQsdC70LjQutCw0YbQuNC4IiwicHVibGlzaGVkIjoiMDYuMDIuMjAyNSIsInNyY19saW5rIjoiaHR0cHM6Ly9tYXJrZXRwbGFjZS4xYy1iaXRyaXgucnUvc29sdXRpb25zL2FzcHJvLmRpZ2l0YWwvIiwiZml4X2xpbmsiOiJodHRwczovL2FzcHJvLnJ1L25ld3Mvdnpsb215LXNheXRvdi1hc3Byby8ifSx7ImNvZGUiOiJhc3Byby5pc2hvcCIsIm5hbWUiOiLQkNGB0L/RgNC+OiDQmNC90YLQtdGA0L3QtdGCLdC80LDQs9Cw0LfQuNC9IiwicGFydG5lciI6ItCQ0YHQv9GA0L4iLCJmaXhlZCI6bnVsbCwid2l0aGRyYXduIjp0cnVlLCJ2ZXJzaW9uX3JhdyI6ItGB0L3Rj9GC0L4g0YEg0L/Rg9Cx0LvQuNC60LDRhtC40LgiLCJwdWJsaXNoZWQiOiIwNi4wMi4yMDI1Iiwic3JjX2xpbmsiOiJodHRwczovL21hcmtldHBsYWNlLjFjLWJpdHJpeC5ydS9zb2x1dGlvbnMvYXNwcm8uaXNob3AvIiwiZml4X2xpbmsiOiJodHRwczovL2FzcHJvLnJ1L25ld3Mvdnpsb215LXNheXRvdi1hc3Byby8ifSx7ImNvZGUiOiJhc3Byby5rc2hvcCIsIm5hbWUiOiLQkNGB0L/RgNC+OiDQmtGA0YPRgtC+0Lkg0YjQvtC/IiwicGFydG5lciI6ItCQ0YHQv9GA0L4iLCJmaXhlZCI6bnVsbCwid2l0aGRyYXduIjp0cnVlLCJ2ZXJzaW9uX3JhdyI6ItGB0L3Rj9GC0L4g0YEg0L/Rg9Cx0LvQuNC60LDRhtC40LgiLCJwdWJsaXNoZWQiOiIwNi4wMi4yMDI1Iiwic3JjX2xpbmsiOiJodHRwczovL21hcmtldHBsYWNlLjFjLWJpdHJpeC5ydS9zb2x1dGlvbnMvYXNwcm8ua3Nob3AvIiwiZml4X2xpbmsiOiJodHRwczovL2FzcHJvLnJ1L25ld3Mvdnpsb215LXNheXRvdi1hc3Byby8ifSx7ImNvZGUiOiJhc3Byby5sYW5kc2NhcGUiLCJuYW1lIjoi0JDRgdC/0YDQvjog0JvQsNC90LTRiNCw0YTRgiIsInBhcnRuZXIiOiLQkNGB0L/RgNC+IiwiZml4ZWQiOm51bGwsIndpdGhkcmF3biI6dHJ1ZSwidmVyc2lvbl9yYXciOiLRgdC90Y/RgtC+INGBINC/0YPQsdC70LjQutCw0YbQuNC4IiwicHVibGlzaGVkIjoiMDYuMDIuMjAyNSIsInNyY19saW5rIjoiaHR0cHM6Ly9tYXJrZXRwbGFjZS4xYy1iaXRyaXgucnUvc29sdXRpb25zL2FzcHJvLmxhbmRzY2FwZS8iLCJmaXhfbGluayI6Imh0dHBzOi8vYXNwcm8ucnUvbmV3cy92emxvbXktc2F5dG92LWFzcHJvLyJ9LHsiY29kZSI6ImFzcHJvLmxpdGUiLCJuYW1lIjoi0JDRgdC/0YDQvjog0JvQsNC50YLRiNC+0L8iLCJmaXhlZCI6IjEuMS42IiwidmVyc2lvbl9yYXciOiLQtNC+IDEuMS42IiwicHVibGlzaGVkIjoiMDYuMDIuMjAyNSIsInNyY19saW5rIjoiaHR0cHM6Ly9tYXJrZXRwbGFjZS4xYy1iaXRyaXgucnUvc29sdXRpb25zL2FzcHJvLmxpdGUvIiwiZml4X2xpbmsiOiJodHRwczovL2FzcHJvLnJ1L25ld3Mvdnpsb215LXNheXRvdi1hc3Byby8ifSx7ImNvZGUiOiJhc3Byby5tYXgiLCJuYW1lIjoi0JDRgdC/0YDQvjog0JzQsNC60YHQuNC80YPQvCIsImZpeGVkIjoiMi4xLjkiLCJ2ZXJzaW9uX3JhdyI6ItC00L4gMi4xLjkiLCJwdWJsaXNoZWQiOiIwNi4wMi4yMDI1Iiwic3JjX2xpbmsiOiJodHRwczovL21hcmtldHBsYWNlLjFjLWJpdHJpeC5ydS9zb2x1dGlvbnMvYXNwcm8ubWF4LyIsImZpeF9saW5rIjoiaHR0cHM6Ly9hc3Byby5ydS9uZXdzL3Z6bG9teS1zYXl0b3YtYXNwcm8vIn0seyJjb2RlIjoiYXNwcm8ubWVkYzIiLCJuYW1lIjoi0JDRgdC/0YDQvjog0JzQtdC00LjRhtC40L3RgdC60LjQuSDRhtC10L3RgtGAIDIuMCIsInBhcnRuZXIiOiLQkNGB0L/RgNC+IiwiZml4ZWQiOm51bGwsIndpdGhkcmF3biI6dHJ1ZSwidmVyc2lvbl9yYXciOiLRgdC90Y/RgtC+INGBINC/0YPQsdC70LjQutCw0YbQuNC4IiwicHVibGlzaGVkIjoiMDYuMDIuMjAyNSIsInNyY19saW5rIjoiaHR0cHM6Ly9tYXJrZXRwbGFjZS4xYy1iaXRyaXgucnUvc29sdXRpb25zL2FzcHJvLm1lZGMyLyIsImZpeF9saW5rIjoiaHR0cHM6Ly9hc3Byby5ydS9uZXdzL3Z6bG9teS1zYXl0b3YtYXNwcm8vIn0seyJjb2RlIjoiYXNwcm8ubXNob3AiLCJuYW1lIjoi0JDRgdC/0YDQvjog0JzQsNGA0LrQtdGCIiwiZml4ZWQiOiIxLjguNiIsInZlcnNpb25fcmF3Ijoi0LTQviAxLjguNiIsInB1Ymxpc2hlZCI6IjA2LjAyLjIwMjUiLCJzcmNfbGluayI6Imh0dHBzOi8vbWFya2V0cGxhY2UuMWMtYml0cml4LnJ1L3NvbHV0aW9ucy9hc3Byby5tc2hvcC8iLCJmaXhfbGluayI6Imh0dHBzOi8vYXNwcm8ucnUvbmV3cy92emxvbXktc2F5dG92LWFzcHJvLyJ9LHsiY29kZSI6ImFzcHJvLm5leHQiLCJuYW1lIjoi0JDRgdC/0YDQvjogTmV4dCIsImZpeGVkIjoiMS45LjkiLCJ2ZXJzaW9uX3JhdyI6ItC00L4gMS45LjkiLCJwdWJsaXNoZWQiOiIwNi4wMi4yMDI1Iiwic3JjX2xpbmsiOiJodHRwczovL21hcmtldHBsYWNlLjFjLWJpdHJpeC5ydS9zb2x1dGlvbnMvYXNwcm8ubmV4dC8iLCJmaXhfbGluayI6Imh0dHBzOi8vYXNwcm8ucnUvbmV3cy92emxvbXktc2F5dG92LWFzcHJvLyJ9LHsiY29kZSI6ImFzcHJvLm9wdGltdXMiLCJuYW1lIjoi0JDRgdC/0YDQvjog0J7Qv9GC0LjQvNGD0YEiLCJmaXhlZCI6IjEuNy44IiwidmVyc2lvbl9yYXciOiLQtNC+IDEuNy44IiwicHVibGlzaGVkIjoiMDYuMDIuMjAyNSIsInNyY19saW5rIjoiaHR0cHM6Ly9tYXJrZXRwbGFjZS4xYy1iaXRyaXgucnUvc29sdXRpb25zL2FzcHJvLm9wdGltdXMvIiwiZml4X2xpbmsiOiJodHRwczovL2FzcHJvLnJ1L25ld3Mvdnpsb215LXNheXRvdi1hc3Byby8ifSx7ImNvZGUiOiJhc3Byby5wcmlvcml0eSIsIm5hbWUiOiLQkNGB0L/RgNC+OiDQn9GA0LjQvtGA0LjRgtC4IiwicGFydG5lciI6ItCQ0YHQv9GA0L4iLCJmaXhlZCI6bnVsbCwid2l0aGRyYXduIjp0cnVlLCJ2ZXJzaW9uX3JhdyI6ItGB0L3Rj9GC0L4g0YEg0L/Rg9Cx0LvQuNC60LDRhtC40LgiLCJwdWJsaXNoZWQiOiIwNi4wMi4yMDI1Iiwic3JjX2xpbmsiOiJodHRwczovL21hcmtldHBsYWNlLjFjLWJpdHJpeC5ydS9zb2x1dGlvbnMvYXNwcm8ucHJpb3JpdHkvIiwiZml4X2xpbmsiOiJodHRwczovL2FzcHJvLnJ1L25ld3Mvdnpsb215LXNheXRvdi1hc3Byby8ifSx7ImNvZGUiOiJhc3Byby5yZXNvcnQiLCJuYW1lIjoi0JDRgdC/0YDQvjog0JrRg9GA0L7RgNGCIiwicGFydG5lciI6ItCQ0YHQv9GA0L4iLCJmaXhlZCI6bnVsbCwid2l0aGRyYXduIjp0cnVlLCJ2ZXJzaW9uX3JhdyI6ItGB0L3Rj9GC0L4g0YEg0L/Rg9Cx0LvQuNC60LDRhtC40LgiLCJwdWJsaXNoZWQiOiIwNi4wMi4yMDI1Iiwic3JjX2xpbmsiOiJodHRwczovL21hcmtldHBsYWNlLjFjLWJpdHJpeC5ydS9zb2x1dGlvbnMvYXNwcm8ucmVzb3J0LyIsImZpeF9saW5rIjoiaHR0cHM6Ly9hc3Byby5ydS9uZXdzL3Z6bG9teS1zYXl0b3YtYXNwcm8vIn0seyJjb2RlIjoiYXNwcm8uc3Ryb3kiLCJuYW1lIjoi0JDRgdC/0YDQvjog0KHRgtGA0L7QudC60LAiLCJwYXJ0bmVyIjoi0JDRgdC/0YDQviIsImZpeGVkIjpudWxsLCJ3aXRoZHJhd24iOnRydWUsInZlcnNpb25fcmF3Ijoi0YHQvdGP0YLQviDRgSDQv9GD0LHQu9C40LrQsNGG0LjQuCIsInB1Ymxpc2hlZCI6IjA2LjAyLjIwMjUiLCJzcmNfbGluayI6Imh0dHBzOi8vbWFya2V0cGxhY2UuMWMtYml0cml4LnJ1L3NvbHV0aW9ucy9hc3Byby5zdHJveS8iLCJmaXhfbGluayI6Imh0dHBzOi8vYXNwcm8ucnUvbmV3cy92emxvbXktc2F5dG92LWFzcHJvLyJ9LHsiY29kZSI6ImFzcHJvLnRpcmVzIiwibmFtZSI6ItCQ0YHQv9GA0L46INCo0LjQvdGLINC4INC00LjRgdC60LgiLCJwYXJ0bmVyIjoi0JDRgdC/0YDQviIsImZpeGVkIjpudWxsLCJ3aXRoZHJhd24iOnRydWUsInZlcnNpb25fcmF3Ijoi0YHQvdGP0YLQviDRgSDQv9GD0LHQu9C40LrQsNGG0LjQuCIsInB1Ymxpc2hlZCI6IjA2LjAyLjIwMjUiLCJzcmNfbGluayI6Imh0dHBzOi8vbWFya2V0cGxhY2UuMWMtYml0cml4LnJ1L3NvbHV0aW9ucy9hc3Byby50aXJlcy8iLCJmaXhfbGluayI6Imh0dHBzOi8vYXNwcm8ucnUvbmV3cy92emxvbXktc2F5dG92LWFzcHJvLyJ9LHsiY29kZSI6ImFzcHJvLnRpcmVzMiIsIm5hbWUiOiLQkNGB0L/RgNC+OiDQqNC40L3RiyDQuCDQtNC40YHQutC4IDIuMCIsImZpeGVkIjoiMS4xLjE0IiwidmVyc2lvbl9yYXciOiLQtNC+IDEuMS4xNCIsInB1Ymxpc2hlZCI6IjA2LjAyLjIwMjUiLCJzcmNfbGluayI6Imh0dHBzOi8vbWFya2V0cGxhY2UuMWMtYml0cml4LnJ1L3NvbHV0aW9ucy9hc3Byby50aXJlczIvIiwiZml4X2xpbmsiOiJodHRwczovL2FzcHJvLnJ1L25ld3Mvdnpsb215LXNheXRvdi1hc3Byby8ifSx7ImNvZGUiOiJlc29sLmFsbGltcG9ydGV4cG9ydCIsIm5hbWUiOiLQnNC90L7Qs9C+0YTRg9C90LrRhtC40L7QvdCw0LvRjNC90YvQuSDRjdC60YHQv9C+0YDRgi/QuNC80L/QvtGA0YIg0LIgRXhjZWwiLCJmaXhlZCI6IjAuNi40IiwidmVyc2lvbl9yYXciOiLQtNC+IDAuNi40IiwicHVibGlzaGVkIjoiMzAuMTIuMjAyNSIsInNyY19saW5rIjoiaHR0cHM6Ly9tYXJrZXRwbGFjZS4xYy1iaXRyaXgucnUvc29sdXRpb25zL2Vzb2wuYWxsaW1wb3J0ZXhwb3J0LyIsImZpeF9saW5rIjoiaHR0cHM6Ly9lc29sdXRpb25zLnN1L2Jlem9wYXN0bm9zdC1zYXl0b3YvZG9yYWJvdGtpLWJlem9wYXNub3N0aS1tb2R1bGV5LWltcG9ydGEvIn0seyJjb2RlIjoiZXNvbC5pbXBvcnRleHBvcnRleGNlbCIsIm5hbWUiOiLQrdC60YHQv9C+0YDRgi/QmNC80L/QvtGA0YIg0YLQvtCy0LDRgNC+0LIg0LIgRXhjZWwiLCJmaXhlZCI6IjMuMi42IiwidmVyc2lvbl9yYXciOiLQtNC+IDMuMi42IiwicHVibGlzaGVkIjoiMzAuMTIuMjAyNSIsInNyY19saW5rIjoiaHR0cHM6Ly9tYXJrZXRwbGFjZS4xYy1iaXRyaXgucnUvc29sdXRpb25zL2Vzb2wuaW1wb3J0ZXhwb3J0ZXhjZWwvIiwiZml4X2xpbmsiOiJodHRwczovL2Vzb2x1dGlvbnMuc3UvYmV6b3Bhc3Rub3N0LXNheXRvdi9kb3JhYm90a2ktYmV6b3Bhc25vc3RpLW1vZHVsZXktaW1wb3J0YS8ifSx7ImNvZGUiOiJlc29sLmltcG9ydHhtbCIsIm5hbWUiOiLQmNC80L/QvtGA0YIg0LjQtyBYTUwsIFlNTCwgSlNPTi4g0JfQsNCz0YDRg9C30LrQsCDQutCw0YLQsNC70L7Qs9CwINGC0L7QstCw0YDQvtCyIDHQoS3QkdC40YLRgNC40LrRgSIsImZpeGVkIjoiMS4xLjciLCJ2ZXJzaW9uX3JhdyI6ItC00L4gMS4xLjciLCJwdWJsaXNoZWQiOiIxMy4wMy4yMDI1Iiwic3JjX2xpbmsiOiJodHRwczovL21hcmtldHBsYWNlLjFjLWJpdHJpeC5ydS9zb2x1dGlvbnMvZXNvbC5pbXBvcnR4bWwvIiwiZml4X2xpbmsiOiJodHRwczovL2Vzb2x1dGlvbnMuc3UvYmV6b3Bhc3Rub3N0LXNheXRvdi8ifSx7ImNvZGUiOiJlc29sLm1hc3NlZGl0IiwibmFtZSI6ItCc0LDRgdGB0L7QstCw0Y8g0L7QsdGA0LDQsdC+0YLQutCwINGN0LvQtdC80LXQvdGC0L7QsiDQuNC90YTQvtCx0LvQvtC60LAgKNGC0L7QstCw0YDQvtCyKSIsImZpeGVkIjoiMC43LjgiLCJ2ZXJzaW9uX3JhdyI6ItC00L4gMC43LjgiLCJwdWJsaXNoZWQiOiIxMy4wMy4yMDI1Iiwic3JjX2xpbmsiOiJodHRwczovL21hcmtldHBsYWNlLjFjLWJpdHJpeC5ydS9zb2x1dGlvbnMvZXNvbC5tYXNzZWRpdC8iLCJmaXhfbGluayI6Imh0dHBzOi8vZXNvbHV0aW9ucy5zdS9iZXpvcGFzdG5vc3Qtc2F5dG92LyJ9LHsiY29kZSI6ImludGVjLmNvcmUiLCJuYW1lIjoi0K/QtNGA0L4gLSDQsdCw0LfQvtCy0YvQuSDQvNC+0LTRg9C70Ywg0LTQu9GPINGA0LXRiNC10L3QuNC5IElOVEVDIiwiZml4ZWQiOiIxLjIuMzAiLCJ2ZXJzaW9uX3JhdyI6ItC00L4gMS4yLjMwIiwicHVibGlzaGVkIjoiMzAuMDQuMjAyNiIsInNyY19saW5rIjoiaHR0cHM6Ly9tYXJrZXRwbGFjZS4xYy1iaXRyaXgucnUvc29sdXRpb25zL2ludGVjLmNvcmUvIiwiZml4X2xpbmsiOiJodHRwczovL3NwLmludGVjd2ViLnJ1L2tiL2FydGljbGVzLzM3MTI2NS11eWF6dmltb3N0LXNheXRvdi1rLXZpcnVzYW0tb2Jub3ZsZW5pZS1iZXpvcGFzbm9zdGktZGx5YS1yZXNoZW5peS11bml2ZXJzZS8ifSx7ImNvZGUiOiJpc3ByaW5nLnNkb3N5bmMiLCJuYW1lIjoi0JzQsNCz0LDQt9C40L0g0L/QvtC00LDRgNC60L7QsiBJU3ByaW5nIiwiZml4ZWQiOiIwLjcuMCIsInZlcnNpb25fcmF3Ijoi0LTQviAwLjcuMCIsInB1Ymxpc2hlZCI6IjEwLjExLjIwMjYiLCJzcmNfbGluayI6Imh0dHBzOi8vbWFya2V0cGxhY2UuMWMtYml0cml4LnJ1L3NvbHV0aW9ucy9pc3ByaW5nLnNkb3N5bmMvIiwiZml4X2xpbmsiOiJodHRwczovL2hhYnIuY29tL3J1L2FydGljbGVzLzExMDY5NDQvIn0seyJjb2RlIjoiamNvZGUucGhvdG9jb21wYXJlIiwibmFtZSI6ItCk0L7RgtC+INCU0L4g0Lgg0J/QvtGB0LvQtTog0YHRgNCw0LLQvdC10L3QuNC1INC40LfQvtCx0YDQsNC20LXQvdC40Lkg0LTQvi/Qv9C+0YHQu9C1IiwiZml4ZWQiOiIxLjAuMiIsInZlcnNpb25fcmF3Ijoi0LTQviAxLjAuMiIsInB1Ymxpc2hlZCI6IjA0LjA5LjIwMjYiLCJzcmNfbGluayI6Imh0dHBzOi8vbWFya2V0cGxhY2UuMWMtYml0cml4LnJ1L3NvbHV0aW9ucy9qY29kZS5waG90b2NvbXBhcmUvIiwiZml4X2xpbmsiOiJodHRwczovL2hhYnIuY29tL3J1L25ld3MvMTA3OTI2Ni8ifSx7ImNvZGUiOiJrZGEuZXhwb3J0ZXhjZWwiLCJuYW1lIjoi0K3QutGB0L/QvtGA0YIg0LIgRXhjZWwuINCS0YvQs9GA0YPQt9C60LAg0LrQsNGC0LDQu9C+0LPQsCDRgtC+0LLQsNGA0L7QsiAx0KEt0JHQuNGC0YDQuNC60YEuINCh0L7Qt9C00LDQvdC40LUg0L/RgNCw0LnRgS3Qu9C40YHRgtCwIiwiZml4ZWQiOiIxLjIuMyIsInZlcnNpb25fcmF3Ijoi0LTQviAxLjIuMyIsInB1Ymxpc2hlZCI6IjEzLjAzLjIwMjUiLCJzcmNfbGluayI6Imh0dHBzOi8vbWFya2V0cGxhY2UuMWMtYml0cml4LnJ1L3NvbHV0aW9ucy9rZGEuZXhwb3J0ZXhjZWwvIiwiZml4X2xpbmsiOiJodHRwczovL21heWFraXQucnUvYWJvdXQvbmV3cy9iZXpvcGFjbm9zdC1zYWp0b3YifSx7ImNvZGUiOiJrZGEuaW1wb3J0ZXhjZWwiLCJuYW1lIjoi0JjQvNC/0L7RgNGCINC40LcgRXhjZWwiLCJmaXhlZCI6IjMuMi42IiwidmVyc2lvbl9yYXciOiLQtNC+IDMuMi42IiwicHVibGlzaGVkIjoiMzAuMTIuMjAyNSIsInNyY19saW5rIjoiaHR0cHM6Ly9tYXJrZXRwbGFjZS4xYy1iaXRyaXgucnUvc29sdXRpb25zL2tkYS5pbXBvcnRleGNlbC8iLCJmaXhfbGluayI6Imh0dHBzOi8vZXNvbHV0aW9ucy5zdS9iZXpvcGFzdG5vc3Qtc2F5dG92L2RvcmFib3RraS1iZXpvcGFzbm9zdGktbW9kdWxleS1pbXBvcnRhLyJ9LHsiY29kZSI6ImtvbXRldC5kZWxpdmVyeSIsIm5hbWUiOiLQmtCe0JzQotCV0KIg0JrQsNGB0YHQsCDQmtGD0YDRjNC10YAiLCJmaXhlZCI6IjIuOC4xIiwidmVyc2lvbl9yYXciOiLQtNC+IDIuOC4xIiwicHVibGlzaGVkIjoiMjYuMDguMjAyNiIsInNyY19saW5rIjoiaHR0cHM6Ly9tYXJrZXRwbGFjZS4xYy1iaXRyaXgucnUvc29sdXRpb25zL2tvbXRldC5kZWxpdmVyeS8/dXBkYXRlX3N5cz1ZI3RhYi1hYm91dC1saW5rIiwiZml4X2xpbmsiOiJodHRwczovL2thc3NhLmtvbXRldC5ydS9ibG9nL29ibm92bGVuaXllLWJlem9wYXNub3N0aS1wbGFnaW5hLWtvbXRldC1rYXNzYS1rdXJ5ZXItdi1pcy1iaXRyaWtzIn0seyJjb2RlIjoic2hzLnBhcnNlciIsIm5hbWUiOiLQodC+0YLQsdC40YI6INCf0LDRgNGB0LXRgCDQutC+0L3RgtC10L3RgtCwIOKAkyDRgdCw0LnRgtGLLCBleGNlbCwgeG1sLCB5bWwsIGNzdiwgcnNzIiwiZml4ZWQiOiI1LjEwLjQiLCJ2ZXJzaW9uX3JhdyI6ItC00L4gNS4xMC40IiwicHVibGlzaGVkIjoiMTcuMDMuMjAyNSIsInNyY19saW5rIjoiaHR0cHM6Ly9tYXJrZXRwbGFjZS4xYy1iaXRyaXgucnUvc29sdXRpb25zL3Nocy5wYXJzZXIvIiwiZml4X2xpbmsiOiJodHRwczovL3d3dy5zb3RiaXQucnUvaW5mby9tb2R1bGUvMWMtYml0cml4LXNlY3VyaXR5LXBhdGNoLmh0bWwifSx7ImNvZGUiOiJzb3RiaXQuaHRtbGVkaXRvcmFkZGl0aW9uIiwibmFtZSI6ItCh0L7RgtCx0LjRgjog0JHRi9GB0YLRgNCw0Y8g0LfQsNCz0YDRg9C30LrQsCDQutCw0YDRgtC40L3QvtC6INCyINCy0LjQt9GD0LDQu9GM0L3QvtC8INGA0LXQtNCw0LrRgtC+0YDQtSIsImZpeGVkIjoiMS4xLjAiLCJ2ZXJzaW9uX3JhdyI6ItC00L4gMS4xLjAiLCJwdWJsaXNoZWQiOiIxNy4wMy4yMDI1Iiwic3JjX2xpbmsiOiJodHRwczovL21hcmtldHBsYWNlLjFjLWJpdHJpeC5ydS9zb2x1dGlvbnMvc290Yml0Lmh0bWxlZGl0b3JhZGRpdGlvbi8iLCJmaXhfbGluayI6Imh0dHBzOi8vd3d3LnNvdGJpdC5ydS9pbmZvL21vZHVsZS8xYy1iaXRyaXgtc2VjdXJpdHktcGF0Y2guaHRtbCJ9LHsiY29kZSI6InNvdGJpdC5vcmlnYW1pIiwibmFtZSI6ItCh0L7RgtCx0LjRgjog0J7RgNC40LPQsNC80LgiLCJwYXJ0bmVyIjoi0KHQvtGC0LHQuNGCIiwiZml4ZWQiOm51bGwsIndpdGhkcmF3biI6dHJ1ZSwidmVyc2lvbl9yYXciOiLRgdC90Y/RgtC+INGBINC/0YPQsdC70LjQutCw0YbQuNC4IiwicHVibGlzaGVkIjoiMTcuMDMuMjAyNSIsInNyY19saW5rIjoiaHR0cHM6Ly9tYXJrZXRwbGFjZS4xYy1iaXRyaXgucnUvc29sdXRpb25zL3NvdGJpdC5vcmlnYW1pLyIsImZpeF9saW5rIjoiaHR0cHM6Ly93d3cuc290Yml0LnJ1L2luZm8vbW9kdWxlLzFjLWJpdHJpeC1zZWN1cml0eS1wYXRjaC5odG1sIn0seyJjb2RlIjoic290Yml0LnJlZ2lvbnMiLCJuYW1lIjoi0KHQvtGC0LHQuNGCOiDQnNGD0LvRjNGC0LjRgNC10LPQuNC+0L3QsNC70YzQvdC+0YHRgtGMIiwiZml4ZWQiOiIxLjguNSIsInZlcnNpb25fcmF3Ijoi0LTQviAxLjguNSIsInB1Ymxpc2hlZCI6IjE3LjAzLjIwMjUiLCJzcmNfbGluayI6Imh0dHBzOi8vbWFya2V0cGxhY2UuMWMtYml0cml4LnJ1L3NvbHV0aW9ucy9zb3RiaXQucmVnaW9ucy8iLCJmaXhfbGluayI6Imh0dHBzOi8vd3d3LnNvdGJpdC5ydS9pbmZvL21vZHVsZS8xYy1iaXRyaXgtc2VjdXJpdHktcGF0Y2guaHRtbCJ9LHsiY29kZSI6InNvdGJpdC5yZXZpZXdzIiwibmFtZSI6ItCh0L7RgtCx0LjRgjog0KDQsNGB0YjQuNGA0LXQvdC90YvQtSDQvtGC0LfRi9Cy0YsiLCJmaXhlZCI6IjIuMC4wIiwidmVyc2lvbl9yYXciOiLQtNC+IDIuMC4wIiwicHVibGlzaGVkIjoiMTcuMDMuMjAyNSIsInNyY19saW5rIjoiaHR0cHM6Ly9tYXJrZXRwbGFjZS4xYy1iaXRyaXgucnUvc29sdXRpb25zL3NvdGJpdC5yZXZpZXdzLyIsImZpeF9saW5rIjoiaHR0cHM6Ly93d3cuc290Yml0LnJ1L2luZm8vbW9kdWxlLzFjLWJpdHJpeC1zZWN1cml0eS1wYXRjaC5odG1sIn1dfQ==';
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
