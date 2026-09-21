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

$REGISTRY_B64 = 'eyJzb3VyY2UiOiJodHRwczovL3d3dy4xYy1iaXRyaXgucnUvdnVsX2Rldi9yc3MvIiwidmVyc2lvbiI6MywiZ2VuZXJhdGVkIjoiMjAyNi0wOS0xMCIsIm5vdGUiOiJBdXRvLWdlbmVyYXRlZCBmcm9tIHRoZSAxQy1CaXRyaXggdnVsX2RldiByZWdpc3RyeSBieSBzY3JpcHRzL3VwZGF0ZV92dWxuX3JlZ2lzdHJ5LnB5LCBwbHVzIGN1cmF0ZWQgd2l0aGRyYXduL3VucHVibGlzaGVkIG1vZHVsZXMgZnJvbSBiaXRyaXhfdnVsbl9tb2R1bGVzX21hbnVhbC5qc29uLiBBIG1vZHVsZSBpcyB2dWxuZXJhYmxlIHdoZW4gaXRzIGluc3RhbGxlZCB2ZXJzaW9uIGlzIDwgXCJmaXhlZFwiLCBvciB1bmNvbmRpdGlvbmFsbHkgd2hlbiBcIndpdGhkcmF3blwiOiB0cnVlIChyZW1vdmVkIGZyb20gdGhlIG1hcmtldHBsYWNlIC0tIG5vIGZpeDsgcmVtb3ZlIGl0KS4iLCJtb2R1bGVzIjpbeyJjb2RlIjoiYWNyaXQuYm9udXMiLCJuYW1lIjoi0KHQuNGB0YLQtdC80LAg0LHQvtC90YPRgdC+0LIuINCf0YDQvtCz0YDQsNC80LzRiyDQu9C+0Y/Qu9GM0L3QvtGB0YLQuCIsImZpeGVkIjoiMy40LjkiLCJ2ZXJzaW9uX3JhdyI6ItC00L4gMy40LjkiLCJwdWJsaXNoZWQiOiIxMC4wOS4yMDI1Iiwic3JjX2xpbmsiOiJodHRwczovL21hcmtldHBsYWNlLjFjLWJpdHJpeC5ydS9zb2x1dGlvbnMvYWNyaXQuYm9udXMvIiwiZml4X2xpbmsiOiJodHRwczovL3QubWUvY3liZXJva19uZXdzLzE0MCJ9LHsiY29kZSI6ImFjcml0LmltcG9ydCIsIm5hbWUiOiLQo9C90LjQstC10YDRgdCw0LvRjNC90YvQuSDQuNC80L/QvtGA0YIiLCJmaXhlZCI6IjEuNzkuMCIsInZlcnNpb25fcmF3Ijoi0LTQviAxLjc5LjAiLCJwdWJsaXNoZWQiOiIyOS4wNi4yMDI2Iiwic3JjX2xpbmsiOiJodHRwczovL21hcmtldHBsYWNlLjFjLWJpdHJpeC5ydS9zb2x1dGlvbnMvYWNyaXQuaW1wb3J0LyIsImZpeF9saW5rIjoiaHR0cHM6Ly93d3cuYWNyaXQtc3R1ZGlvLnJ1L3RlY2huaWNhbC1zdXBwb3J0L25hc3Ryb3lrYS1tb2R1bHlhLXVuaXZlcnNhbG55eS1pbXBvcnQvdXN0cmFuZW5ueWUtdXlhenZpbW9zdGktdi12ZXJzaWktdjEtNzktMC8ifSx7ImNvZGUiOiJhc3Byby5hbGxjb3JwIiwibmFtZSI6ItCQ0YHQv9GA0L46INCa0L7RgNC/0L7RgNCw0YLQuNCy0L3Ri9C5INGB0LDQudGCIiwiZml4ZWQiOiIxLjEuMTciLCJ2ZXJzaW9uX3JhdyI6ItC00L4gMS4xLjE3IiwicHVibGlzaGVkIjoiMDYuMDIuMjAyNSIsInNyY19saW5rIjoiaHR0cHM6Ly9tYXJrZXRwbGFjZS4xYy1iaXRyaXgucnUvc29sdXRpb25zL2FzcHJvLmFsbGNvcnAvIiwiZml4X2xpbmsiOiJodHRwczovL2FzcHJvLnJ1L25ld3Mvdnpsb215LXNheXRvdi1hc3Byby8ifSx7ImNvZGUiOiJhc3Byby5hbGxjb3JwMiIsIm5hbWUiOiLQkNGB0L/RgNC+OiDQmtC+0YDQv9C+0YDQsNGC0LjQstC90YvQuSDRgdCw0LnRgiAyLjAiLCJmaXhlZCI6IjEuMi4yNSIsInZlcnNpb25fcmF3Ijoi0LTQviAxLjIuMjUiLCJwdWJsaXNoZWQiOiIwNi4wMi4yMDI1Iiwic3JjX2xpbmsiOiJodHRwczovL21hcmtldHBsYWNlLjFjLWJpdHJpeC5ydS9zb2x1dGlvbnMvYXNwcm8uYWxsY29ycDIvIiwiZml4X2xpbmsiOiJodHRwczovL2FzcHJvLnJ1L25ld3Mvdnpsb215LXNheXRvdi1hc3Byby8ifSx7ImNvZGUiOiJhc3Byby5hbGxjb3JwMyIsIm5hbWUiOiLQkNGB0L/RgNC+OiDQmtC+0YDQv9C+0YDQsNGC0LjQstC90YvQuSDRgdCw0LnRgiAzLjAiLCJmaXhlZCI6IjEuMi4xMSIsInZlcnNpb25fcmF3Ijoi0LTQviAxLjIuMTEiLCJwdWJsaXNoZWQiOiIwNi4wMi4yMDI1Iiwic3JjX2xpbmsiOiJodHRwczovL21hcmtldHBsYWNlLjFjLWJpdHJpeC5ydS9zb2x1dGlvbnMvYXNwcm8uYWxsY29ycDMvIiwiZml4X2xpbmsiOiJodHRwczovL2FzcHJvLnJ1L25ld3Mvdnpsb215LXNheXRvdi1hc3Byby8ifSx7ImNvZGUiOiJhc3Byby5hbGxjb3JwM2RpZ2l0YWwiLCJuYW1lIjoi0JDRgdC/0YDQvjogRGlnaXRhbCAyLjAiLCJmaXhlZCI6IjEuMC4xNyIsInZlcnNpb25fcmF3Ijoi0LTQviAxLjAuMTciLCJwdWJsaXNoZWQiOiIwNi4wMi4yMDI1Iiwic3JjX2xpbmsiOiJodHRwczovL21hcmtldHBsYWNlLjFjLWJpdHJpeC5ydS9zb2x1dGlvbnMvYXNwcm8uYWxsY29ycDNkaWdpdGFsLyIsImZpeF9saW5rIjoiaHR0cHM6Ly9hc3Byby5ydS9uZXdzL3Z6bG9teS1zYXl0b3YtYXNwcm8vIn0seyJjb2RlIjoiYXNwcm8uYWxsY29ycDNsYW5kc2NhcGUiLCJuYW1lIjoi0JDRgdC/0YDQvjog0JvQsNC90LTRiNCw0YTRgiAyLjAiLCJmaXhlZCI6IjEuMC42IiwidmVyc2lvbl9yYXciOiLQtNC+IDEuMC42IiwicHVibGlzaGVkIjoiMDYuMDIuMjAyNSIsInNyY19saW5rIjoiaHR0cHM6Ly9tYXJrZXRwbGFjZS4xYy1iaXRyaXgucnUvc29sdXRpb25zL2FzcHJvLmFsbGNvcnAzbGFuZHNjYXBlLyIsImZpeF9saW5rIjoiaHR0cHM6Ly9hc3Byby5ydS9uZXdzL3Z6bG9teS1zYXl0b3YtYXNwcm8vIn0seyJjb2RlIjoiYXNwcm8uYWxsY29ycDNtZWRjIiwibmFtZSI6ItCQ0YHQv9GA0L46INCc0LXQtNC40YbQuNC90YHQutC40Lkg0YbQtdC90YLRgCAzLjAiLCJmaXhlZCI6IjEuMC4yMSIsInZlcnNpb25fcmF3Ijoi0LTQviAxLjAuMjEiLCJwdWJsaXNoZWQiOiIwNi4wMi4yMDI1Iiwic3JjX2xpbmsiOiJodHRwczovL21hcmtldHBsYWNlLjFjLWJpdHJpeC5ydS9zb2x1dGlvbnMvYXNwcm8uYWxsY29ycDNtZWRjLyIsImZpeF9saW5rIjoiaHR0cHM6Ly9hc3Byby5ydS9uZXdzL3Z6bG9teS1zYXl0b3YtYXNwcm8vIn0seyJjb2RlIjoiYXNwcm8uYWxsY29ycDNtZXRhbCIsIm5hbWUiOiLQkNGB0L/RgNC+OiDQnNC10YLQsNC70LsiLCJmaXhlZCI6IjEuMC4yMSIsInZlcnNpb25fcmF3Ijoi0LTQviAxLjAuMjEiLCJwdWJsaXNoZWQiOiIwNi4wMi4yMDI1Iiwic3JjX2xpbmsiOiJodHRwczovL21hcmtldHBsYWNlLjFjLWJpdHJpeC5ydS9zb2x1dGlvbnMvYXNwcm8uYWxsY29ycDNtZXRhbC8iLCJmaXhfbGluayI6Imh0dHBzOi8vYXNwcm8ucnUvbmV3cy92emxvbXktc2F5dG92LWFzcHJvLyJ9LHsiY29kZSI6ImFzcHJvLmFsbGNvcnAzcmVzb3J0IiwibmFtZSI6ItCQ0YHQv9GA0L46INCa0YPRgNC+0YDRgiAyLjAiLCJmaXhlZCI6IjEuMC4xMCIsInZlcnNpb25fcmF3Ijoi0LTQviAxLjAuMTAiLCJwdWJsaXNoZWQiOiIwNi4wMi4yMDI1Iiwic3JjX2xpbmsiOiJodHRwczovL21hcmtldHBsYWNlLjFjLWJpdHJpeC5ydS9zb2x1dGlvbnMvYXNwcm8uYWxsY29ycDNyZXNvcnQvIiwiZml4X2xpbmsiOiJodHRwczovL2FzcHJvLnJ1L25ld3Mvdnpsb215LXNheXRvdi1hc3Byby8ifSx7ImNvZGUiOiJhc3Byby5hbGxjb3JwM3N0cm95IiwibmFtZSI6ItCQ0YHQv9GA0L46INCh0YLRgNC+0LnQutCwIDIuMCIsImZpeGVkIjoiMS4wLjE2IiwidmVyc2lvbl9yYXciOiLQtNC+IDEuMC4xNiIsInB1Ymxpc2hlZCI6IjA2LjAyLjIwMjUiLCJzcmNfbGluayI6Imh0dHBzOi8vbWFya2V0cGxhY2UuMWMtYml0cml4LnJ1L3NvbHV0aW9ucy9hc3Byby5hbGxjb3JwM3N0cm95LyIsImZpeF9saW5rIjoiaHR0cHM6Ly9hc3Byby5ydS9uZXdzL3Z6bG9teS1zYXl0b3YtYXNwcm8vIn0seyJjb2RlIjoiYXNwcm8uZGlnaXRhbCIsIm5hbWUiOiLQkNGB0L/RgNC+OiBEaWdpdGFsIiwicGFydG5lciI6ItCQ0YHQv9GA0L4iLCJmaXhlZCI6bnVsbCwid2l0aGRyYXduIjp0cnVlLCJ2ZXJzaW9uX3JhdyI6ItGB0L3Rj9GC0L4g0YEg0L/Rg9Cx0LvQuNC60LDRhtC40LgiLCJwdWJsaXNoZWQiOiIwNi4wMi4yMDI1Iiwic3JjX2xpbmsiOiJodHRwczovL21hcmtldHBsYWNlLjFjLWJpdHJpeC5ydS9zb2x1dGlvbnMvYXNwcm8uZGlnaXRhbC8iLCJmaXhfbGluayI6Imh0dHBzOi8vYXNwcm8ucnUvbmV3cy92emxvbXktc2F5dG92LWFzcHJvLyJ9LHsiY29kZSI6ImFzcHJvLmlzaG9wIiwibmFtZSI6ItCQ0YHQv9GA0L46INCY0L3RgtC10YDQvdC10YIt0LzQsNCz0LDQt9C40L0iLCJwYXJ0bmVyIjoi0JDRgdC/0YDQviIsImZpeGVkIjpudWxsLCJ3aXRoZHJhd24iOnRydWUsInZlcnNpb25fcmF3Ijoi0YHQvdGP0YLQviDRgSDQv9GD0LHQu9C40LrQsNGG0LjQuCIsInB1Ymxpc2hlZCI6IjA2LjAyLjIwMjUiLCJzcmNfbGluayI6Imh0dHBzOi8vbWFya2V0cGxhY2UuMWMtYml0cml4LnJ1L3NvbHV0aW9ucy9hc3Byby5pc2hvcC8iLCJmaXhfbGluayI6Imh0dHBzOi8vYXNwcm8ucnUvbmV3cy92emxvbXktc2F5dG92LWFzcHJvLyJ9LHsiY29kZSI6ImFzcHJvLmtzaG9wIiwibmFtZSI6ItCQ0YHQv9GA0L46INCa0YDRg9GC0L7QuSDRiNC+0L8iLCJwYXJ0bmVyIjoi0JDRgdC/0YDQviIsImZpeGVkIjpudWxsLCJ3aXRoZHJhd24iOnRydWUsInZlcnNpb25fcmF3Ijoi0YHQvdGP0YLQviDRgSDQv9GD0LHQu9C40LrQsNGG0LjQuCIsInB1Ymxpc2hlZCI6IjA2LjAyLjIwMjUiLCJzcmNfbGluayI6Imh0dHBzOi8vbWFya2V0cGxhY2UuMWMtYml0cml4LnJ1L3NvbHV0aW9ucy9hc3Byby5rc2hvcC8iLCJmaXhfbGluayI6Imh0dHBzOi8vYXNwcm8ucnUvbmV3cy92emxvbXktc2F5dG92LWFzcHJvLyJ9LHsiY29kZSI6ImFzcHJvLmxhbmRzY2FwZSIsIm5hbWUiOiLQkNGB0L/RgNC+OiDQm9Cw0L3QtNGI0LDRhNGCIiwicGFydG5lciI6ItCQ0YHQv9GA0L4iLCJmaXhlZCI6bnVsbCwid2l0aGRyYXduIjp0cnVlLCJ2ZXJzaW9uX3JhdyI6ItGB0L3Rj9GC0L4g0YEg0L/Rg9Cx0LvQuNC60LDRhtC40LgiLCJwdWJsaXNoZWQiOiIwNi4wMi4yMDI1Iiwic3JjX2xpbmsiOiJodHRwczovL21hcmtldHBsYWNlLjFjLWJpdHJpeC5ydS9zb2x1dGlvbnMvYXNwcm8ubGFuZHNjYXBlLyIsImZpeF9saW5rIjoiaHR0cHM6Ly9hc3Byby5ydS9uZXdzL3Z6bG9teS1zYXl0b3YtYXNwcm8vIn0seyJjb2RlIjoiYXNwcm8ubGl0ZSIsIm5hbWUiOiLQkNGB0L/RgNC+OiDQm9Cw0LnRgtGI0L7QvyIsImZpeGVkIjoiMS4xLjYiLCJ2ZXJzaW9uX3JhdyI6ItC00L4gMS4xLjYiLCJwdWJsaXNoZWQiOiIwNi4wMi4yMDI1Iiwic3JjX2xpbmsiOiJodHRwczovL21hcmtldHBsYWNlLjFjLWJpdHJpeC5ydS9zb2x1dGlvbnMvYXNwcm8ubGl0ZS8iLCJmaXhfbGluayI6Imh0dHBzOi8vYXNwcm8ucnUvbmV3cy92emxvbXktc2F5dG92LWFzcHJvLyJ9LHsiY29kZSI6ImFzcHJvLm1heCIsIm5hbWUiOiLQkNGB0L/RgNC+OiDQnNCw0LrRgdC40LzRg9C8IiwiZml4ZWQiOiIyLjEuOSIsInZlcnNpb25fcmF3Ijoi0LTQviAyLjEuOSIsInB1Ymxpc2hlZCI6IjA2LjAyLjIwMjUiLCJzcmNfbGluayI6Imh0dHBzOi8vbWFya2V0cGxhY2UuMWMtYml0cml4LnJ1L3NvbHV0aW9ucy9hc3Byby5tYXgvIiwiZml4X2xpbmsiOiJodHRwczovL2FzcHJvLnJ1L25ld3Mvdnpsb215LXNheXRvdi1hc3Byby8ifSx7ImNvZGUiOiJhc3Byby5tZWRjMiIsIm5hbWUiOiLQkNGB0L/RgNC+OiDQnNC10LTQuNGG0LjQvdGB0LrQuNC5INGG0LXQvdGC0YAgMi4wIiwicGFydG5lciI6ItCQ0YHQv9GA0L4iLCJmaXhlZCI6bnVsbCwid2l0aGRyYXduIjp0cnVlLCJ2ZXJzaW9uX3JhdyI6ItGB0L3Rj9GC0L4g0YEg0L/Rg9Cx0LvQuNC60LDRhtC40LgiLCJwdWJsaXNoZWQiOiIwNi4wMi4yMDI1Iiwic3JjX2xpbmsiOiJodHRwczovL21hcmtldHBsYWNlLjFjLWJpdHJpeC5ydS9zb2x1dGlvbnMvYXNwcm8ubWVkYzIvIiwiZml4X2xpbmsiOiJodHRwczovL2FzcHJvLnJ1L25ld3Mvdnpsb215LXNheXRvdi1hc3Byby8ifSx7ImNvZGUiOiJhc3Byby5tc2hvcCIsIm5hbWUiOiLQkNGB0L/RgNC+OiDQnNCw0YDQutC10YIiLCJmaXhlZCI6IjEuOC42IiwidmVyc2lvbl9yYXciOiLQtNC+IDEuOC42IiwicHVibGlzaGVkIjoiMDYuMDIuMjAyNSIsInNyY19saW5rIjoiaHR0cHM6Ly9tYXJrZXRwbGFjZS4xYy1iaXRyaXgucnUvc29sdXRpb25zL2FzcHJvLm1zaG9wLyIsImZpeF9saW5rIjoiaHR0cHM6Ly9hc3Byby5ydS9uZXdzL3Z6bG9teS1zYXl0b3YtYXNwcm8vIn0seyJjb2RlIjoiYXNwcm8ubmV4dCIsIm5hbWUiOiLQkNGB0L/RgNC+OiBOZXh0IiwiZml4ZWQiOiIxLjkuOSIsInZlcnNpb25fcmF3Ijoi0LTQviAxLjkuOSIsInB1Ymxpc2hlZCI6IjA2LjAyLjIwMjUiLCJzcmNfbGluayI6Imh0dHBzOi8vbWFya2V0cGxhY2UuMWMtYml0cml4LnJ1L3NvbHV0aW9ucy9hc3Byby5uZXh0LyIsImZpeF9saW5rIjoiaHR0cHM6Ly9hc3Byby5ydS9uZXdzL3Z6bG9teS1zYXl0b3YtYXNwcm8vIn0seyJjb2RlIjoiYXNwcm8ub3B0aW11cyIsIm5hbWUiOiLQkNGB0L/RgNC+OiDQntC/0YLQuNC80YPRgSIsImZpeGVkIjoiMS43LjgiLCJ2ZXJzaW9uX3JhdyI6ItC00L4gMS43LjgiLCJwdWJsaXNoZWQiOiIwNi4wMi4yMDI1Iiwic3JjX2xpbmsiOiJodHRwczovL21hcmtldHBsYWNlLjFjLWJpdHJpeC5ydS9zb2x1dGlvbnMvYXNwcm8ub3B0aW11cy8iLCJmaXhfbGluayI6Imh0dHBzOi8vYXNwcm8ucnUvbmV3cy92emxvbXktc2F5dG92LWFzcHJvLyJ9LHsiY29kZSI6ImFzcHJvLnByaW9yaXR5IiwibmFtZSI6ItCQ0YHQv9GA0L46INCf0YDQuNC+0YDQuNGC0LgiLCJwYXJ0bmVyIjoi0JDRgdC/0YDQviIsImZpeGVkIjpudWxsLCJ3aXRoZHJhd24iOnRydWUsInZlcnNpb25fcmF3Ijoi0YHQvdGP0YLQviDRgSDQv9GD0LHQu9C40LrQsNGG0LjQuCIsInB1Ymxpc2hlZCI6IjA2LjAyLjIwMjUiLCJzcmNfbGluayI6Imh0dHBzOi8vbWFya2V0cGxhY2UuMWMtYml0cml4LnJ1L3NvbHV0aW9ucy9hc3Byby5wcmlvcml0eS8iLCJmaXhfbGluayI6Imh0dHBzOi8vYXNwcm8ucnUvbmV3cy92emxvbXktc2F5dG92LWFzcHJvLyJ9LHsiY29kZSI6ImFzcHJvLnJlc29ydCIsIm5hbWUiOiLQkNGB0L/RgNC+OiDQmtGD0YDQvtGA0YIiLCJwYXJ0bmVyIjoi0JDRgdC/0YDQviIsImZpeGVkIjpudWxsLCJ3aXRoZHJhd24iOnRydWUsInZlcnNpb25fcmF3Ijoi0YHQvdGP0YLQviDRgSDQv9GD0LHQu9C40LrQsNGG0LjQuCIsInB1Ymxpc2hlZCI6IjA2LjAyLjIwMjUiLCJzcmNfbGluayI6Imh0dHBzOi8vbWFya2V0cGxhY2UuMWMtYml0cml4LnJ1L3NvbHV0aW9ucy9hc3Byby5yZXNvcnQvIiwiZml4X2xpbmsiOiJodHRwczovL2FzcHJvLnJ1L25ld3Mvdnpsb215LXNheXRvdi1hc3Byby8ifSx7ImNvZGUiOiJhc3Byby5zdHJveSIsIm5hbWUiOiLQkNGB0L/RgNC+OiDQodGC0YDQvtC50LrQsCIsInBhcnRuZXIiOiLQkNGB0L/RgNC+IiwiZml4ZWQiOm51bGwsIndpdGhkcmF3biI6dHJ1ZSwidmVyc2lvbl9yYXciOiLRgdC90Y/RgtC+INGBINC/0YPQsdC70LjQutCw0YbQuNC4IiwicHVibGlzaGVkIjoiMDYuMDIuMjAyNSIsInNyY19saW5rIjoiaHR0cHM6Ly9tYXJrZXRwbGFjZS4xYy1iaXRyaXgucnUvc29sdXRpb25zL2FzcHJvLnN0cm95LyIsImZpeF9saW5rIjoiaHR0cHM6Ly9hc3Byby5ydS9uZXdzL3Z6bG9teS1zYXl0b3YtYXNwcm8vIn0seyJjb2RlIjoiYXNwcm8udGlyZXMiLCJuYW1lIjoi0JDRgdC/0YDQvjog0KjQuNC90Ysg0Lgg0LTQuNGB0LrQuCIsInBhcnRuZXIiOiLQkNGB0L/RgNC+IiwiZml4ZWQiOm51bGwsIndpdGhkcmF3biI6dHJ1ZSwidmVyc2lvbl9yYXciOiLRgdC90Y/RgtC+INGBINC/0YPQsdC70LjQutCw0YbQuNC4IiwicHVibGlzaGVkIjoiMDYuMDIuMjAyNSIsInNyY19saW5rIjoiaHR0cHM6Ly9tYXJrZXRwbGFjZS4xYy1iaXRyaXgucnUvc29sdXRpb25zL2FzcHJvLnRpcmVzLyIsImZpeF9saW5rIjoiaHR0cHM6Ly9hc3Byby5ydS9uZXdzL3Z6bG9teS1zYXl0b3YtYXNwcm8vIn0seyJjb2RlIjoiYXNwcm8udGlyZXMyIiwibmFtZSI6ItCQ0YHQv9GA0L46INCo0LjQvdGLINC4INC00LjRgdC60LggMi4wIiwiZml4ZWQiOiIxLjEuMTQiLCJ2ZXJzaW9uX3JhdyI6ItC00L4gMS4xLjE0IiwicHVibGlzaGVkIjoiMDYuMDIuMjAyNSIsInNyY19saW5rIjoiaHR0cHM6Ly9tYXJrZXRwbGFjZS4xYy1iaXRyaXgucnUvc29sdXRpb25zL2FzcHJvLnRpcmVzMi8iLCJmaXhfbGluayI6Imh0dHBzOi8vYXNwcm8ucnUvbmV3cy92emxvbXktc2F5dG92LWFzcHJvLyJ9LHsiY29kZSI6ImVzb2wuYWxsaW1wb3J0ZXhwb3J0IiwibmFtZSI6ItCc0L3QvtCz0L7RhNGD0L3QutGG0LjQvtC90LDQu9GM0L3Ri9C5INGN0LrRgdC/0L7RgNGCL9C40LzQv9C+0YDRgiDQsiBFeGNlbCIsImZpeGVkIjoiMC42LjQiLCJ2ZXJzaW9uX3JhdyI6ItC00L4gMC42LjQiLCJwdWJsaXNoZWQiOiIzMC4xMi4yMDI1Iiwic3JjX2xpbmsiOiJodHRwczovL21hcmtldHBsYWNlLjFjLWJpdHJpeC5ydS9zb2x1dGlvbnMvZXNvbC5hbGxpbXBvcnRleHBvcnQvIiwiZml4X2xpbmsiOiJodHRwczovL2Vzb2x1dGlvbnMuc3UvYmV6b3Bhc3Rub3N0LXNheXRvdi9kb3JhYm90a2ktYmV6b3Bhc25vc3RpLW1vZHVsZXktaW1wb3J0YS8ifSx7ImNvZGUiOiJlc29sLmltcG9ydGV4cG9ydGV4Y2VsIiwibmFtZSI6ItCt0LrRgdC/0L7RgNGCL9CY0LzQv9C+0YDRgiDRgtC+0LLQsNGA0L7QsiDQsiBFeGNlbCIsImZpeGVkIjoiMy4yLjYiLCJ2ZXJzaW9uX3JhdyI6ItC00L4gMy4yLjYiLCJwdWJsaXNoZWQiOiIzMC4xMi4yMDI1Iiwic3JjX2xpbmsiOiJodHRwczovL21hcmtldHBsYWNlLjFjLWJpdHJpeC5ydS9zb2x1dGlvbnMvZXNvbC5pbXBvcnRleHBvcnRleGNlbC8iLCJmaXhfbGluayI6Imh0dHBzOi8vZXNvbHV0aW9ucy5zdS9iZXpvcGFzdG5vc3Qtc2F5dG92L2RvcmFib3RraS1iZXpvcGFzbm9zdGktbW9kdWxleS1pbXBvcnRhLyJ9LHsiY29kZSI6ImVzb2wuaW1wb3J0eG1sIiwibmFtZSI6ItCY0LzQv9C+0YDRgiDQuNC3IFhNTCwgWU1MLCBKU09OLiDQl9Cw0LPRgNGD0LfQutCwINC60LDRgtCw0LvQvtCz0LAg0YLQvtCy0LDRgNC+0LIgMdChLdCR0LjRgtGA0LjQutGBIiwiZml4ZWQiOiIxLjEuNyIsInZlcnNpb25fcmF3Ijoi0LTQviAxLjEuNyIsInB1Ymxpc2hlZCI6IjEzLjAzLjIwMjUiLCJzcmNfbGluayI6Imh0dHBzOi8vbWFya2V0cGxhY2UuMWMtYml0cml4LnJ1L3NvbHV0aW9ucy9lc29sLmltcG9ydHhtbC8iLCJmaXhfbGluayI6Imh0dHBzOi8vZXNvbHV0aW9ucy5zdS9iZXpvcGFzdG5vc3Qtc2F5dG92LyJ9LHsiY29kZSI6ImVzb2wubWFzc2VkaXQiLCJuYW1lIjoi0JzQsNGB0YHQvtCy0LDRjyDQvtCx0YDQsNCx0L7RgtC60LAg0Y3Qu9C10LzQtdC90YLQvtCyINC40L3RhNC+0LHQu9C+0LrQsCAo0YLQvtCy0LDRgNC+0LIpIiwiZml4ZWQiOiIwLjcuOCIsInZlcnNpb25fcmF3Ijoi0LTQviAwLjcuOCIsInB1Ymxpc2hlZCI6IjEzLjAzLjIwMjUiLCJzcmNfbGluayI6Imh0dHBzOi8vbWFya2V0cGxhY2UuMWMtYml0cml4LnJ1L3NvbHV0aW9ucy9lc29sLm1hc3NlZGl0LyIsImZpeF9saW5rIjoiaHR0cHM6Ly9lc29sdXRpb25zLnN1L2Jlem9wYXN0bm9zdC1zYXl0b3YvIn0seyJjb2RlIjoiaW50ZWMuY29yZSIsIm5hbWUiOiLQr9C00YDQviAtINCx0LDQt9C+0LLRi9C5INC80L7QtNGD0LvRjCDQtNC70Y8g0YDQtdGI0LXQvdC40LkgSU5URUMiLCJmaXhlZCI6IjEuMi4zMCIsInZlcnNpb25fcmF3Ijoi0LTQviAxLjIuMzAiLCJwdWJsaXNoZWQiOiIzMC4wNC4yMDI2Iiwic3JjX2xpbmsiOiJodHRwczovL21hcmtldHBsYWNlLjFjLWJpdHJpeC5ydS9zb2x1dGlvbnMvaW50ZWMuY29yZS8iLCJmaXhfbGluayI6Imh0dHBzOi8vc3AuaW50ZWN3ZWIucnUva2IvYXJ0aWNsZXMvMzcxMjY1LXV5YXp2aW1vc3Qtc2F5dG92LWstdmlydXNhbS1vYm5vdmxlbmllLWJlem9wYXNub3N0aS1kbHlhLXJlc2hlbml5LXVuaXZlcnNlLyJ9LHsiY29kZSI6Impjb2RlLnBob3RvY29tcGFyZSIsIm5hbWUiOiLQpNC+0YLQviDQlNC+INC4INCf0L7RgdC70LU6INGB0YDQsNCy0L3QtdC90LjQtSDQuNC30L7QsdGA0LDQttC10L3QuNC5INC00L4v0L/QvtGB0LvQtSIsImZpeGVkIjoiMS4wLjIiLCJ2ZXJzaW9uX3JhdyI6ItC00L4gMS4wLjIiLCJwdWJsaXNoZWQiOiIwNC4wOS4yMDI2Iiwic3JjX2xpbmsiOiJodHRwczovL21hcmtldHBsYWNlLjFjLWJpdHJpeC5ydS9zb2x1dGlvbnMvamNvZGUucGhvdG9jb21wYXJlLyIsImZpeF9saW5rIjoiaHR0cHM6Ly9oYWJyLmNvbS9ydS9uZXdzLzEwNzkyNjYvIn0seyJjb2RlIjoia2RhLmV4cG9ydGV4Y2VsIiwibmFtZSI6ItCt0LrRgdC/0L7RgNGCINCyIEV4Y2VsLiDQktGL0LPRgNGD0LfQutCwINC60LDRgtCw0LvQvtCz0LAg0YLQvtCy0LDRgNC+0LIgMdChLdCR0LjRgtGA0LjQutGBLiDQodC+0LfQtNCw0L3QuNC1INC/0YDQsNC50YEt0LvQuNGB0YLQsCIsImZpeGVkIjoiMS4yLjMiLCJ2ZXJzaW9uX3JhdyI6ItC00L4gMS4yLjMiLCJwdWJsaXNoZWQiOiIxMy4wMy4yMDI1Iiwic3JjX2xpbmsiOiJodHRwczovL21hcmtldHBsYWNlLjFjLWJpdHJpeC5ydS9zb2x1dGlvbnMva2RhLmV4cG9ydGV4Y2VsLyIsImZpeF9saW5rIjoiaHR0cHM6Ly9tYXlha2l0LnJ1L2Fib3V0L25ld3MvYmV6b3BhY25vc3Qtc2FqdG92In0seyJjb2RlIjoia2RhLmltcG9ydGV4Y2VsIiwibmFtZSI6ItCY0LzQv9C+0YDRgiDQuNC3IEV4Y2VsIiwiZml4ZWQiOiIzLjIuNiIsInZlcnNpb25fcmF3Ijoi0LTQviAzLjIuNiIsInB1Ymxpc2hlZCI6IjMwLjEyLjIwMjUiLCJzcmNfbGluayI6Imh0dHBzOi8vbWFya2V0cGxhY2UuMWMtYml0cml4LnJ1L3NvbHV0aW9ucy9rZGEuaW1wb3J0ZXhjZWwvIiwiZml4X2xpbmsiOiJodHRwczovL2Vzb2x1dGlvbnMuc3UvYmV6b3Bhc3Rub3N0LXNheXRvdi9kb3JhYm90a2ktYmV6b3Bhc25vc3RpLW1vZHVsZXktaW1wb3J0YS8ifSx7ImNvZGUiOiJrb210ZXQuZGVsaXZlcnkiLCJuYW1lIjoi0JrQntCc0KLQldCiINCa0LDRgdGB0LAg0JrRg9GA0YzQtdGAIiwiZml4ZWQiOiIyLjguMSIsInZlcnNpb25fcmF3Ijoi0LTQviAyLjguMSIsInB1Ymxpc2hlZCI6IjI2LjA4LjIwMjYiLCJzcmNfbGluayI6Imh0dHBzOi8vbWFya2V0cGxhY2UuMWMtYml0cml4LnJ1L3NvbHV0aW9ucy9rb210ZXQuZGVsaXZlcnkvP3VwZGF0ZV9zeXM9WSN0YWItYWJvdXQtbGluayIsImZpeF9saW5rIjoiaHR0cHM6Ly9rYXNzYS5rb210ZXQucnUvYmxvZy9vYm5vdmxlbml5ZS1iZXpvcGFzbm9zdGktcGxhZ2luYS1rb210ZXQta2Fzc2Eta3VyeWVyLXYtaXMtYml0cmlrcyJ9LHsiY29kZSI6InNocy5wYXJzZXIiLCJuYW1lIjoi0KHQvtGC0LHQuNGCOiDQn9Cw0YDRgdC10YAg0LrQvtC90YLQtdC90YLQsCDigJMg0YHQsNC50YLRiywgZXhjZWwsIHhtbCwgeW1sLCBjc3YsIHJzcyIsImZpeGVkIjoiNS4xMC40IiwidmVyc2lvbl9yYXciOiLQtNC+IDUuMTAuNCIsInB1Ymxpc2hlZCI6IjE3LjAzLjIwMjUiLCJzcmNfbGluayI6Imh0dHBzOi8vbWFya2V0cGxhY2UuMWMtYml0cml4LnJ1L3NvbHV0aW9ucy9zaHMucGFyc2VyLyIsImZpeF9saW5rIjoiaHR0cHM6Ly93d3cuc290Yml0LnJ1L2luZm8vbW9kdWxlLzFjLWJpdHJpeC1zZWN1cml0eS1wYXRjaC5odG1sIn0seyJjb2RlIjoic290Yml0Lmh0bWxlZGl0b3JhZGRpdGlvbiIsIm5hbWUiOiLQodC+0YLQsdC40YI6INCR0YvRgdGC0YDQsNGPINC30LDQs9GA0YPQt9C60LAg0LrQsNGA0YLQuNC90L7QuiDQsiDQstC40LfRg9Cw0LvRjNC90L7QvCDRgNC10LTQsNC60YLQvtGA0LUiLCJmaXhlZCI6IjEuMS4wIiwidmVyc2lvbl9yYXciOiLQtNC+IDEuMS4wIiwicHVibGlzaGVkIjoiMTcuMDMuMjAyNSIsInNyY19saW5rIjoiaHR0cHM6Ly9tYXJrZXRwbGFjZS4xYy1iaXRyaXgucnUvc29sdXRpb25zL3NvdGJpdC5odG1sZWRpdG9yYWRkaXRpb24vIiwiZml4X2xpbmsiOiJodHRwczovL3d3dy5zb3RiaXQucnUvaW5mby9tb2R1bGUvMWMtYml0cml4LXNlY3VyaXR5LXBhdGNoLmh0bWwifSx7ImNvZGUiOiJzb3RiaXQub3JpZ2FtaSIsIm5hbWUiOiLQodC+0YLQsdC40YI6INCe0YDQuNCz0LDQvNC4IiwicGFydG5lciI6ItCh0L7RgtCx0LjRgiIsImZpeGVkIjpudWxsLCJ3aXRoZHJhd24iOnRydWUsInZlcnNpb25fcmF3Ijoi0YHQvdGP0YLQviDRgSDQv9GD0LHQu9C40LrQsNGG0LjQuCIsInB1Ymxpc2hlZCI6IjE3LjAzLjIwMjUiLCJzcmNfbGluayI6Imh0dHBzOi8vbWFya2V0cGxhY2UuMWMtYml0cml4LnJ1L3NvbHV0aW9ucy9zb3RiaXQub3JpZ2FtaS8iLCJmaXhfbGluayI6Imh0dHBzOi8vd3d3LnNvdGJpdC5ydS9pbmZvL21vZHVsZS8xYy1iaXRyaXgtc2VjdXJpdHktcGF0Y2guaHRtbCJ9LHsiY29kZSI6InNvdGJpdC5yZWdpb25zIiwibmFtZSI6ItCh0L7RgtCx0LjRgjog0JzRg9C70YzRgtC40YDQtdCz0LjQvtC90LDQu9GM0L3QvtGB0YLRjCIsImZpeGVkIjoiMS44LjUiLCJ2ZXJzaW9uX3JhdyI6ItC00L4gMS44LjUiLCJwdWJsaXNoZWQiOiIxNy4wMy4yMDI1Iiwic3JjX2xpbmsiOiJodHRwczovL21hcmtldHBsYWNlLjFjLWJpdHJpeC5ydS9zb2x1dGlvbnMvc290Yml0LnJlZ2lvbnMvIiwiZml4X2xpbmsiOiJodHRwczovL3d3dy5zb3RiaXQucnUvaW5mby9tb2R1bGUvMWMtYml0cml4LXNlY3VyaXR5LXBhdGNoLmh0bWwifSx7ImNvZGUiOiJzb3RiaXQucmV2aWV3cyIsIm5hbWUiOiLQodC+0YLQsdC40YI6INCg0LDRgdGI0LjRgNC10L3QvdGL0LUg0L7RgtC30YvQstGLIiwiZml4ZWQiOiIyLjAuMCIsInZlcnNpb25fcmF3Ijoi0LTQviAyLjAuMCIsInB1Ymxpc2hlZCI6IjE3LjAzLjIwMjUiLCJzcmNfbGluayI6Imh0dHBzOi8vbWFya2V0cGxhY2UuMWMtYml0cml4LnJ1L3NvbHV0aW9ucy9zb3RiaXQucmV2aWV3cy8iLCJmaXhfbGluayI6Imh0dHBzOi8vd3d3LnNvdGJpdC5ydS9pbmZvL21vZHVsZS8xYy1iaXRyaXgtc2VjdXJpdHktcGF0Y2guaHRtbCJ9XX0=';
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
