<?php
declare(strict_types=1);

require __DIR__ . '/../app/bootstrap.php';

use WSSC\Auth\Auth;
use WSSC\Security\Csrf;
use WSSC\Util\Html;

$config = WSSC\app_config();

function wssc_project_root(): string
{
    return realpath(__DIR__ . '/..') ?: (__DIR__ . '/..');
}

function wssc_vuln_db_path(): string
{
    return wssc_project_root() . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . 'vuln_db.json';
}

function wssc_is_ip_allowed(array $cfg): bool
{
    $allowed = $cfg['admin']['update_allowed_ips'] ?? [];
    if (!is_array($allowed) || !$allowed) {
        return true;
    }
    $ip = (string)($_SERVER['REMOTE_ADDR'] ?? '');
    return in_array($ip, $allowed, true);
}

function wssc_allowed_sources(): array
{
    return [
        [
            'id' => 'nvd_cms',
            'name' => 'NVD (NIST) - CVE API 2.0 (CMS core)',
            'url' => 'https://services.nvd.nist.gov/rest/json/cves/2.0',
            'description' => 'Extrage CVE-uri și intervale de versiuni pentru WordPress/Drupal/Joomla din CPE/configurations (NVD).',
        ],
        [
            'id' => 'nvd_recent',
            'name' => 'NVD (NIST) - CVE API 2.0 (recent)',
            'url' => 'https://services.nvd.nist.gov/rest/json/cves/2.0',
            'description' => 'Importă CVE-uri recente (listă generală) pentru referință în baza locală.',
        ],
        [
            'id' => 'cisa_kev',
            'name' => 'CISA KEV (Known Exploited Vulnerabilities)',
            'url' => 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
            'description' => 'Listă publică de CVE-uri exploatate activ (fără intervale de versiuni).',
        ],
        [
            'id' => 'circl_last',
            'name' => 'CIRCL CVE Search (last)',
            'url' => 'https://cve.circl.lu/api/last',
            'description' => 'Importă ultimele CVE-uri din API public (format alternativ față de NVD).',
        ],
    ];
}

function wssc_curl_get(string $url, int $timeoutSeconds, int $maxBytes): array
{
    $u = parse_url($url);
    if (!is_array($u) || ($u['scheme'] ?? '') !== 'https') {
        return ['ok' => false, 'status' => 0, 'body' => '', 'error' => 'URL invalid (doar https este permis).'];
    }

    $ch = curl_init();
    if ($ch === false) {
        return ['ok' => false, 'status' => 0, 'body' => '', 'error' => 'cURL indisponibil.'];
    }

    $body = '';
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => false,
        CURLOPT_HEADER => false,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_MAXREDIRS => 0,
        CURLOPT_CONNECTTIMEOUT => $timeoutSeconds,
        CURLOPT_TIMEOUT => $timeoutSeconds,
        CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
        CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
        CURLOPT_USERAGENT => 'WSSC/1.0 (+cve-sync)',
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_WRITEFUNCTION => static function ($curl, string $chunk) use (&$body, $maxBytes): int {
            $remaining = $maxBytes - strlen($body);
            if ($remaining <= 0) {
                return 0;
            }
            if (strlen($chunk) > $remaining) {
                $chunk = substr($chunk, 0, $remaining);
            }
            $body .= $chunk;
            return strlen($chunk);
        },
    ]);

    $ok = curl_exec($ch);
    $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $err = curl_error($ch);
    $ch = null;

    if ($ok === false) {
        return ['ok' => false, 'status' => $status ?: 0, 'body' => '', 'error' => $err !== '' ? $err : 'Eroare HTTP.'];
    }

    return ['ok' => true, 'status' => $status, 'body' => $body, 'error' => null];
}

function wssc_get_json(string $url, int $timeoutSeconds, int $maxBytes): array
{
    $resp = wssc_curl_get($url, $timeoutSeconds, $maxBytes);
    if (!$resp['ok']) {
        throw new RuntimeException(($resp['error'] ?? 'Eroare HTTP.') . ' (' . $url . ')');
    }
    if ((int)($resp['status'] ?? 0) < 200 || (int)($resp['status'] ?? 0) >= 300) {
        throw new RuntimeException('HTTP ' . (int)($resp['status'] ?? 0) . ' la ' . $url);
    }
    $decoded = json_decode((string)($resp['body'] ?? ''), true);
    if (!is_array($decoded)) {
        throw new RuntimeException('JSON invalid la ' . $url);
    }
    return $decoded;
}

function wssc_read_vuln_db(): array
{
    $path = wssc_vuln_db_path();
    if (!is_file($path)) {
        return [];
    }
    $raw = file_get_contents($path);
    if (!is_string($raw) || $raw === '') {
        return [];
    }
    $decoded = json_decode($raw, true);
    return is_array($decoded) ? $decoded : [];
}

function wssc_write_vuln_db(array $data): void
{
    $path = wssc_vuln_db_path();
    $dir = dirname($path);
    if (!is_dir($dir)) {
        if (!@mkdir($dir, 0755, true) && !is_dir($dir)) {
            throw new RuntimeException('Nu se poate crea folderul data/.');
        }
    }

    $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if (!is_string($json) || $json === '') {
        throw new RuntimeException('Nu se poate genera JSON.');
    }

    $tmp = tempnam($dir, 'wssc_vdb_');
    if (!is_string($tmp) || $tmp === '') {
        throw new RuntimeException('Nu se poate crea fișier temporar.');
    }
    if (@file_put_contents($tmp, $json, LOCK_EX) === false) {
        @unlink($tmp);
        throw new RuntimeException('Nu se poate scrie fișierul temporar (permisiuni).');
    }
    if (!@rename($tmp, $path)) {
        @unlink($tmp);
        throw new RuntimeException('Nu se poate înlocui vuln_db.json (permisiuni).');
    }
}

function wssc_normalize_text(?string $s): string
{
    $s = is_string($s) ? trim($s) : '';
    return preg_replace('/\s+/', ' ', $s) ?? $s;
}

function wssc_pick_en_description(array $descriptions): string
{
    foreach ($descriptions as $d) {
        if (is_array($d) && ($d['lang'] ?? null) === 'en' && is_string($d['value'] ?? null)) {
            return wssc_normalize_text($d['value']);
        }
    }
    foreach ($descriptions as $d) {
        if (is_array($d) && is_string($d['value'] ?? null)) {
            return wssc_normalize_text($d['value']);
        }
    }
    return '';
}

function wssc_cpe_to_vendor_product_version(string $criteria): array
{
    $parts = explode(':', $criteria);
    if (count($parts) < 6 || $parts[0] !== 'cpe' || $parts[1] !== '2.3') {
        return ['vendor' => null, 'product' => null, 'version' => null];
    }
    return [
        'vendor' => $parts[3] !== '' ? $parts[3] : null,
        'product' => $parts[4] !== '' ? $parts[4] : null,
        'version' => $parts[5] !== '' ? $parts[5] : null,
    ];
}

function wssc_cms_from_cpe(string $vendor, string $product): ?string
{
    if ($vendor === 'wordpress' && $product === 'wordpress') {
        return 'WordPress';
    }
    if ($vendor === 'drupal' && $product === 'drupal') {
        return 'Drupal';
    }
    if (($vendor === 'joomla' && str_starts_with($product, 'joomla')) || ($vendor === 'open_source_matter' && str_contains($product, 'joomla'))) {
        return 'Joomla';
    }
    return null;
}

function wssc_collect_cpe_matches(array $node, array &$out): void
{
    foreach (($node['cpeMatch'] ?? []) as $m) {
        if (!is_array($m)) {
            continue;
        }
        $crit = $m['criteria'] ?? null;
        if (!is_string($crit) || $crit === '') {
            continue;
        }
        $out[] = $m;
    }
    foreach (($node['children'] ?? []) as $ch) {
        if (is_array($ch)) {
            wssc_collect_cpe_matches($ch, $out);
        }
    }
}

function wssc_nvd_fetch_page(array $params, int $timeoutSeconds): array
{
    $base = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
    $url = $base . '?' . http_build_query($params);

    $attempt = 0;
    $delayUs = 500_000;
    while (true) {
        $attempt++;

        $resp = wssc_curl_get($url, $timeoutSeconds, 6_000_000);
        if (!$resp['ok']) {
            throw new RuntimeException(($resp['error'] ?? 'Eroare HTTP.') . ' (' . $url . ')');
        }

        $status = (int)($resp['status'] ?? 0);
        if ($status === 404) {
            throw new RuntimeException('NVD API: request invalid (de obicei intervalul pubStartDate/pubEndDate depășește 120 zile). HTTP 404 la ' . $url);
        }

        if (($status === 429 || $status === 503) && $attempt < 6) {
            usleep($delayUs);
            $delayUs = min(8_000_000, $delayUs * 2);
            continue;
        }

        if ($status < 200 || $status >= 300) {
            throw new RuntimeException('HTTP ' . $status . ' la ' . $url);
        }

        $decoded = json_decode((string)($resp['body'] ?? ''), true);
        if (!is_array($decoded)) {
            throw new RuntimeException('JSON invalid la ' . $url);
        }
        return $decoded;
    }
}

/**
 * @return list<array{start:string,end:string}>
 */
function wssc_nvd_pubdate_segments(int $lastDays): array
{
    $lastDays = max(1, $lastDays);
    $maxRangeDays = 120;

    $endTs = time();
    $startTs = $endTs - ($lastDays * 86400);
    $segments = [];
    $cursor = $startTs;
    while ($cursor < $endTs) {
        $segEnd = min($cursor + ($maxRangeDays * 86400), $endTs);
        $segments[] = [
            'start' => gmdate('Y-m-d\TH:i:s.000\Z', $cursor),
            'end' => gmdate('Y-m-d\TH:i:s.000\Z', $segEnd),
        ];
        $cursor = $segEnd;
    }
    return $segments;
}

function wssc_source_nvd_recent(array $settings): array
{
    $timeout = (int)($settings['timeout_seconds'] ?? 20);
    $lastDays = (int)($settings['nvd_last_days'] ?? 120);
    $max = (int)($settings['nvd_max_results'] ?? 500);
    $apiKey = trim((string)($settings['nvd_api_key'] ?? ''));
    $sleepUs = $apiKey !== '' ? 250_000 : 600_000;

    $lastDays = max(1, min(3650, $lastDays));
    $max = max(1, min(5000, $max));

    $cves = [];
    $seen = [];
    $perPage = 200;

    $segments = wssc_nvd_pubdate_segments($lastDays);
    foreach ($segments as $seg) {
        $startIndex = 0;
        while (count($cves) < $max) {
            $params = [
                'pubStartDate' => $seg['start'],
                'pubEndDate' => $seg['end'],
                'startIndex' => $startIndex,
                'resultsPerPage' => $perPage,
            ];
            if ($apiKey !== '') {
                $params['apiKey'] = $apiKey;
            }
            $page = wssc_nvd_fetch_page($params, $timeout);

            $v = $page['vulnerabilities'] ?? [];
            if (!is_array($v) || !$v) {
                break;
            }

            foreach ($v as $item) {
                if (!is_array($item) || !is_array($item['cve'] ?? null)) {
                    continue;
                }
                $c = $item['cve'];
                $id = $c['id'] ?? null;
                if (!is_string($id) || !preg_match('/^CVE-\d{4}-\d+$/', $id)) {
                    continue;
                }
                if (isset($seen[$id])) {
                    continue;
                }
                $seen[$id] = true;
                $cves[] = [
                    'cve' => $id,
                    'title' => wssc_normalize_text($c['sourceIdentifier'] ?? '') !== '' ? ('NVD: ' . wssc_normalize_text($c['sourceIdentifier'] ?? '')) : '',
                    'description' => wssc_pick_en_description(is_array($c['descriptions'] ?? null) ? $c['descriptions'] : []),
                    'published' => is_string($c['published'] ?? null) ? $c['published'] : null,
                    'modified' => is_string($c['lastModified'] ?? null) ? $c['lastModified'] : null,
                    'link' => 'https://nvd.nist.gov/vuln/detail/' . $id,
                    'source' => 'nvd',
                ];

                if (count($cves) >= $max) {
                    break 2;
                }
            }

            $startIndex += $perPage;
            $total = (int)($page['totalResults'] ?? 0);
            if ($total > 0 && $startIndex >= $total) {
                break;
            }
            usleep($sleepUs);
        }
    }

    return [
        'cms' => [],
        'cves' => $cves,
        'stats' => ['cves' => count($cves), 'cms' => 0],
    ];
}

function wssc_source_nvd_cms(array $settings): array
{
    $timeout = (int)($settings['timeout_seconds'] ?? 20);
    $lastDays = (int)($settings['nvd_last_days'] ?? 120);
    $max = (int)($settings['nvd_max_results'] ?? 800);
    $apiKey = trim((string)($settings['nvd_api_key'] ?? ''));
    $sleepUs = $apiKey !== '' ? 250_000 : 600_000;

    $lastDays = max(1, min(3650, $lastDays));
    $max = max(1, min(5000, $max));

    $keywords = [
        ['kw' => 'wordpress', 'cms' => 'WordPress'],
        ['kw' => 'drupal', 'cms' => 'Drupal'],
        ['kw' => 'joomla', 'cms' => 'Joomla'],
    ];

    $cmsEntries = [];
    $cves = [];
    $seenCms = [];
    $seenCves = [];

    foreach ($keywords as $k) {
        $perPage = 200;
        $segments = wssc_nvd_pubdate_segments($lastDays);
        foreach ($segments as $seg) {
            $startIndex = 0;
            while ((count($cmsEntries) + count($cves)) < $max) {
                $params = [
                    'keywordSearch' => $k['kw'],
                    'pubStartDate' => $seg['start'],
                    'pubEndDate' => $seg['end'],
                    'startIndex' => $startIndex,
                    'resultsPerPage' => $perPage,
                ];
                if ($apiKey !== '') {
                    $params['apiKey'] = $apiKey;
                }
                $page = wssc_nvd_fetch_page($params, $timeout);

                $v = $page['vulnerabilities'] ?? [];
                if (!is_array($v) || !$v) {
                    break;
                }

                foreach ($v as $item) {
                    if (!is_array($item) || !is_array($item['cve'] ?? null)) {
                        continue;
                    }
                    $c = $item['cve'];
                    $id = $c['id'] ?? null;
                    if (!is_string($id) || !preg_match('/^CVE-\d{4}-\d+$/', $id)) {
                        continue;
                    }

                    if (!isset($seenCves[$id])) {
                        $seenCves[$id] = true;
                        $cves[] = [
                            'cve' => $id,
                            'title' => '',
                            'description' => wssc_pick_en_description(is_array($c['descriptions'] ?? null) ? $c['descriptions'] : []),
                            'published' => is_string($c['published'] ?? null) ? $c['published'] : null,
                            'modified' => is_string($c['lastModified'] ?? null) ? $c['lastModified'] : null,
                            'link' => 'https://nvd.nist.gov/vuln/detail/' . $id,
                            'source' => 'nvd',
                        ];
                    }

                    $configs = $c['configurations'] ?? null;
                    if (!is_array($configs)) {
                        continue;
                    }

                    $matches = [];
                    foreach ($configs as $cfg) {
                        if (!is_array($cfg)) {
                            continue;
                        }
                        foreach (($cfg['nodes'] ?? []) as $node) {
                            if (is_array($node)) {
                                wssc_collect_cpe_matches($node, $matches);
                            }
                        }
                    }

                    foreach ($matches as $m) {
                        $criteria = (string)($m['criteria'] ?? '');
                        $parsed = wssc_cpe_to_vendor_product_version($criteria);
                        $vendor = $parsed['vendor'];
                        $product = $parsed['product'];
                        if (!is_string($vendor) || !is_string($product)) {
                            continue;
                        }
                        $cms = wssc_cms_from_cpe($vendor, $product);
                        if ($cms === null) {
                            continue;
                        }

                        $ver = $parsed['version'];
                        $minInc = null;
                        $minExc = null;
                        $maxInc = null;
                        $maxExc = null;

                        if (is_string($ver) && $ver !== '' && $ver !== '*' && $ver !== '-') {
                            $minInc = $ver;
                            $maxInc = $ver;
                        } else {
                            if (is_string($m['versionStartIncluding'] ?? null)) $minInc = (string)$m['versionStartIncluding'];
                            if (is_string($m['versionStartExcluding'] ?? null)) $minExc = (string)$m['versionStartExcluding'];
                            if (is_string($m['versionEndIncluding'] ?? null)) $maxInc = (string)$m['versionEndIncluding'];
                            if (is_string($m['versionEndExcluding'] ?? null)) $maxExc = (string)$m['versionEndExcluding'];
                        }

                        if ($minInc === null && $minExc === null && $maxInc === null && $maxExc === null) {
                            continue;
                        }

                        $key = $cms . '|' . $id . '|' . (string)$minInc . '|' . (string)$minExc . '|' . (string)$maxInc . '|' . (string)$maxExc;
                        if (isset($seenCms[$key])) {
                            continue;
                        }
                        $seenCms[$key] = true;

                        $cmsEntries[] = [
                            'name' => $cms,
                            'min_version_inclusive' => $minInc,
                            'min_version_exclusive' => $minExc,
                            'max_version_inclusive' => $maxInc,
                            'max_version_exclusive' => $maxExc,
                            'cve' => $id,
                            'title' => wssc_normalize_text($c['sourceIdentifier'] ?? '') !== '' ? ('NVD: ' . wssc_normalize_text($c['sourceIdentifier'] ?? '')) : 'NVD CVE',
                            'link' => 'https://nvd.nist.gov/vuln/detail/' . $id,
                            'notes' => '',
                            'source' => 'nvd',
                        ];

                        if ((count($cmsEntries) + count($cves)) >= $max) {
                            break 4;
                        }
                    }
                }

                $startIndex += $perPage;
                $total = (int)($page['totalResults'] ?? 0);
                if ($total > 0 && $startIndex >= $total) {
                    break;
                }
                usleep($sleepUs);
            }
        }
    }

    return [
        'cms' => $cmsEntries,
        'cves' => $cves,
        'stats' => ['cves' => count($cves), 'cms' => count($cmsEntries)],
    ];
}

function wssc_source_cisa_kev(array $settings): array
{
    $timeout = (int)($settings['timeout_seconds'] ?? 20);
    $data = wssc_get_json('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', $timeout, 6_000_000);
    $v = $data['vulnerabilities'] ?? null;
    if (!is_array($v)) {
        return ['cms' => [], 'cves' => [], 'stats' => ['cves' => 0, 'cms' => 0]];
    }

    $cves = [];
    $seen = [];
    foreach ($v as $item) {
        if (!is_array($item)) {
            continue;
        }
        $id = $item['cveID'] ?? null;
        if (!is_string($id) || !preg_match('/^CVE-\d{4}-\d+$/', $id)) {
            continue;
        }
        if (isset($seen[$id])) {
            continue;
        }
        $seen[$id] = true;
        $cves[] = [
            'cve' => $id,
            'title' => wssc_normalize_text($item['vulnerabilityName'] ?? ''),
            'description' => wssc_normalize_text($item['shortDescription'] ?? ''),
            'published' => null,
            'modified' => null,
            'link' => 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
            'source' => 'cisa_kev',
        ];
    }

    return [
        'cms' => [],
        'cves' => $cves,
        'stats' => ['cves' => count($cves), 'cms' => 0],
    ];
}

function wssc_source_circl_last(array $settings): array
{
    $timeout = (int)($settings['timeout_seconds'] ?? 20);
    $data = wssc_get_json('https://cve.circl.lu/api/last', $timeout, 6_000_000);
    if (!is_array($data)) {
        return ['cms' => [], 'cves' => [], 'stats' => ['cves' => 0, 'cms' => 0]];
    }

    $cves = [];
    $seen = [];
    foreach ($data as $item) {
        if (!is_array($item)) {
            continue;
        }
        $id = $item['id'] ?? null;
        if (!is_string($id) || !preg_match('/^CVE-\d{4}-\d+$/', $id)) {
            continue;
        }
        if (isset($seen[$id])) {
            continue;
        }
        $seen[$id] = true;
        $refs = [];
        foreach (($item['references'] ?? []) as $r) {
            if (is_string($r) && $r !== '') {
                $refs[] = $r;
            }
        }
        $cves[] = [
            'cve' => $id,
            'title' => wssc_normalize_text($item['summary'] ?? ''),
            'description' => wssc_normalize_text($item['summary'] ?? ''),
            'published' => is_string($item['Published'] ?? null) ? $item['Published'] : null,
            'modified' => is_string($item['Modified'] ?? null) ? $item['Modified'] : null,
            'link' => $refs[0] ?? ('https://cve.circl.lu/cve/' . $id),
            'source' => 'circl',
        ];
    }

    return [
        'cms' => [],
        'cves' => $cves,
        'stats' => ['cves' => count($cves), 'cms' => 0],
    ];
}

function wssc_merge_cves(array $lists): array
{
    $out = [];
    $seen = [];
    foreach ($lists as $list) {
        foreach ($list as $row) {
            if (!is_array($row)) {
                continue;
            }
            $id = $row['cve'] ?? null;
            if (!is_string($id) || $id === '') {
                continue;
            }
            if (isset($seen[$id])) {
                continue;
            }
            $seen[$id] = true;
            $out[] = $row;
        }
    }
    return $out;
}

function wssc_merge_cms(array $lists): array
{
    $out = [];
    $seen = [];
    foreach ($lists as $list) {
        foreach ($list as $row) {
            if (!is_array($row)) {
                continue;
            }
            $cms = (string)($row['name'] ?? '');
            $cve = (string)($row['cve'] ?? '');
            $minI = (string)($row['min_version_inclusive'] ?? '');
            $minE = (string)($row['min_version_exclusive'] ?? '');
            $maxI = (string)($row['max_version_inclusive'] ?? '');
            $maxE = (string)($row['max_version_exclusive'] ?? '');
            $key = $cms . '|' . $cve . '|' . $minI . '|' . $minE . '|' . $maxI . '|' . $maxE;
            if ($cms === '' || $cve === '' || isset($seen[$key])) {
                continue;
            }
            $seen[$key] = true;
            $out[] = $row;
        }
    }
    return $out;
}

if (!wssc_is_ip_allowed($config)) {
    http_response_code(403);
    echo 'Acces interzis (IP neautorizat).';
    exit;
}

$errors = [];
$messages = [];
$csrf = new Csrf();
$token = $csrf->getToken();
$auth = new Auth(WSSC\db());
$authed = $auth->isAuthenticated() && $auth->role() === 'administrator';
$authedUser = $authed ? ($auth->username() ?? '') : '';

$db = wssc_read_vuln_db();
$settings = is_array($db['settings'] ?? null) ? $db['settings'] : [];
$enabled = $settings['enabled_sources'] ?? null;
$enabled = is_array($enabled) ? array_values(array_filter($enabled, 'is_string')) : ['nvd_cms'];

$timeoutSeconds = (int)($settings['timeout_seconds'] ?? 20);
$nvdLastDays = (int)($settings['nvd_last_days'] ?? 365);
$nvdMaxResults = (int)($settings['nvd_max_results'] ?? 800);
$nvdApiKey = is_string($settings['nvd_api_key'] ?? null) ? trim((string)$settings['nvd_api_key']) : '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        $csrf->requireValidToken($_POST['csrf_token'] ?? null);
        $action = (string)($_POST['action'] ?? '');

        if ($action === 'login') {
            $username = (string)($_POST['username'] ?? '');
            $pwd = (string)($_POST['password'] ?? '');
            $auth->login($username, $pwd);
            if ($auth->role() !== 'administrator') {
                $auth->logout();
                throw new RuntimeException('Acces interzis.');
            }
            $authed = true;
            $authedUser = $auth->username() ?? '';
            $messages[] = 'Autentificare reușită.';
        }

        if ($action === 'logout') {
            $auth->logout();
            $authed = false;
            $authedUser = '';
            $messages[] = 'Delogat.';
        }

        if (!in_array($action, ['login', 'logout'], true)) {
            $auth->requireRole('administrator');
            $authed = true;
            $authedUser = $auth->username() ?? '';
        }

        $newEnabled = $_POST['sources'] ?? [];
        $newEnabled = is_array($newEnabled) ? array_values(array_filter($newEnabled, 'is_string')) : [];

        $validIds = array_map(static fn($s) => (string)$s['id'], wssc_allowed_sources());
        $newEnabled = array_values(array_intersect($newEnabled, $validIds));

        $timeoutSeconds = (int)($_POST['timeout_seconds'] ?? $timeoutSeconds);
        $timeoutSeconds = max(5, min(120, $timeoutSeconds));

        $nvdLastDays = (int)($_POST['nvd_last_days'] ?? $nvdLastDays);
        $nvdLastDays = max(1, min(3650, $nvdLastDays));

        $nvdMaxResults = (int)($_POST['nvd_max_results'] ?? $nvdMaxResults);
        $nvdMaxResults = max(1, min(5000, $nvdMaxResults));

        $nvdApiKey = trim((string)($_POST['nvd_api_key'] ?? $nvdApiKey));
        if (strlen($nvdApiKey) > 200) {
            $nvdApiKey = substr($nvdApiKey, 0, 200);
        }

        $settings = [
            'enabled_sources' => $newEnabled,
            'timeout_seconds' => $timeoutSeconds,
            'nvd_last_days' => $nvdLastDays,
            'nvd_max_results' => $nvdMaxResults,
            'nvd_api_key' => $nvdApiKey,
        ];

        if ($action === 'save') {
            $db['settings'] = $settings;
            $db['meta'] = is_array($db['meta'] ?? null) ? $db['meta'] : [];
            $db['meta']['settings_updated_at'] = gmdate('c');
            wssc_write_vuln_db($db);
            $messages[] = 'Setările au fost salvate.';
        }

        if ($action === 'save_and_update') {
            $enabled = $newEnabled;

            $runs = [];
            $stats = [];
            $allCms = [];
            $allCves = [];

            foreach ($enabled as $sid) {
                $result = match ($sid) {
                    'nvd_cms' => wssc_source_nvd_cms($settings),
                    'nvd_recent' => wssc_source_nvd_recent($settings),
                    'cisa_kev' => wssc_source_cisa_kev($settings),
                    'circl_last' => wssc_source_circl_last($settings),
                    default => ['cms' => [], 'cves' => [], 'stats' => ['cves' => 0, 'cms' => 0]],
                };
                $runs[$sid] = [
                    'ran_at' => gmdate('c'),
                    'stats' => $result['stats'] ?? [],
                ];
                $stats[$sid] = $result['stats'] ?? [];
                $allCms[] = $result['cms'] ?? [];
                $allCves[] = $result['cves'] ?? [];
            }

            $db = [
                'meta' => [
                    'generated_at' => gmdate('c'),
                    'sources' => $runs,
                ],
                'settings' => $settings,
                'cms' => wssc_merge_cms($allCms),
                'cves' => wssc_merge_cves($allCves),
            ];

            wssc_write_vuln_db($db);

            $messages[] = 'vuln_db.json a fost actualizat.';
        }
    } catch (Throwable $e) {
        $errors[] = $e->getMessage();
    }
}

$enabled = $settings['enabled_sources'] ?? $enabled;
$enabled = is_array($enabled) ? array_values(array_filter($enabled, 'is_string')) : [];

$currentMeta = is_array($db['meta'] ?? null) ? $db['meta'] : [];
$generatedAt = is_string($currentMeta['generated_at'] ?? null) ? $currentMeta['generated_at'] : null;
$cmsCount = is_array($db['cms'] ?? null) ? count($db['cms']) : 0;
$cvesCount = is_array($db['cves'] ?? null) ? count($db['cves']) : 0;

?>
<!doctype html>
<html lang="ro">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title><?= Html::e('WSSC - Surse CVE') ?></title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
  <?= WSSC\navbar_html($config) ?>

  <main class="container my-4">
    <div class="d-flex align-items-center justify-content-between mb-3">
      <h1 class="h4 mb-0">Surse publice pentru CVE-uri</h1>
      <span class="badge bg-secondary">Admin</span>
    </div>

    <?php if ($errors): ?>
      <div class="alert alert-danger">
        <div class="fw-semibold mb-1">Eroare</div>
        <ul class="mb-0">
          <?php foreach ($errors as $er): ?>
            <li><?= Html::e($er) ?></li>
          <?php endforeach; ?>
        </ul>
      </div>
    <?php endif; ?>

    <?php if ($messages): ?>
      <div class="alert alert-success">
        <ul class="mb-0">
          <?php foreach ($messages as $m): ?>
            <li><?= Html::e($m) ?></li>
          <?php endforeach; ?>
        </ul>
      </div>
    <?php endif; ?>

    <?php if (!$authed): ?>
      <div class="card mb-3">
        <div class="card-header">Autentificare</div>
        <div class="card-body">
          <form method="post" class="row g-2">
            <input type="hidden" name="csrf_token" value="<?= Html::e($token) ?>">
            <input type="hidden" name="action" value="login">
            <div class="col-md-4">
              <input class="form-control" name="username" placeholder="Username" required>
            </div>
            <div class="col-md-5">
              <input class="form-control" type="password" name="password" placeholder="Parolă" required>
            </div>
            <div class="col-md-3">
              <button class="btn btn-primary w-100" type="submit">Login</button>
            </div>
          </form>
        </div>
      </div>
    <?php else: ?>
      <form method="post" class="mb-3">
        <input type="hidden" name="csrf_token" value="<?= Html::e($token) ?>">
        <input type="hidden" name="action" value="logout">
        <div class="d-flex align-items-center gap-2">
          <span class="small text-muted">Autentificat: <?= Html::e($authedUser) ?></span>
          <button class="btn btn-outline-secondary btn-sm" type="submit">Logout</button>
        </div>
      </form>

      <div class="card mb-3">
        <div class="card-header">Stare bază locală</div>
        <div class="card-body">
          <div class="row g-2">
            <div class="col-md-4">
              <div class="text-muted small">Fișier</div>
              <div class="small"><code><?= Html::e(wssc_vuln_db_path()) ?></code></div>
            </div>
            <div class="col-md-4">
              <div class="text-muted small">Generat la</div>
              <div><?= Html::e($generatedAt ?: '-') ?></div>
            </div>
            <div class="col-md-2">
              <div class="text-muted small">CMS entries</div>
              <div><?= Html::e((string)$cmsCount) ?></div>
            </div>
            <div class="col-md-2">
              <div class="text-muted small">CVE entries</div>
              <div><?= Html::e((string)$cvesCount) ?></div>
            </div>
          </div>
        </div>
      </div>

      <form method="post" class="card">
        <div class="card-header d-flex align-items-center justify-content-between">
          <span>Surse</span>
          <div class="d-flex gap-2">
            <button class="btn btn-outline-secondary btn-sm" type="button" id="selectAll">Bifează toate</button>
            <button class="btn btn-outline-secondary btn-sm" type="button" id="selectNone">Debifează toate</button>
          </div>
        </div>
        <div class="card-body">
          <input type="hidden" name="csrf_token" value="<?= Html::e($token) ?>">

          <div class="row g-3 mb-3">
            <div class="col-md-4">
              <label class="form-label small text-muted">Timeout (sec)</label>
              <input class="form-control" type="number" min="5" max="120" name="timeout_seconds" value="<?= Html::e((string)$timeoutSeconds) ?>">
            </div>
            <div class="col-md-4">
              <label class="form-label small text-muted">NVD: ultimele N zile</label>
              <input class="form-control" type="number" min="1" max="3650" name="nvd_last_days" value="<?= Html::e((string)$nvdLastDays) ?>">
            </div>
            <div class="col-md-4">
              <label class="form-label small text-muted">NVD: max rezultate</label>
              <input class="form-control" type="number" min="1" max="5000" name="nvd_max_results" value="<?= Html::e((string)$nvdMaxResults) ?>">
            </div>
            <div class="col-12">
              <label class="form-label small text-muted">NVD API key (opțional)</label>
              <input class="form-control" name="nvd_api_key" value="<?= Html::e((string)$nvdApiKey) ?>" autocomplete="off">
            </div>
            <div class="col-12 text-muted small">
              NVD are rate-limit. Dacă primești erori, micșorează numărul de rezultate sau intervalul de zile.
            </div>
          </div>

          <div class="list-group mb-3">
            <?php foreach (wssc_allowed_sources() as $s): ?>
              <?php
                $sid = (string)$s['id'];
                $checked = in_array($sid, $enabled, true);
              ?>
              <label class="list-group-item d-flex gap-3 align-items-start">
                <input class="form-check-input mt-1 srcChk" type="checkbox" name="sources[]" value="<?= Html::e($sid) ?>" <?= $checked ? 'checked' : '' ?>>
                <span class="flex-grow-1">
                  <div class="fw-semibold"><?= Html::e((string)$s['name']) ?></div>
                  <div class="text-muted small"><?= Html::e((string)$s['description']) ?></div>
                  <div class="small"><a href="<?= Html::e((string)$s['url']) ?>" target="_blank" rel="noopener">Sursă</a></div>
                </span>
              </label>
            <?php endforeach; ?>
          </div>

          <div class="d-flex gap-2 flex-wrap">
            <button class="btn btn-outline-primary" name="action" value="save" type="submit">Salvează selecția</button>
            <button class="btn btn-primary" name="action" value="save_and_update" type="submit">Salvează și actualizează vuln_db.json</button>
          </div>
        </div>
      </form>
    <?php endif; ?>
  </main>

  <script>
    (function () {
      const allBtn = document.getElementById('selectAll');
      const noneBtn = document.getElementById('selectNone');
      const boxes = () => Array.from(document.querySelectorAll('.srcChk'));
      allBtn?.addEventListener('click', () => boxes().forEach(b => b.checked = true));
      noneBtn?.addEventListener('click', () => boxes().forEach(b => b.checked = false));
    })();
  </script>
  <?= WSSC\footer_html($config) ?>
</body>
</html>
