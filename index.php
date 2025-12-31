<?php
declare(strict_types=1);

require __DIR__ . '/app/bootstrap.php';

use WSSC\Security\Csrf;
use WSSC\Security\DomainValidator;
use WSSC\Security\RateLimiter;
use WSSC\Storage\AuditLogger;
use WSSC\Storage\ScanRepository;
use WSSC\Util\Html;
use WSSC\Auth\Auth;

$config = WSSC\app_config();
$db = WSSC\db();

$audit = new AuditLogger($db);
$repo = new ScanRepository($db);
$csrf = new Csrf();
$rateLimiter = new RateLimiter($db, $config['security']['rate_limit']);
$auth = new Auth($db);

function wssc_page_title(string $title): string
{
    return 'WSSC - ' . $title;
}

function wssc_layout(string $title, string $bodyHtml, array $config): void
{
    echo '<!doctype html><html lang="ro"><head>';
    echo '<meta charset="utf-8">';
    echo '<meta name="viewport" content="width=device-width, initial-scale=1">';
    echo '<title>' . Html::e($title) . '</title>';
    if ($config['ui']['use_bootstrap_cdn']) {
        echo '<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">';
    }
    echo '<link rel="stylesheet" href="assets/css/app.css">';
    echo '</head><body>';

    echo \WSSC\navbar_html($config);

    echo '<main class="container my-4">' . $bodyHtml . '</main>';

    echo \WSSC\footer_html($config);

    echo '<script src="assets/js/app.js"></script>';
    echo '</body></html>';
}

$loginErrors = [];
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    try {
        $csrf->requireValidToken($_POST['csrf_token'] ?? null);
        $action = (string)$_POST['action'];
        if ($action === 'login') {
            $username = (string)($_POST['username'] ?? '');
            $pwd = (string)($_POST['password'] ?? '');
            $auth->login($username, $pwd);
        }
        if ($action === 'logout') {
            $auth->logout();
        }
    } catch (Throwable $e) {
        $loginErrors[] = $e->getMessage();
    }
}

if (isset($_GET['action']) && (string)$_GET['action'] === 'logout') {
    $auth->logout();
    header('Location: index.php');
    exit;
}

if (!$auth->isAuthenticated()) {
    $token = $csrf->getToken();
    $body = '<div class="row g-4"><div class="col-lg-6">';
    if ($loginErrors) {
        $body .= '<div class="alert alert-danger"><ul class="mb-0">';
        foreach ($loginErrors as $er) {
            $body .= '<li>' . Html::e($er) . '</li>';
        }
        $body .= '</ul></div>';
    }
    $body .= '<div class="card"><div class="card-header">Autentificare</div><div class="card-body">';
    $body .= '<form method="post" class="row g-2">';
    $body .= '<input type="hidden" name="csrf_token" value="' . Html::e($token) . '">';
    $body .= '<input type="hidden" name="action" value="login">';
    $body .= '<div class="col-md-4"><input class="form-control" name="username" placeholder="Username" required></div>';
    $body .= '<div class="col-md-5"><input class="form-control" type="password" name="password" placeholder="Parolă" required></div>';
    $body .= '<div class="col-md-3"><button class="btn btn-primary w-100" type="submit">Login</button></div>';
    $body .= '</form></div></div>';
    $body .= '</div></div>';
    wssc_layout(wssc_page_title('Autentificare'), $body, $config);
    exit;
}

$page = (string)($_GET['page'] ?? '');

if ($page === 'scan') {
    $scanId = (int)($_GET['id'] ?? 0);
    $scan = $scanId > 0 ? $repo->getById($scanId) : null;

    if (!$scan) {
        wssc_layout(wssc_page_title('Scanare'), '<div class="alert alert-danger">Scanare inexistentă.</div>', $config);
        exit;
    }

    $result = $scan['result_json'] ? json_decode($scan['result_json'], true) : null;
    $status = $scan['status'];
    $progress = (int)$scan['progress'];
    $token = $csrf->getToken();
    $captchaQuestion = null;
    if ($config['security']['captcha']['enabled']) {
        $captchaQuestion = WSSC\captcha()->newChallenge();
    }

    $body = '<div class="d-flex align-items-center justify-content-between mb-3">';
    $body .= '<h1 class="h4 mb-0">Rezultate: ' . Html::e($scan['domain']) . '</h1>';
    $body .= '<span class="badge bg-' . ($status === 'done' ? 'success' : ($status === 'error' ? 'danger' : 'secondary')) . '">'
        . Html::e(strtoupper($status)) . '</span>';
    $body .= '</div>';

    $body .= '<div class="card mb-3"><div class="card-header">Scanare nouă</div><div class="card-body">';
    $body .= '<form id="scanForm" method="post" autocomplete="off">';
    $body .= '<input type="hidden" name="csrf_token" value="' . Html::e($token) . '">';
    $body .= '<div class="row g-3">';
    $body .= '<div class="col-md-6">';
    $body .= '<label class="form-label">Domeniu</label>';
    $body .= '<input class="form-control" name="domain" placeholder="ex: sub.example.com" value="' . Html::e((string)$scan['domain']) . '" required>';
    $body .= '<div class="form-text">Scanează doar domenii pe care le deții sau ai permisiune explicită.</div>';
    $body .= '</div>';
    $body .= '<div class="col-md-4">';
    $body .= '<label class="form-label">Tip scanare</label>';
    $body .= '<select class="form-select" name="mode">';
    $body .= '<option value="quick">Rapidă</option>';
    $body .= '<option value="full">Completă</option>';
    $body .= '</select>';
    $body .= '</div>';
    $body .= '<div class="col-md-2 d-flex align-items-end">';
    $body .= '<button class="btn btn-primary w-100" type="submit">Pornește</button>';
    $body .= '</div>';
    $body .= '</div>';
    if ($captchaQuestion) {
        $body .= '<div class="row g-3 mt-0">';
        $body .= '<div class="col-md-6">';
        $body .= '<label class="form-label mt-3">CAPTCHA</label>';
        $body .= '<div class="d-flex gap-2 align-items-center">';
        $body .= '<div class="captcha-box">' . Html::e($captchaQuestion) . '</div>';
        $body .= '<input class="form-control" name="captcha_answer" placeholder="Răspuns" required>';
        $body .= '</div></div></div>';
    }
    $body .= '</form>';
    $body .= '<div id="scanRunner" class="card mt-3 d-none"><div class="card-body">';
    $body .= '<div class="d-flex align-items-center justify-content-between mb-2">';
    $body .= '<div class="fw-semibold">Scanare în progres</div>';
    $body .= '<div class="small text-muted" id="scanProgressText">0%</div>';
    $body .= '</div>';
    $body .= '<div class="progress" role="progressbar" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100">';
    $body .= '<div class="progress-bar" id="scanProgressBar" style="width:0%"></div>';
    $body .= '</div>';
    $body .= '<div class="small text-muted mt-2" id="scanStatusText">Inițializare...</div>';
    $body .= '</div></div>';
    $body .= '</div></div>';

    $body .= '<div class="card mb-3"><div class="card-body">';
    $body .= '<div class="row g-3">';
    $body .= '<div class="col-md-3"><div class="text-muted small">Mod</div><div>' . Html::e($scan['mode']) . '</div></div>';
    $body .= '<div class="col-md-3"><div class="text-muted small">IP țintă</div><div>' . Html::e($scan['resolved_ip'] ?? '-') . '</div></div>';
    $body .= '<div class="col-md-3"><div class="text-muted small">Creat</div><div>' . Html::e($scan['created_at']) . '</div></div>';
    $body .= '<div class="col-md-3"><div class="text-muted small">Finalizat</div><div>' . Html::e($scan['finished_at'] ?? '-') . '</div></div>';
    $body .= '</div>';
    $body .= '</div></div>';

    if ($status !== 'done') {
        $body .= '<div class="card mb-3"><div class="card-body">';
        $body .= '<div class="d-flex align-items-center justify-content-between mb-2">';
        $body .= '<div class="fw-semibold">Scanarea rulează</div>';
        $body .= '<div class="small text-muted">' . $progress . '%</div>';
        $body .= '</div>';
        $body .= '<div class="progress" role="progressbar" aria-valuenow="' . $progress . '" aria-valuemin="0" aria-valuemax="100">';
        $body .= '<div class="progress-bar" style="width:' . $progress . '%"></div>';
        $body .= '</div>';
        $body .= '<div class="small text-muted mt-2">Pagina se va actualiza automat.</div>';
        $body .= '<script>window.WSSC_AUTO_REFRESH_SCAN_ID=' . (int)$scanId . ';</script>';
        $body .= '</div></div>';
    }

    if ($status === 'error') {
        $body .= '<div class="alert alert-danger">Eroare: ' . Html::e((string)$scan['error_message']) . '</div>';
    }

    if (is_array($result)) {
        if (isset($result['tech']) && is_array($result['tech'])) {
            $tech = $result['tech'];
            $cmsName = (string)($tech['cms']['name'] ?? '');
            $cmsVer = (string)($tech['cms']['version'] ?? '');
            $phpVer = (string)($tech['php']['version_exposed'] ?? '');
            $webServer = (string)($tech['web_server'] ?? '');
            $js = isset($tech['js']) && is_array($tech['js']) ? $tech['js'] : [];
            $libs = isset($tech['libraries']) && is_array($tech['libraries']) ? $tech['libraries'] : [];

            $body .= '<div class="card mb-3"><div class="card-header">Tehnologii detectate</div><div class="card-body">';
            $body .= '<div class="row g-3">';
            $body .= '<div class="col-md-4"><div class="text-muted small">Web server</div><div>' . Html::e($webServer !== '' ? $webServer : '-') . '</div></div>';
            $body .= '<div class="col-md-4"><div class="text-muted small">PHP (expus)</div><div>' . Html::e($phpVer !== '' ? $phpVer : '-') . '</div></div>';
            $body .= '<div class="col-md-4"><div class="text-muted small">CMS</div><div>' . Html::e($cmsName !== '' ? ($cmsName . ($cmsVer !== '' ? ' ' . $cmsVer : '')) : '-') . '</div></div>';
            $body .= '</div>';

            $body .= '<div class="row g-3 mt-1">';
            $body .= '<div class="col-md-6"><div class="text-muted small mb-1">JS</div>';
            if ($js) {
                foreach ($js as $t) {
                    $body .= '<span class="badge bg-secondary me-1 mb-1">' . Html::e((string)$t) . '</span>';
                }
            } else {
                $body .= '<span class="text-muted">-</span>';
            }
            $body .= '</div>';
            $body .= '<div class="col-md-6"><div class="text-muted small mb-1">Librării</div>';
            if ($libs) {
                foreach ($libs as $t) {
                    $body .= '<span class="badge bg-secondary me-1 mb-1">' . Html::e((string)$t) . '</span>';
                }
            } else {
                $body .= '<span class="text-muted">-</span>';
            }
            $body .= '</div></div>';

            $body .= '</div></div>';
        }

        if (isset($result['ports']) && is_array($result['ports'])) {
            $body .= '<div class="card mb-3"><div class="card-header">Scanare porturi</div><div class="card-body">';
            $body .= '<div class="table-responsive"><table class="table table-sm mb-0">';
            $body .= '<thead><tr><th>Port</th><th>Status</th></tr></thead><tbody>';
            foreach ($result['ports'] as $p => $st) {
                $st = (string)$st;
                $badge = match ($st) {
                    'OPEN' => 'success',
                    'FILTERED' => 'warning',
                    default => 'secondary',
                };
                $body .= '<tr>';
                $body .= '<td>' . (int)$p . '</td>';
                $body .= '<td><span class="badge bg-' . $badge . '">' . Html::e($st) . '</span></td>';
                $body .= '</tr>';
            }
            $body .= '</tbody></table></div>';
            $body .= '</div></div>';
        }

        if (isset($result['tls']) && is_array($result['tls'])) {
            $tls = $result['tls'];
            $cert = $tls['cert'] ?? null;
            $protocols = $tls['protocols'] ?? null;

            $body .= '<div class="card mb-3"><div class="card-header">SSL/TLS</div><div class="card-body">';
            $body .= '<div class="row g-3">';
            if (is_array($cert)) {
                $vt = isset($cert['valid_to']) ? (int)$cert['valid_to'] : 0;
                $validTo = $vt > 0 ? gmdate('Y-m-d H:i:s', $vt) . ' UTC' : '-';
                $body .= '<div class="col-md-6"><div class="text-muted small">Expirare certificat</div><div>' . Html::e($validTo) . '</div></div>';
                $issuerArr = isset($cert['issuer']) && is_array($cert['issuer']) ? $cert['issuer'] : null;
                $issuerStr = '-';
                if (is_array($issuerArr)) {
                    $cn = '';
                    foreach (['CN', 'cn', 'commonName'] as $k) {
                        if (is_string($issuerArr[$k] ?? null) && $issuerArr[$k] !== '') {
                            $cn = (string)$issuerArr[$k];
                            break;
                        }
                    }
                    $org = '';
                    foreach (['O', 'o', 'organizationName'] as $k) {
                        if (is_string($issuerArr[$k] ?? null) && $issuerArr[$k] !== '') {
                            $org = (string)$issuerArr[$k];
                            break;
                        }
                    }
                    if ($cn !== '' && $org !== '') {
                        $issuerStr = $cn . ' (' . $org . ')';
                    } elseif ($cn !== '') {
                        $issuerStr = $cn;
                    } elseif ($org !== '') {
                        $issuerStr = $org;
                    } else {
                        $issuerStr = json_encode($issuerArr, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
                    }
                }
                $body .= '<div class="col-md-6"><div class="text-muted small">Issuer</div><div>' . Html::e($issuerStr) . '</div></div>';
            } else {
                $body .= '<div class="col-md-6"><div class="text-muted small">Certificat</div><div class="text-muted">-</div></div>';
                $body .= '<div class="col-md-6"><div class="text-muted small">Issuer</div><div class="text-muted">-</div></div>';
            }
            $body .= '<div class="col-md-6"><div class="text-muted small">Protocoale (detectate)</div>';
            if (is_array($protocols)) {
                foreach ($protocols as $k => $v) {
                    $v = (string)$v;
                    $badge = $v === 'SUPPORTED' ? 'success' : 'secondary';
                    $info = '';
                    if ($k === 'TLSv1.0') $info = 'Protocol legacy; vulnerabilități cunoscute. Dezactivează.';
                    if ($k === 'TLSv1.1') $info = 'Protocol legacy; dezavizat. Dezactivează.';
                    if ($k === 'TLSv1.2') $info = 'Standard acceptat; configurează ciphers moderne.';
                    if ($k === 'TLSv1.3') $info = 'Cea mai nouă versiune TLS; preferată.';
                    $best = 'https://cheatsheetseries.owasp.org/cheatsheets/TLS_Cipher_String_Cheat_Sheet.html';
                    $title = $info !== '' ? ($info . ' Vezi best practices.') : 'Protocol';
                    $body .= '<span class="badge bg-' . $badge . ' me-1 mb-1" data-bs-toggle="tooltip" title="' . Html::e($title) . '"><span class="me-1">' . Html::e((string)$k) . ':</span> ' . Html::e($v) . ' <a href="' . Html::e($best) . '" target="_blank" rel="noopener" class="text-decoration-underline text-reset">bp</a><span class="ms-1 text-muted" data-bs-toggle="tooltip" title="' . Html::e($title) . '">?</span></span>';
                }
            } else {
                $body .= '<span class="text-muted">-</span>';
            }
            $body .= '</div></div>';
            $body .= '</div></div>';
        }

        if (isset($result['exposures']) && is_array($result['exposures'])) {
            $body .= '<div class="card mb-3"><div class="card-header">Expuneri comune</div><div class="card-body">';
            $body .= '<div class="table-responsive"><table class="table table-sm mb-0">';
            $body .= '<thead><tr><th>Check</th><th>Status</th><th>URL</th></tr></thead><tbody>';
            foreach ($result['exposures'] as $k => $v) {
                $statusCode = is_array($v) ? (int)($v['status'] ?? 0) : 0;
                $url = is_array($v) ? (string)($v['url'] ?? '') : '';
                $badge = $statusCode === 200 ? 'warning' : 'secondary';
                $body .= '<tr>';
                $body .= '<td>' . Html::e((string)$k) . '</td>';
                $body .= '<td><span class="badge bg-' . $badge . '">' . Html::e((string)$statusCode) . '</span></td>';
                $body .= '<td class="small">' . Html::e($url !== '' ? $url : '-') . '</td>';
                $body .= '</tr>';
            }
            $body .= '</tbody></table></div>';
            $body .= '</div></div>';
        }
    }

        if ($result && isset($result['findings']) && is_array($result['findings'])) {
        $body .= '<div class="h5 mb-2">Vulnerabilități</div>';
            $counts = ['HIGH' => 0, 'MEDIUM' => 0, 'LOW' => 0, 'INFO' => 0];
            foreach ($result['findings'] as $f) {
                $sev = (string)($f['severity'] ?? 'INFO');
                if (!isset($counts[$sev])) {
                    $counts[$sev] = 0;
                }
                $counts[$sev]++;
            }

            $body .= '<div class="card mb-3"><div class="card-body">';
            $body .= '<div class="d-flex flex-wrap gap-2">';
            $body .= '<span class="badge bg-danger">HIGH: ' . $counts['HIGH'] . '</span>';
            $body .= '<span class="badge bg-warning text-dark">MEDIUM: ' . $counts['MEDIUM'] . '</span>';
            $body .= '<span class="badge bg-info text-dark">LOW: ' . $counts['LOW'] . '</span>';
            $body .= '<span class="badge bg-secondary">INFO: ' . $counts['INFO'] . '</span>';
            $body .= '</div>';
            $body .= '</div></div>';

            $body .= '<div class="accordion" id="findingsAccordion">';
            $idx = 0;
        foreach ($result['findings'] as $f) {
            $idx++;
            $fid = 'f' . $idx;
            $sev = (string)($f['severity'] ?? 'INFO');
            $cat = (string)($f['category'] ?? 'General');
            $title = (string)($f['title'] ?? 'Finding');
            $desc = (string)($f['description'] ?? '');
            $rec = (string)($f['recommendation'] ?? '');
            $evidence = $f['evidence'] ?? null;

            $sevClass = match ($sev) {
                'HIGH' => 'danger',
                'MEDIUM' => 'warning',
                'LOW' => 'info',
                default => 'secondary',
            };

            $body .= '<div class="accordion-item">';
            $body .= '<h2 class="accordion-header">';
            $body .= '<button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#' . $fid . '">';
            $body .= '<span class="badge bg-' . $sevClass . ' me-2">' . Html::e($sev) . '</span>';
            $body .= '<span class="text-muted me-2">[' . Html::e($cat) . ']</span>';
            $body .= Html::e($title);
            $body .= '</button></h2>';
            $body .= '<div id="' . $fid . '" class="accordion-collapse collapse" data-bs-parent="#findingsAccordion">';
            $body .= '<div class="accordion-body">';
            if ($desc !== '') {
                $body .= '<div class="mb-2">' . nl2br(Html::e($desc)) . '</div>';
            }
            if ($rec !== '') {
                $body .= '<div class="mb-2"><div class="fw-semibold">Recomandare</div><div>' . nl2br(Html::e($rec)) . '</div></div>';
            }
            if (is_array($evidence)) {
                $cve = is_string($evidence['cve'] ?? null) ? (string)$evidence['cve'] : '';
                $cveLink = is_string($evidence['cve_link'] ?? null) ? (string)$evidence['cve_link'] : '';
                $risk = is_string($evidence['risk'] ?? null) ? (string)$evidence['risk'] : '';
                $affected = is_string($evidence['affected'] ?? null) ? (string)$evidence['affected'] : '';
                $safe = is_string($evidence['recommended_safe'] ?? null) ? (string)$evidence['recommended_safe'] : '';
                $portNum = isset($evidence['port']) ? (int)$evidence['port'] : 0;
                $service = is_string($evidence['service'] ?? null) ? (string)$evidence['service'] : '';
                $best = is_string($evidence['best_practices'] ?? null) ? (string)$evidence['best_practices'] : '';

                $isHttps = static function (string $url): bool {
                    $p = parse_url($url);
                    return is_array($p) && strtolower((string)($p['scheme'] ?? '')) === 'https';
                };

                if ($cve !== '' || $risk !== '' || $affected !== '' || $safe !== '') {
                    $body .= '<div class="mt-3">';
                    $body .= '<div class="fw-semibold">Detalii</div>';
                    $body .= '<ul class="mb-0">';
                    if ($cve !== '') {
                        if ($cveLink !== '' && $isHttps($cveLink)) {
                            $body .= '<li><span class="text-muted">CVE:</span> <a href="' . Html::e($cveLink) . '" target="_blank" rel="noopener">' . Html::e($cve) . '</a></li>';
                        } else {
                            $body .= '<li><span class="text-muted">CVE:</span> ' . Html::e($cve) . '</li>';
                        }
                    }
                    if ($portNum > 0) {
                        $body .= '<li><span class="text-muted">Port:</span> ' . (int)$portNum . ($service !== '' ? (' (' . Html::e($service) . ')') : '') . '</li>';
                    }
                    if ($affected !== '') {
                        $body .= '<li><span class="text-muted">Interval afectat:</span> ' . Html::e($affected) . '</li>';
                    }
                    if ($safe !== '') {
                        $body .= '<li><span class="text-muted">Versiune recomandată:</span> ' . Html::e($safe) . '</li>';
                    }
                    if ($risk !== '') {
                        $body .= '<li><span class="text-muted">Risc:</span> ' . Html::e($risk) . '</li>';
                    }
                    if ($best !== '' && $isHttps($best)) {
                        $body .= '<li><span class="text-muted">Best practices:</span> <a href="' . Html::e($best) . '" target="_blank" rel="noopener">link</a></li>';
                    }
                    $body .= '</ul>';
                    $body .= '</div>';
                }
            }
            if ($evidence !== null) {
                $body .= '<details><summary class="small text-muted">Evidență</summary>';
                $body .= '<pre class="mt-2 mb-0 small code-block">' . Html::e(json_encode($evidence, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)) . '</pre>';
                $body .= '</details>';
            }
            $body .= '</div></div></div>';
        }
        $body .= '</div>';
    }

    if ($config['ui']['use_bootstrap_cdn']) {
        $body .= '<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script>';
        $body .= '<script>(function(){var t=document.querySelectorAll("[data-bs-toggle=tooltip]");t.forEach(function(el){new bootstrap.Tooltip(el);});})();</script>';
    }

    wssc_layout(wssc_page_title('Rezultate'), $body, $config);
    exit;
}

if ($page === 'history') {
    $domain = trim((string)($_GET['domain'] ?? ''));
    $scans = $repo->listRecentScans($domain !== '' ? $domain : null, 50);

    $body = '<div class="d-flex align-items-center justify-content-between mb-3">';
    $body .= '<h1 class="h4 mb-0">Istoric scanări</h1>';
    $body .= '</div>';

    $body .= '<form class="row g-2 mb-3" method="get">';
    $body .= '<input type="hidden" name="page" value="history">';
    $body .= '<div class="col-md-6"><input class="form-control" name="domain" placeholder="Filtru domeniu (ex: example.com)" value="' . Html::e($domain) . '"></div>';
    $body .= '<div class="col-md-2"><button class="btn btn-primary w-100" type="submit">Filtrează</button></div>';
    $body .= '<div class="col-md-2"><a class="btn btn-outline-secondary w-100" href="index.php?page=history">Reset</a></div>';
    $body .= '</form>';

    $body .= '<div class="card"><div class="table-responsive"><table class="table mb-0">';
    $body .= '<thead><tr><th>ID</th><th>Domeniu</th><th>Mod</th><th>Status</th><th>Creat</th><th></th></tr></thead><tbody>';
    foreach ($scans as $s) {
        $body .= '<tr>';
        $body .= '<td>' . (int)$s['id'] . '</td>';
        $body .= '<td>' . Html::e($s['domain']) . '</td>';
        $body .= '<td>' . Html::e($s['mode']) . '</td>';
        $body .= '<td>' . Html::e($s['status']) . ' (' . (int)$s['progress'] . '%)</td>';
        $body .= '<td>' . Html::e($s['created_at']) . '</td>';
        $body .= '<td class="text-end">';
        $body .= '<a class="btn btn-sm btn-outline-primary me-1" href="index.php?page=scan&id=' . (int)$s['id'] . '">Deschide</a>';
        $body .= '<a class="btn btn-sm btn-outline-secondary" href="index.php?domain=' . urlencode((string)$s['domain']) . '&mode=quick">Re-scan rapid</a>';
        $body .= '</td>';
        $body .= '</tr>';
    }
    if (!$scans) {
        $body .= '<tr><td colspan="6" class="text-muted">Nu există scanări salvate.</td></tr>';
    }
    $body .= '</tbody></table></div></div>';

    wssc_layout(wssc_page_title('Istoric'), $body, $config);
    exit;
}

if ($page === 'compare') {
    $a = (int)($_GET['a'] ?? 0);
    $b = (int)($_GET['b'] ?? 0);

    $body = '<div class="d-flex align-items-center justify-content-between mb-3">';
    $body .= '<h1 class="h4 mb-0">Comparare scanări</h1>';
    $body .= '</div>';

    $recent = $repo->listRecentScans(null, 50);
    $body .= '<form class="row g-2 mb-3" method="get">';
    $body .= '<input type="hidden" name="page" value="compare">';
    $body .= '<div class="col-md-5"><select class="form-select" name="a">';
    $body .= '<option value="0">Scanare A...</option>';
    foreach ($recent as $s) {
        $selected = $a === (int)$s['id'] ? ' selected' : '';
        $body .= '<option value="' . (int)$s['id'] . '"' . $selected . '>#' . (int)$s['id'] . ' - ' . Html::e($s['domain']) . ' (' . Html::e($s['created_at']) . ')</option>';
    }
    $body .= '</select></div>';
    $body .= '<div class="col-md-5"><select class="form-select" name="b">';
    $body .= '<option value="0">Scanare B...</option>';
    foreach ($recent as $s) {
        $selected = $b === (int)$s['id'] ? ' selected' : '';
        $body .= '<option value="' . (int)$s['id'] . '"' . $selected . '>#' . (int)$s['id'] . ' - ' . Html::e($s['domain']) . ' (' . Html::e($s['created_at']) . ')</option>';
    }
    $body .= '</select></div>';
    $body .= '<div class="col-md-2"><button class="btn btn-primary w-100" type="submit">Compară</button></div>';
    $body .= '</form>';

    if ($a > 0 && $b > 0 && $a !== $b) {
        $scanA = $repo->getById($a);
        $scanB = $repo->getById($b);
        if ($scanA && $scanB && $scanA['status'] === 'done' && $scanB['status'] === 'done') {
            $resA = json_decode((string)$scanA['result_json'], true);
            $resB = json_decode((string)$scanB['result_json'], true);

            $map = static function (array $res): array {
                $out = [];
                foreach (($res['findings'] ?? []) as $f) {
                    $key = (string)($f['id'] ?? ($f['category'] ?? '') . '|' . ($f['title'] ?? ''));
                    $out[$key] = $f;
                }
                return $out;
            };

            $fa = $map($resA ?? []);
            $fb = $map($resB ?? []);

            $new = array_diff_key($fb, $fa);
            $gone = array_diff_key($fa, $fb);

            $body .= '<div class="row g-3">';
            $body .= '<div class="col-md-6"><div class="card h-100"><div class="card-header">Noi în B (' . count($new) . ')</div><div class="card-body">';
            if ($new) {
                $body .= '<ul class="mb-0">';
                foreach ($new as $f) {
                    $body .= '<li><span class="badge bg-secondary me-2">' . Html::e((string)($f['severity'] ?? 'INFO')) . '</span>' . Html::e((string)($f['title'] ?? '')) . '</li>';
                }
                $body .= '</ul>';
            } else {
                $body .= '<div class="text-muted">Nicio problemă nouă.</div>';
            }
            $body .= '</div></div></div>';

            $body .= '<div class="col-md-6"><div class="card h-100"><div class="card-header">Rezolvate în B (' . count($gone) . ')</div><div class="card-body">';
            if ($gone) {
                $body .= '<ul class="mb-0">';
                foreach ($gone as $f) {
                    $body .= '<li><span class="badge bg-secondary me-2">' . Html::e((string)($f['severity'] ?? 'INFO')) . '</span>' . Html::e((string)($f['title'] ?? '')) . '</li>';
                }
                $body .= '</ul>';
            } else {
                $body .= '<div class="text-muted">Nicio problemă rezolvată.</div>';
            }
            $body .= '</div></div></div>';
            $body .= '</div>';
        } else {
            $body .= '<div class="alert alert-warning">Ambele scanări trebuie să fie finalizate (status DONE) pentru comparare.</div>';
        }
    }

    wssc_layout(wssc_page_title('Comparare'), $body, $config);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['domain'])) {
    $audit->log('dashboard_submit', ['ip' => $_SERVER['REMOTE_ADDR'] ?? null]);

    try {
        $csrf->requireValidToken($_POST['csrf_token'] ?? null);

        if ($config['security']['captcha']['enabled']) {
            $captchaOk = WSSC\captcha()->verify((string)($_POST['captcha_answer'] ?? ''));
            if (!$captchaOk) {
                throw new RuntimeException('CAPTCHA invalid.');
            }
        }

        $rateLimiter->hitOrThrow($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');

        $domainInput = (string)($_POST['domain'] ?? '');
        $mode = (string)($_POST['mode'] ?? 'quick');
        $mode = in_array($mode, ['quick', 'full'], true) ? $mode : 'quick';

        $validator = new DomainValidator();
        $target = $validator->validateAndResolve($domainInput);

        $scanId = $repo->createQueuedScan(
            domain: $target['domain'],
            ip: $target['ip'],
            mode: $mode,
            createdIp: (string)($_SERVER['REMOTE_ADDR'] ?? ''),
            sessionHash: WSSC\session_hash()
        );

        header('Location: index.php?page=scan&id=' . $scanId);
        exit;
    } catch (Throwable $e) {
        $error = $e->getMessage();
    }
}

$token = $csrf->getToken();
$captchaQuestion = null;
if ($config['security']['captcha']['enabled']) {
    $captchaQuestion = WSSC\captcha()->newChallenge();
}

$prefillDomain = trim((string)($_GET['domain'] ?? ''));
$prefillMode = (string)($_GET['mode'] ?? 'quick');
$prefillMode = in_array($prefillMode, ['quick', 'full'], true) ? $prefillMode : 'quick';

$body = '<div class="row g-4">';
$body .= '<div class="col-lg-7">';
$body .= '<h1 class="h4">Dashboard</h1>';
$body .= '<div class="text-muted mb-3">Scanare pasivă / semi-activă pentru audit informațional (fără exploit-uri).</div>';

if (isset($error) && $error !== '') {
    $body .= '<div class="alert alert-danger">' . Html::e($error) . '</div>';
}

$body .= '<div class="card"><div class="card-body">';
$body .= '<form id="scanForm" method="post" autocomplete="off">';
$body .= '<input type="hidden" name="csrf_token" value="' . Html::e($token) . '">';
$body .= '<div class="mb-3">';
$body .= '<label class="form-label">Domeniu</label>';
$body .= '<input class="form-control" name="domain" placeholder="ex: sub.example.com" value="' . Html::e($prefillDomain) . '" required>';
$body .= '<div class="form-text">Scanează doar domenii pe care le deții sau ai permisiune explicită.</div>';
$body .= '</div>';

$body .= '<div class="mb-3">';
$body .= '<label class="form-label">Tip scanare</label>';
$body .= '<select class="form-select" name="mode">';
$body .= '<option value="quick"' . ($prefillMode === 'quick' ? ' selected' : '') . '>Rapidă</option>';
$body .= '<option value="full"' . ($prefillMode === 'full' ? ' selected' : '') . '>Completă</option>';
$body .= '</select>';
$body .= '</div>';

if ($captchaQuestion) {
    $body .= '<div class="mb-3">';
    $body .= '<label class="form-label">CAPTCHA</label>';
    $body .= '<div class="d-flex gap-2 align-items-center">';
    $body .= '<div class="captcha-box">' . Html::e($captchaQuestion) . '</div>';
    $body .= '<input class="form-control" name="captcha_answer" placeholder="Răspuns" required>';
    $body .= '</div></div>';
}

$body .= '<button class="btn btn-primary" type="submit">Pornește scanarea</button>';
$body .= '</form>';
$body .= '</div></div>';

$body .= '<div id="scanRunner" class="card mt-3 d-none"><div class="card-body">';
$body .= '<div class="d-flex align-items-center justify-content-between mb-2">';
$body .= '<div class="fw-semibold">Scanare în progres</div>';
$body .= '<div class="small text-muted" id="scanProgressText">0%</div>';
$body .= '</div>';
$body .= '<div class="progress" role="progressbar" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100">';
$body .= '<div class="progress-bar" id="scanProgressBar" style="width:0%"></div>';
$body .= '</div>';
$body .= '<div class="small text-muted mt-2" id="scanStatusText">Inițializare...</div>';
$body .= '</div></div>';

$body .= '</div>';

$body .= '<div class="col-lg-5">';
$body .= '<div class="card"><div class="card-body">';
$body .= '<div class="fw-semibold mb-2">Ce verifică aplicația</div>';
$body .= '<ul class="mb-0">';
$body .= '<li>Porturi comune (OPEN/CLOSED/FILTERED)</li>';
$body .= '<li>Tehnologii utilizate (header + fingerprint)</li>';
$body .= '<li>SSL/TLS (certificat, protocoale slabe)</li>';
$body .= '<li>Security headers</li>';
$body .= '<li>Expuneri comune (robots.txt, .env, admin panels)</li>';
$body .= '</ul>';
$body .= '</div></div>';

$body .= '<div class="alert alert-warning mt-3 mb-0">';
$body .= '<span class="fw-semibold">' . Html::e($config['ui']['disclaimer_text']) . '</span>';
$body .= '</div>';
$body .= '</div>';
$body .= '</div>';

if ($config['ui']['use_bootstrap_cdn']) {
    $body .= '<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script>';
}

wssc_layout(wssc_page_title('Dashboard'), $body, $config);
