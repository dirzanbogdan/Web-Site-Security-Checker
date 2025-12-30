<?php
declare(strict_types=1);

require __DIR__ . '/../app/bootstrap.php';

use WSSC\Security\Csrf;
use WSSC\Security\DomainValidator;
use WSSC\Security\RateLimiter;
use WSSC\Scanner\DomainScanner;
use WSSC\Storage\AuditLogger;
use WSSC\Storage\ScanRepository;

header('Content-Type: application/json; charset=utf-8');

$config = WSSC\app_config();
$db = WSSC\db();

$csrf = new Csrf();
$repo = new ScanRepository($db);
$audit = new AuditLogger($db);
$rateLimiter = new RateLimiter($db, $config['security']['rate_limit']);
$scanner = new DomainScanner($config);

function wssc_json(int $statusCode, array $payload): void
{
    http_response_code($statusCode);
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

try {
    $action = (string)($_POST['action'] ?? $_GET['action'] ?? '');

    if ($action === 'create') {
        $csrf->requireValidToken($_POST['csrf_token'] ?? null);
        $rateLimiter->hitOrThrow($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');

        $domainInput = (string)($_POST['domain'] ?? '');
        $mode = (string)($_POST['mode'] ?? 'quick');
        $mode = in_array($mode, ['quick', 'full'], true) ? $mode : 'quick';

        if ($config['security']['captcha']['enabled']) {
            $captchaOk = WSSC\captcha()->verify((string)($_POST['captcha_answer'] ?? ''));
            if (!$captchaOk) {
                wssc_json(400, ['ok' => false, 'error' => 'CAPTCHA invalid.']);
            }
        }

        $validator = new DomainValidator();
        $target = $validator->validateAndResolve($domainInput);

        $scanId = $repo->createQueuedScan(
            domain: $target['domain'],
            ip: $target['ip'],
            mode: $mode,
            createdIp: (string)($_SERVER['REMOTE_ADDR'] ?? ''),
            sessionHash: WSSC\session_hash()
        );

        $audit->log('scan_create', ['scan_id' => $scanId, 'domain' => $target['domain'], 'mode' => $mode]);

        wssc_json(200, ['ok' => true, 'scan_id' => $scanId, 'redirect' => 'index.php?page=scan&id=' . $scanId]);
    }

    if ($action === 'run') {
        $csrf->requireValidToken($_POST['csrf_token'] ?? null);
        $scanId = (int)($_POST['scan_id'] ?? 0);
        if ($scanId <= 0) {
            wssc_json(400, ['ok' => false, 'error' => 'scan_id invalid.']);
        }

        $scan = $repo->getById($scanId);
        if (!$scan) {
            wssc_json(404, ['ok' => false, 'error' => 'Scanare inexistentă.']);
        }

        $requestIp = (string)($_SERVER['REMOTE_ADDR'] ?? '');
        if ($scan['created_ip'] !== '' && $requestIp !== '' && $scan['created_ip'] !== $requestIp) {
            wssc_json(403, ['ok' => false, 'error' => 'Acces interzis.']);
        }
        if ((string)$scan['session_hash'] !== WSSC\session_hash()) {
            wssc_json(403, ['ok' => false, 'error' => 'Sesiune invalidă.']);
        }

        if ($scan['status'] === 'done') {
            wssc_json(200, ['ok' => true, 'status' => 'done', 'progress' => 100]);
        }
        if ($scan['status'] === 'error') {
            wssc_json(200, ['ok' => true, 'status' => 'error', 'progress' => (int)$scan['progress'], 'error' => (string)$scan['error_message']]);
        }

        $updated = $scanner->runTimeboxed($repo, $scanId, 2.5);
        wssc_json(200, [
            'ok' => true,
            'status' => $updated['status'],
            'progress' => (int)$updated['progress'],
            'redirect' => 'index.php?page=scan&id=' . $scanId,
        ]);
    }

    if ($action === 'status') {
        $scanId = (int)($_GET['scan_id'] ?? 0);
        $scan = $scanId > 0 ? $repo->getById($scanId) : null;
        if (!$scan) {
            wssc_json(404, ['ok' => false, 'error' => 'Scanare inexistentă.']);
        }
        wssc_json(200, [
            'ok' => true,
            'status' => $scan['status'],
            'progress' => (int)$scan['progress'],
            'error' => $scan['error_message'],
        ]);
    }

    wssc_json(400, ['ok' => false, 'error' => 'Acțiune invalidă.']);
} catch (Throwable $e) {
    wssc_json(500, ['ok' => false, 'error' => $e->getMessage()]);
}

