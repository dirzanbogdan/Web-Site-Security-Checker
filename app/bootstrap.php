<?php
declare(strict_types=1);

namespace WSSC;

use PDO;
use RuntimeException;
use WSSC\Db\Db;
use WSSC\Security\Captcha;

/**
 * Bootstrap pentru Web Site Security Checker (WSSC).
 *
 * - Încarcă config-ul
 * - Inițializează sesiunea
 * - Configurează autoload pentru clasele din app/src
 */

const APP_ROOT = __DIR__ . '/..';

spl_autoload_register(static function (string $class): void {
    $prefix = 'WSSC\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }
    $relative = substr($class, strlen($prefix));
    $path = __DIR__ . '/src/' . str_replace('\\', '/', $relative) . '.php';
    if (is_file($path)) {
        require $path;
    }
});

ini_set('session.cookie_httponly', '1');
ini_set('session.use_strict_mode', '1');
ini_set('session.cookie_samesite', 'Lax');

if (!headers_sent()) {
    header('X-Powered-By:');
}

session_start();

/**
 * Încarcă configurația aplicației.
 * Pentru instalare pe cPanel: copiați config/config.sample.php în config/config.php și completați credențialele.
 */
function app_config(): array
{
    static $cfg = null;
    if (is_array($cfg)) {
        return $cfg;
    }

    $path = APP_ROOT . '/config/config.php';
    if (!is_file($path)) {
        $sample = APP_ROOT . '/config/config.sample.php';
        $msg = 'Lipsește config/config.php. Copiază config/config.sample.php în config/config.php și completează valorile.';
        if (PHP_SAPI !== 'cli' && !headers_sent()) {
            http_response_code(500);
            header('Content-Type: text/plain; charset=utf-8');
            echo $msg . PHP_EOL;
            echo 'Sample: ' . $sample . PHP_EOL;
            exit;
        }
        throw new RuntimeException($msg);
    }

    $cfg = require $path;
    if (!is_array($cfg)) {
        throw new RuntimeException('Config invalid: config/config.php trebuie să returneze un array.');
    }
    return $cfg;
}

/**
 * Returnează o instanță PDO, configurată pentru MySQL/MariaDB.
 */
function db(): PDO
{
    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }

    if (!class_exists(PDO::class)) {
        throw new RuntimeException('Extensia PHP "PDO" lipsește. Activează "pdo" și "pdo_mysql" în cPanel (Select PHP Version) sau contactează hosting-ul.');
    }
    if (!extension_loaded('pdo_mysql')) {
        throw new RuntimeException('Extensia PHP "pdo_mysql" lipsește. Activează driverul MySQL pentru PDO în cPanel (Select PHP Version) sau contactează hosting-ul.');
    }

    $cfg = app_config();
    $pdo = Db::connect($cfg['db']);
    return $pdo;
}

/**
 * Hash stabil pentru sesiunea curentă (folosit la "ownership" pentru job-uri de scanare).
 */
function session_hash(): string
{
    $sid = session_id();
    return hash('sha256', 'wssc:' . $sid);
}

/**
 * CAPTCHA simplu (opțional) pentru rate limiting / anti-abuz.
 */
function captcha(): Captcha
{
    static $c = null;
    if ($c instanceof Captcha) {
        return $c;
    }
    $cfg = app_config();
    $c = new Captcha($cfg['security']['captcha']);
    return $c;
}

function app_commit_short(): ?string
{
    $gitDir = APP_ROOT . '/.git';
    if (!is_dir($gitDir)) {
        return null;
    }

    $headPath = $gitDir . '/HEAD';
    $headRaw = @file_get_contents($headPath);
    if (!is_string($headRaw) || trim($headRaw) === '') {
        return null;
    }
    $head = trim($headRaw);

    $hash = '';
    if (str_starts_with($head, 'ref:')) {
        $ref = trim(substr($head, 4));
        $refPath = $gitDir . '/' . str_replace('/', '/', $ref);
        $refRaw = @file_get_contents($refPath);
        if (is_string($refRaw) && trim($refRaw) !== '') {
            $hash = trim($refRaw);
        } else {
            $packed = @file_get_contents($gitDir . '/packed-refs');
            if (is_string($packed) && $packed !== '') {
                foreach (preg_split('/\R/', $packed) ?: [] as $line) {
                    $line = trim((string)$line);
                    if ($line === '' || str_starts_with($line, '#') || str_starts_with($line, '^')) {
                        continue;
                    }
                    $parts = preg_split('/\s+/', $line);
                    if (!is_array($parts) || count($parts) < 2) {
                        continue;
                    }
                    if ((string)$parts[1] === $ref) {
                        $hash = (string)$parts[0];
                        break;
                    }
                }
            }
        }
    } else {
        $hash = $head;
    }

    if (!preg_match('/^[0-9a-f]{7,40}$/i', $hash)) {
        return null;
    }
    return substr(strtolower($hash), 0, 7);
}
