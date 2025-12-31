<?php
declare(strict_types=1);

require __DIR__ . '/../app/bootstrap.php';

use WSSC\Auth\Auth;
use WSSC\Util\Html;

$config = WSSC\app_config();

function wssc_exec_available(): bool
{
    if (!function_exists('shell_exec')) {
        return false;
    }
    $disabled = (string)ini_get('disable_functions');
    $disabledList = array_filter(array_map('trim', explode(',', $disabled)));
    return !in_array('shell_exec', $disabledList, true);
}

function wssc_run_cmd(string $cmd, string $cwd): array
{
    if (!wssc_exec_available()) {
        return ['ok' => false, 'out' => '', 'error' => 'Execuția de comenzi este dezactivată pe server.'];
    }
    $full = 'cd ' . escapeshellarg($cwd) . ' && ' . $cmd . ' 2>&1';
    $out = shell_exec($full);
    $out = is_string($out) ? $out : '';
    return ['ok' => true, 'out' => $out, 'error' => null];
}

function wssc_project_root(): string
{
    return realpath(__DIR__ . '/..') ?: (__DIR__ . '/..');
}

function wssc_recursive_zip_add(ZipArchive $zip, string $root, string $path, array $exclude): void
{
    $path = rtrim($path, DIRECTORY_SEPARATOR);
    $items = @scandir($path);
    if (!is_array($items)) {
        return;
    }

    foreach ($items as $it) {
        if ($it === '.' || $it === '..') {
            continue;
        }
        $full = $path . DIRECTORY_SEPARATOR . $it;
        $rel = ltrim(str_replace($root, '', $full), DIRECTORY_SEPARATOR);

        foreach ($exclude as $ex) {
            if ($rel === $ex || str_starts_with($rel, rtrim($ex, '/') . '/')) {
                continue 2;
            }
        }

        if (is_dir($full)) {
            $zip->addEmptyDir(str_replace('\\', '/', $rel));
            wssc_recursive_zip_add($zip, $root, $full, $exclude);
        } elseif (is_file($full)) {
            $zip->addFile($full, str_replace('\\', '/', $rel));
        }
    }
}

function wssc_dump_db(PDO $pdo): string
{
    $tables = ['users', 'scans', 'rate_limits', 'audit_log'];
    $out = [];
    $out[] = "SET NAMES utf8mb4;";
    $out[] = "SET FOREIGN_KEY_CHECKS=0;";

    foreach ($tables as $t) {
        $stmt = $pdo->query("SHOW CREATE TABLE `" . str_replace('`', '``', $t) . "`");
        $row = $stmt ? $stmt->fetch(PDO::FETCH_ASSOC) : null;
        if (!$row || !isset($row['Create Table'])) {
            continue;
        }
        $out[] = "DROP TABLE IF EXISTS `" . $t . "`;";
        $out[] = $row['Create Table'] . ";";

        $rows = $pdo->query("SELECT * FROM `" . $t . "`");
        if (!$rows) {
            continue;
        }
        while ($r = $rows->fetch(PDO::FETCH_ASSOC)) {
            $cols = array_keys($r);
            $vals = [];
            foreach ($cols as $c) {
                $v = $r[$c];
                if ($v === null) {
                    $vals[] = "NULL";
                } elseif (is_int($v) || is_float($v)) {
                    $vals[] = (string)$v;
                } else {
                    $vals[] = $pdo->quote((string)$v);
                }
            }
            $out[] = "INSERT INTO `" . $t . "` (`" . implode('`,`', $cols) . "`) VALUES (" . implode(',', $vals) . ");";
        }
    }

    $out[] = "SET FOREIGN_KEY_CHECKS=1;";
    return implode("\n", $out) . "\n";
}

function wssc_last_backup(string $dir): ?array
{
    if (!is_dir($dir)) {
        return null;
    }
    $files = glob(rtrim($dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . '*.zip');
    if (!is_array($files) || !$files) {
        return null;
    }
    usort($files, static fn($a, $b) => filemtime($b) <=> filemtime($a));
    $path = $files[0];
    return [
        'name' => basename($path),
        'path' => $path,
        'mtime' => filemtime($path) ?: null,
        'size' => filesize($path) ?: null,
    ];
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

if (!wssc_is_ip_allowed($config)) {
    http_response_code(403);
    echo 'Acces interzis (IP neautorizat).';
    exit;
}

$errors = [];
$messages = [];
$root = wssc_project_root();
$baseUrl = (string)($config['app']['base_url'] ?? '');
$csrf = (new WSSC\Security\Csrf())->getToken();
$auth = new Auth(WSSC\db());

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        (new WSSC\Security\Csrf())->requireValidToken($_POST['csrf_token'] ?? null);
        $action = (string)($_POST['action'] ?? '');

        if ($action === 'login') {
            $username = (string)($_POST['username'] ?? '');
            $pwd = (string)($_POST['password'] ?? '');
            $auth->login($username, $pwd);
            if ($auth->role() !== 'administrator') {
                $auth->logout();
                throw new RuntimeException('Acces interzis.');
            }
            $messages[] = 'Autentificare reușită.';
        }

        if ($action === 'logout') {
            $auth->logout();
            $messages[] = 'Delogat.';
        }

        if (!in_array($action, ['login', 'logout'], true)) {
            $auth->requireRole('administrator');
        }

        if ($action === 'git_update') {
            $branch = trim((string)($_POST['branch'] ?? ''));
            $branch = $branch !== '' ? $branch : (string)($config['admin']['default_update_branch'] ?? 'main');
            if (!preg_match('/^[a-zA-Z0-9._\\/-]+$/', $branch)) {
                throw new RuntimeException('Branch invalid.');
            }

            $fetch = wssc_run_cmd('git fetch --all --prune', $root);
            $pull = wssc_run_cmd('git pull --ff-only origin ' . escapeshellarg($branch), $root);
            $messages[] = 'Git fetch output: ' . trim($fetch['out']);
            $messages[] = 'Git pull output: ' . trim($pull['out']);
        }

        if ($action === 'backup_download' || $action === 'backup_server') {
            if (!class_exists(ZipArchive::class)) {
                throw new RuntimeException('Extensia PHP "zip" nu este disponibilă (ZipArchive).');
            }
            $includeConfig = (string)($_POST['include_config'] ?? '') === '1';
            $backupDir = trim((string)($_POST['backup_dir'] ?? ($root . DIRECTORY_SEPARATOR . 'backups')));
            $backupDir = $backupDir !== '' ? $backupDir : ($root . DIRECTORY_SEPARATOR . 'backups');

            $realBackupDir = realpath($backupDir);
            $realRoot = realpath($root) ?: $root;
            if ($action === 'backup_server') {
                if ($realBackupDir === false) {
                    if (!@mkdir($backupDir, 0755, true) && !is_dir($backupDir)) {
                        throw new RuntimeException('Nu se poate crea folderul de backup pe server.');
                    }
                    $realBackupDir = realpath($backupDir);
                }
                if (!is_string($realBackupDir) || !str_starts_with($realBackupDir, $realRoot)) {
                    throw new RuntimeException('backup_dir trebuie să fie în interiorul proiectului.');
                }
                $ht = $realBackupDir . DIRECTORY_SEPARATOR . '.htaccess';
                if (!is_file($ht)) {
                    @file_put_contents($ht, "Options -Indexes\nDeny from all\n", LOCK_EX);
                }
            }

            $name = 'wssc_backup_' . gmdate('Ymd_His') . '.zip';

            if ($action === 'backup_download') {
                $tmp = tempnam(sys_get_temp_dir(), 'wssc_');
                if (!is_string($tmp)) {
                    throw new RuntimeException('Nu se poate crea fișier temporar.');
                }
                $zipPath = $tmp . '.zip';
                @unlink($tmp);
            } else {
                $zipPath = rtrim((string)$realBackupDir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $name;
            }

            $zip = new ZipArchive();
            if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
                throw new RuntimeException('Nu se poate crea arhiva ZIP.');
            }

            $exclude = ['.git', 'install', 'backups', 'vendor', 'node_modules'];
            if (!$includeConfig) {
                $exclude[] = 'config/config.php';
            }

            wssc_recursive_zip_add($zip, $realRoot, $realRoot, $exclude);

            try {
                $pdo = WSSC\db();
                $zip->addFromString('backup/db.sql', wssc_dump_db($pdo));
            } catch (Throwable $e) {
                $zip->addFromString('backup/db_error.txt', $e->getMessage() . "\n");
            }

            $zip->close();

            if ($action === 'backup_download') {
                header('Content-Type: application/zip');
                header('Content-Disposition: attachment; filename="' . $name . '"');
                header('Content-Length: ' . (string)filesize($zipPath));
                readfile($zipPath);
                @unlink($zipPath);
                exit;
            }

            $messages[] = 'Backup creat pe server: ' . $zipPath;
        }
    } catch (Throwable $e) {
        $errors[] = $e->getMessage();
    }
}

$authed = $auth->isAuthenticated() && $auth->role() === 'administrator';
$authedUser = $authed ? ($auth->username() ?? '') : '';

$info = [
    'exec' => wssc_exec_available() ? 'ENABLED' : 'DISABLED',
    'branch' => null,
    'commit' => null,
    'version' => is_string($config['app']['version'] ?? null) ? (string)$config['app']['version'] : null,
    'remote_main' => null,
    'update_available' => false,
    'behind_commits' => 0,
];

if (wssc_exec_available()) {
    $info['branch'] = trim((string)(wssc_run_cmd('git rev-parse --abbrev-ref HEAD', $root)['out'] ?? ''));
    $info['commit'] = trim((string)(wssc_run_cmd('git rev-parse --short HEAD', $root)['out'] ?? ''));
    $gitVersion = trim((string)(wssc_run_cmd('git describe --tags --always --dirty', $root)['out'] ?? ''));
    if ($gitVersion !== '') {
        $info['version'] = $gitVersion;
    }
    $info['remote_main'] = trim((string)(wssc_run_cmd('git remote -v', $root)['out'] ?? ''));
    wssc_run_cmd('git fetch --all --prune', $root);
    $status = (string)(wssc_run_cmd('git status -uno', $root)['out'] ?? '');
    if ($status !== '') {
        if (preg_match('/behind(?:.*)? by (\d+) commit/i', $status, $m)) {
            $info['behind_commits'] = (int)$m[1];
            if ($info['behind_commits'] > 0) {
                $info['update_available'] = true;
            }
        }
    }
}

$serverBackupDir = $root . DIRECTORY_SEPARATOR . 'backups';
$last = wssc_last_backup($serverBackupDir);

?>
<!doctype html>
<html lang="ro">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title><?= Html::e('WSSC - Update & Backup') ?></title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
  <?= WSSC\navbar_html($config) ?>

  <main class="container my-4">
    <div class="d-flex align-items-center justify-content-between mb-3">
      <h1 class="h4 mb-0">Update & Backup</h1>
      <div class="text-end">
        <span class="small text-muted me-2">Exec:</span>
        <?php if ($info['exec'] === 'ENABLED'): ?>
          <span class="badge bg-success">status: Enabled</span>
        <?php else: ?>
          <span class="badge bg-danger">status: Disabled</span>
        <?php endif; ?>
      </div>
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
            <input type="hidden" name="csrf_token" value="<?= Html::e($csrf) ?>">
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
        <input type="hidden" name="csrf_token" value="<?= Html::e($csrf) ?>">
        <input type="hidden" name="action" value="logout">
        <div class="d-flex align-items-center gap-2">
          <span class="small text-muted">Autentificat: <?= Html::e($authedUser) ?></span>
          <button class="btn btn-outline-secondary btn-sm" type="submit">Logout</button>
        </div>
      </form>

      <div class="row g-3">
        <div class="col-lg-6">
            <div class="card h-100">
              <div class="card-header">Git</div>
              <div class="card-body">
              <?php if ($info['update_available']): ?>
                <div class="alert alert-warning">
                  <div class="fw-semibold mb-1">Exista o noua versiune! Va rog faceti update!</div>
                  <div class="small text-muted">Branch <?= Html::e($info['branch'] ?: '-') ?> este in urma cu <?= Html::e((string)$info['behind_commits']) ?> commit-uri fata de origin.</div>
                </div>
              <?php endif; ?>
                <div class="row g-2">
                  <div class="col-6">
                    <div class="text-muted small">Versiune</div>
                    <div><?= Html::e($info['version'] ?: '-') ?></div>
                  </div>
                <div class="col-6">
                  <div class="text-muted small">Branch curent</div>
                  <div><?= Html::e($info['branch'] ?: '-') ?></div>
                </div>
                <div class="col-6">
                  <div class="text-muted small">Commit</div>
                  <div><?= Html::e($info['commit'] ?: '-') ?></div>
                </div>
                <div class="col-12">
                  <div class="text-muted small">Remote</div>
                  <pre class="small mb-0"><?= Html::e($info['remote_main'] ?: '-') ?></pre>
                </div>
              </div>

              <hr>

              <form method="post" class="row g-2">
                <input type="hidden" name="csrf_token" value="<?= Html::e($csrf) ?>">
                <input type="hidden" name="action" value="git_update">
                <div class="col-md-8">
                  <label class="form-label small text-muted">Update branch</label>
                  <input class="form-control" name="branch" value="<?= Html::e((string)($config['admin']['default_update_branch'] ?? 'main')) ?>">
                </div>
                <div class="col-md-4 d-flex align-items-end">
                  <button class="btn btn-warning w-100" type="submit">Git pull</button>
                </div>
                <div class="col-12 text-muted small">
                  Rulează <code>git fetch</code> și <code>git pull --ff-only origin &lt;branch&gt;</code>. Dacă exec este dezactivat, fă update manual prin SSH/Terminal.
                </div>
              </form>
            </div>
          </div>
        </div>

        <div class="col-lg-6">
          <div class="card h-100">
            <div class="card-header">Backup</div>
            <div class="card-body">
              <div class="mb-3">
                <div class="text-muted small">Ultimul backup (server)</div>
                <?php if ($last): ?>
                  <div class="d-flex flex-wrap gap-2 align-items-center">
                    <span class="badge bg-secondary"><?= Html::e($last['name']) ?></span>
                    <span class="text-muted small"><?= Html::e($last['mtime'] ? date('Y-m-d H:i:s', (int)$last['mtime']) : '-') ?></span>
                    <span class="text-muted small"><?= Html::e($last['size'] ? number_format(((int)$last['size']) / (1024 * 1024), 2) . ' MB' : '-') ?></span>
                  </div>
                <?php else: ?>
                  <div class="text-muted">Niciun backup găsit în <?= Html::e($serverBackupDir) ?></div>
                <?php endif; ?>
              </div>

              <form method="post" class="row g-2 mb-2">
                <input type="hidden" name="csrf_token" value="<?= Html::e($csrf) ?>">
                <input type="hidden" name="action" value="backup_download">
                <div class="col-12">
                  <div class="form-check">
                    <input class="form-check-input" type="checkbox" name="include_config" value="1" id="cfgDl">
                    <label class="form-check-label" for="cfgDl">Include config/config.php în backup</label>
                  </div>
                </div>
                <div class="col-12">
                  <button class="btn btn-primary w-100" type="submit">Backup & Download (laptop)</button>
                </div>
              </form>

              <form method="post" class="row g-2">
                <input type="hidden" name="csrf_token" value="<?= Html::e($csrf) ?>">
                <input type="hidden" name="action" value="backup_server">
                <div class="col-12">
                  <label class="form-label small text-muted">Folder backup pe server (în proiect)</label>
                  <input class="form-control" name="backup_dir" value="<?= Html::e($serverBackupDir) ?>">
                </div>
                <div class="col-12">
                  <div class="form-check">
                    <input class="form-check-input" type="checkbox" name="include_config" value="1" id="cfgSrv">
                    <label class="form-check-label" for="cfgSrv">Include config/config.php în backup</label>
                  </div>
                </div>
                <div class="col-12">
                  <button class="btn btn-outline-primary w-100" type="submit">Backup pe server</button>
                </div>
                <div class="col-12 text-muted small">
                  Backup-ul include fișierele proiectului (fără <code>install</code>, <code>.git</code>, <code>backups</code>) și un dump SQL în <code>backup/db.sql</code>.
                </div>
              </form>
            </div>
          </div>
        </div>
      </div>
    <?php endif; ?>
  </main>
  <?= WSSC\footer_html($config) ?>
</body>
</html>
