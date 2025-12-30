<?php
declare(strict_types=1);

session_start();

function wssc_e(string $s): string
{
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function wssc_token(): string
{
    if (!isset($_SESSION['wssc_install_csrf']) || !is_string($_SESSION['wssc_install_csrf'])) {
        $_SESSION['wssc_install_csrf'] = bin2hex(random_bytes(32));
    }
    return (string)$_SESSION['wssc_install_csrf'];
}

function wssc_require_token(?string $t): void
{
    $exp = wssc_token();
    if (!is_string($t) || $t === '' || !hash_equals($exp, $t)) {
        throw new RuntimeException('CSRF token invalid.');
    }
}

function wssc_project_root(): string
{
    return realpath(__DIR__ . '/..') ?: (__DIR__ . '/..');
}

function wssc_path_join(string ...$parts): string
{
    $out = array_shift($parts) ?? '';
    foreach ($parts as $p) {
        $out = rtrim($out, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . ltrim($p, DIRECTORY_SEPARATOR);
    }
    return $out;
}

function wssc_recursive_delete(string $path): void
{
    if (!file_exists($path)) {
        return;
    }
    if (is_file($path) || is_link($path)) {
        @unlink($path);
        return;
    }
    $items = @scandir($path);
    if (!is_array($items)) {
        return;
    }
    foreach ($items as $it) {
        if ($it === '.' || $it === '..') {
            continue;
        }
        wssc_recursive_delete($path . DIRECTORY_SEPARATOR . $it);
    }
    @rmdir($path);
}

function wssc_mysql_connect(string $host, int $port, string $user, string $pass): mysqli
{
    $mysqli = @new mysqli($host, $user, $pass, '', $port);
    if ($mysqli->connect_errno) {
        throw new RuntimeException('Conexiune MySQL eșuată: ' . $mysqli->connect_error);
    }
    $mysqli->set_charset('utf8mb4');
    return $mysqli;
}

function wssc_mysql_exec(mysqli $db, string $sql): void
{
    if (!$db->query($sql)) {
        throw new RuntimeException('SQL error: ' . $db->error);
    }
}

function wssc_import_schema(mysqli $db, string $schemaPath): void
{
    $sql = file_get_contents($schemaPath);
    if (!is_string($sql) || $sql === '') {
        throw new RuntimeException('Nu se poate citi schema SQL.');
    }
    if (!$db->multi_query($sql)) {
        throw new RuntimeException('Import schema eșuat: ' . $db->error);
    }
    do {
        $res = $db->store_result();
        if ($res instanceof mysqli_result) {
            $res->free();
        }
    } while ($db->more_results() && $db->next_result());
}

function wssc_write_config(string $configPath, array $cfg): void
{
    $export = var_export($cfg, true);
    $php = "<?php\n"
        . "declare(strict_types=1);\n\n"
        . "return " . $export . ";\n";

    $dir = dirname($configPath);
    if (!is_dir($dir)) {
        if (!@mkdir($dir, 0755, true) && !is_dir($dir)) {
            throw new RuntimeException('Nu se poate crea folderul config.');
        }
    }
    if (@file_put_contents($configPath, $php, LOCK_EX) === false) {
        throw new RuntimeException('Nu se poate scrie config/config.php (permisiuni).');
    }
}

function wssc_is_exec_available(): bool
{
    if (!function_exists('shell_exec')) {
        return false;
    }
    $disabled = (string)ini_get('disable_functions');
    $disabledList = array_filter(array_map('trim', explode(',', $disabled)));
    return !in_array('shell_exec', $disabledList, true);
}

$root = wssc_project_root();
$defaultBaseUrl = 'https://sec.e-bm.eu/WSSC';
$errors = [];
$success = null;
$action = (string)($_POST['action'] ?? '');

try {
    if ($action === 'delete_install') {
        wssc_require_token($_POST['csrf_token'] ?? null);
        wssc_recursive_delete(__DIR__);
        header('Location: ' . $defaultBaseUrl);
        exit;
    }

    if ($action === 'install') {
        wssc_require_token($_POST['csrf_token'] ?? null);

        $baseUrl = trim((string)($_POST['base_url'] ?? $defaultBaseUrl));
        $baseUrl = $baseUrl !== '' ? $baseUrl : $defaultBaseUrl;

        $mysqlHost = trim((string)($_POST['mysql_host'] ?? 'localhost'));
        $mysqlPort = (int)($_POST['mysql_port'] ?? 3306);

        $adminUser = (string)($_POST['mysql_admin_user'] ?? '');
        $adminPass = (string)($_POST['mysql_admin_pass'] ?? '');

        $dbName = trim((string)($_POST['db_name'] ?? ''));
        $appUser = trim((string)($_POST['db_user'] ?? ''));
        $appPass = (string)($_POST['db_pass'] ?? '');
        $appUserHost = trim((string)($_POST['db_user_host'] ?? 'localhost'));
        $createDb = (string)($_POST['create_db'] ?? '') === '1';

        $adminUsername = trim((string)($_POST['admin_username'] ?? 'admin'));
        $adminPassword = (string)($_POST['admin_password'] ?? '');
        if ($adminUsername === '' || !preg_match('/^[a-zA-Z0-9._-]{3,64}$/', $adminUsername)) {
            throw new RuntimeException('Username admin invalid (3-64, litere/cifre/._-).');
        }
        if ($adminPassword === '' || strlen($adminPassword) < 10) {
            throw new RuntimeException('Parola admin trebuie să aibă minim 10 caractere.');
        }

        if ($dbName === '' || $appUser === '' || $appPass === '') {
            throw new RuntimeException('DB name/user/pass sunt obligatorii.');
        }
        if (!preg_match('/^[a-zA-Z0-9_]+$/', $dbName)) {
            throw new RuntimeException('DB name invalid (folosește doar litere/cifre/_).');
        }
        if (!preg_match('/^[a-zA-Z0-9_]+$/', $appUser)) {
            throw new RuntimeException('DB user invalid (folosește doar litere/cifre/_).');
        }

        if (!is_dir(wssc_path_join($root, 'config'))) {
            @mkdir(wssc_path_join($root, 'config'), 0755, true);
        }
        $configPath = wssc_path_join($root, 'config', 'config.php');
        if (file_exists($configPath)) {
            throw new RuntimeException('config/config.php există deja. Șterge-l sau editează-l manual.');
        }

        if ($createDb) {
            if ($adminUser === '' || $adminPass === '') {
                throw new RuntimeException('Pentru creare DB/user, completează contul MySQL cu privilegii de creare.');
            }
            $admin = wssc_mysql_connect($mysqlHost, $mysqlPort, $adminUser, $adminPass);

            $safeDb = '`' . str_replace('`', '``', $dbName) . '`';
            wssc_mysql_exec($admin, 'CREATE DATABASE IF NOT EXISTS ' . $safeDb . ' CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci');

            $userSql = "'" . $admin->real_escape_string($appUser) . "'";
            $hostSql = "'" . $admin->real_escape_string($appUserHost !== '' ? $appUserHost : 'localhost') . "'";
            $passSql = "'" . $admin->real_escape_string($appPass) . "'";

            wssc_mysql_exec($admin, 'CREATE USER IF NOT EXISTS ' . $userSql . '@' . $hostSql . ' IDENTIFIED BY ' . $passSql);
            wssc_mysql_exec($admin, 'GRANT ALL PRIVILEGES ON ' . $safeDb . '.* TO ' . $userSql . '@' . $hostSql);
            wssc_mysql_exec($admin, 'FLUSH PRIVILEGES');
            $admin->close();
        }

        $appDb = @new mysqli($mysqlHost, $appUser, $appPass, $dbName, $mysqlPort);
        if ($appDb->connect_errno) {
            throw new RuntimeException('Conectare cu user-ul aplicației eșuată: ' . $appDb->connect_error);
        }
        $appDb->set_charset('utf8mb4');

        $schemaPath = wssc_path_join($root, 'sql', 'schema.sql');
        wssc_import_schema($appDb, $schemaPath);

        $hash = password_hash($adminPassword, PASSWORD_DEFAULT);
        if (!is_string($hash) || $hash === '') {
            throw new RuntimeException('Nu se poate genera hash-ul parolei.');
        }

        $stmt = $appDb->prepare('INSERT INTO users (username, password_hash, role, is_disabled, created_at) VALUES (?, ?, "administrator", 0, NOW())');
        if (!$stmt) {
            throw new RuntimeException('Nu se poate pregăti INSERT users.');
        }
        $stmt->bind_param('ss', $adminUsername, $hash);
        if (!$stmt->execute()) {
            throw new RuntimeException('Creare user admin eșuată: ' . $stmt->error);
        }
        $stmt->close();
        $appDb->close();

        $cfg = [
            'app' => [
                'name' => 'Web Site Security Checker',
                'short_name' => 'WSSC',
                'version' => '1.0.20251230',
                'base_url' => $baseUrl,
            ],
            'db' => [
                'host' => $mysqlHost,
                'port' => $mysqlPort,
                'dbname' => $dbName,
                'user' => $appUser,
                'pass' => $appPass,
                'charset' => 'utf8mb4',
            ],
            'scan' => [
                'http_timeout_seconds' => 10,
                'tls_timeout_seconds' => 8,
                'port_timeout_seconds' => 0.7,
                'http_max_body_bytes' => 200000,
                'ports_common' => [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 8080],
            ],
            'security' => [
                'rate_limit' => [
                    'enabled' => true,
                    'window_seconds' => 60,
                    'max_requests' => 10,
                ],
                'captcha' => [
                    'enabled' => false,
                ],
            ],
            'admin' => [
                'update_allowed_ips' => [],
                'default_update_branch' => 'main',
            ],
            'ui' => [
                'use_bootstrap_cdn' => true,
                'disclaimer_text' => '„Scanați doar domenii pe care le dețineți sau aveți permisiune explicită.”',
            ],
        ];

        wssc_write_config($configPath, $cfg);

        $success = [
            'base_url' => $baseUrl,
            'config_path' => $configPath,
            'exec_available' => wssc_is_exec_available(),
        ];
    }
} catch (Throwable $e) {
    $errors[] = $e->getMessage();
}

$checks = [
    'PHP >= 8.4' => version_compare(PHP_VERSION, '8.4.0', '>='),
    'Extensii: mysqli' => extension_loaded('mysqli'),
    'Extensii: curl' => extension_loaded('curl'),
    'Extensii: openssl' => extension_loaded('openssl'),
];

?>
<!doctype html>
<html lang="ro">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>WSSC - First Use</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
  <div class="container my-4">
    <div class="d-flex align-items-center justify-content-between mb-3">
      <h1 class="h4 mb-0">WSSC - First Use</h1>
      <span class="badge bg-secondary">Installer</span>
    </div>

    <div class="alert alert-warning">
      Folosește acest installer doar o singură dată. După configurare, șterge folderul <code>install</code>.
    </div>

    <?php if ($errors): ?>
      <div class="alert alert-danger">
        <div class="fw-semibold mb-1">Eroare</div>
        <ul class="mb-0">
          <?php foreach ($errors as $er): ?>
            <li><?= wssc_e($er) ?></li>
          <?php endforeach; ?>
        </ul>
      </div>
    <?php endif; ?>

    <?php if (is_array($success)): ?>
      <div class="alert alert-success">
        <div class="fw-semibold">Configurare finalizată</div>
        <div class="small">config/config.php a fost creat. Poți accesa aplicația la: <a href="<?= wssc_e($success['base_url']) ?>"><?= wssc_e($success['base_url']) ?></a></div>
        <?php if (!$success['exec_available']): ?>
          <div class="small mt-2">Notă: execuția de comenzi (git/mysqldump) pare dezactivată; pagina de update va afișa instrucțiuni manuale.</div>
        <?php endif; ?>
      </div>

      <div class="card mb-3">
        <div class="card-header">Ștergere folder install</div>
        <div class="card-body">
          <form method="post" class="d-flex flex-column flex-md-row gap-2">
            <input type="hidden" name="csrf_token" value="<?= wssc_e(wssc_token()) ?>">
            <input type="hidden" name="action" value="delete_install">
            <button class="btn btn-danger" type="submit">Șterge automat folderul install</button>
            <a class="btn btn-outline-secondary" href="<?= wssc_e($success['base_url']) ?>">Deschide aplicația</a>
          </form>
          <div class="text-muted small mt-2">
            Dacă ștergerea automată eșuează, șterge manual folderul <code>install</code> din File Manager / FTP.
          </div>
        </div>
      </div>
    <?php endif; ?>

    <div class="card mb-3">
      <div class="card-header">Verificări server</div>
      <div class="card-body">
        <div class="row g-2">
          <?php foreach ($checks as $label => $ok): ?>
            <div class="col-md-6">
              <div class="d-flex align-items-center justify-content-between border rounded p-2 bg-white">
                <div><?= wssc_e($label) ?></div>
                <span class="badge bg-<?= $ok ? 'success' : 'danger' ?>"><?= $ok ? 'OK' : 'LIPSEȘTE' ?></span>
              </div>
            </div>
          <?php endforeach; ?>
        </div>
      </div>
    </div>

    <?php if (!is_array($success)): ?>
      <form method="post" class="card">
        <div class="card-header">Configurare</div>
        <div class="card-body">
          <input type="hidden" name="csrf_token" value="<?= wssc_e(wssc_token()) ?>">
          <input type="hidden" name="action" value="install">

          <div class="row g-3">
            <div class="col-12">
              <label class="form-label">Base URL</label>
              <input class="form-control" name="base_url" value="<?= wssc_e($defaultBaseUrl) ?>" required>
            </div>

            <div class="col-md-6">
              <label class="form-label">MySQL host</label>
              <input class="form-control" name="mysql_host" value="localhost" required>
            </div>
            <div class="col-md-6">
              <label class="form-label">MySQL port</label>
              <input class="form-control" name="mysql_port" value="3306" required>
            </div>

            <div class="col-12">
              <div class="form-check">
                <input class="form-check-input" type="checkbox" name="create_db" value="1" id="createDbCheck" checked>
                <label class="form-check-label" for="createDbCheck">Creează DB + user (necesită cont MySQL cu privilegii)</label>
              </div>
              <div class="text-muted small">Dacă nu ai privilegii (tipic shared hosting), debifează și folosește o DB/user deja create în cPanel.</div>
            </div>

            <div class="col-md-6">
              <label class="form-label">MySQL admin user</label>
              <input class="form-control" name="mysql_admin_user" placeholder="root sau user cu drept de creare">
            </div>
            <div class="col-md-6">
              <label class="form-label">MySQL admin pass</label>
              <input class="form-control" type="password" name="mysql_admin_pass">
            </div>

            <div class="col-md-4">
              <label class="form-label">DB name</label>
              <input class="form-control" name="db_name" placeholder="wssc" required>
            </div>
            <div class="col-md-4">
              <label class="form-label">DB user</label>
              <input class="form-control" name="db_user" placeholder="wssc_user" required>
            </div>
            <div class="col-md-4">
              <label class="form-label">DB user host</label>
              <input class="form-control" name="db_user_host" value="localhost">
            </div>
            <div class="col-12">
              <label class="form-label">DB password</label>
              <input class="form-control" type="password" name="db_pass" required>
            </div>

            <div class="col-12">
              <label class="form-label">Administrator (username)</label>
              <input class="form-control" name="admin_username" value="admin" required>
            </div>
            <div class="col-12">
              <label class="form-label">Administrator (parolă)</label>
              <input class="form-control" type="password" name="admin_password" required>
              <div class="text-muted small">Minim 10 caractere. Acest cont are acces la update/backup.</div>
            </div>
          </div>

          <div class="d-flex gap-2 mt-3">
            <button class="btn btn-primary" type="submit">Finalizează instalarea</button>
          </div>
        </div>
      </form>
    <?php endif; ?>
  </div>
</body>
</html>
