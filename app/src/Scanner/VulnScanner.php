<?php
declare(strict_types=1);

namespace WSSC\Scanner;

use RuntimeException;
use Throwable;
use WSSC\Http\HttpClient;

final class VulnScanner
{
    public function __construct(private readonly array $config)
    {
    }

    /**
     * Verifică security headers (pe baza răspunsului HTTP).
     *
     * @param array<string,mixed> $resp
     * @return list<array<string,mixed>>
     */
    public function checkSecurityHeaders(array $resp, bool $isHttpsOk): array
    {
        $headers = is_array($resp['headers'] ?? null) ? $resp['headers'] : [];
        $h = $this->normalizeHeaders($headers);

        $findings = [];
        $missing = static function (string $key) use ($h): bool {
            return !array_key_exists(strtolower($key), $h);
        };

        if ($missing('Content-Security-Policy')) {
            $findings[] = $this->finding(
                id: 'headers.csp.missing',
                category: 'Security Headers',
                severity: 'MEDIUM',
                title: 'Lipsește Content-Security-Policy',
                description: 'CSP reduce riscul de XSS și încărcări de resurse nesigure.',
                recommendation: 'Definește o politică CSP restrictivă, pornind de la default-src \'self\'.',
                evidence: ['header' => 'Content-Security-Policy']
            );
        }
        if ($missing('X-Frame-Options')) {
            $findings[] = $this->finding(
                id: 'headers.xfo.missing',
                category: 'Security Headers',
                severity: 'LOW',
                title: 'Lipsește X-Frame-Options',
                description: 'Site-ul poate fi încadrat în iframe (risc clickjacking).',
                recommendation: 'Setează X-Frame-Options: DENY sau SAMEORIGIN.',
                evidence: ['header' => 'X-Frame-Options']
            );
        }
        if ($missing('X-Content-Type-Options')) {
            $findings[] = $this->finding(
                id: 'headers.xcto.missing',
                category: 'Security Headers',
                severity: 'LOW',
                title: 'Lipsește X-Content-Type-Options',
                description: 'Browser-ul poate face MIME sniffing în anumite scenarii.',
                recommendation: 'Setează X-Content-Type-Options: nosniff.',
                evidence: ['header' => 'X-Content-Type-Options']
            );
        }
        if ($isHttpsOk && $missing('Strict-Transport-Security')) {
            $findings[] = $this->finding(
                id: 'headers.hsts.missing',
                category: 'Security Headers',
                severity: 'MEDIUM',
                title: 'Lipsește Strict-Transport-Security (HSTS)',
                description: 'Fără HSTS, utilizatorii pot ajunge pe HTTP în anumite scenarii.',
                recommendation: 'Activează HSTS: Strict-Transport-Security: max-age=15552000; includeSubDomains (după testare).',
                evidence: ['header' => 'Strict-Transport-Security']
            );
        }

        $server = $h['server'] ?? null;
        if (is_string($server) && preg_match('/\b(apache|nginx|litespeed)\/[0-9]/i', $server)) {
            $findings[] = $this->finding(
                id: 'headers.server.version_exposed',
                category: 'Hardening',
                severity: 'LOW',
                title: 'Versiune server expusă în header',
                description: 'Header-ul Server poate expune versiuni și facilita fingerprinting.',
                recommendation: 'Redu informațiile expuse: ServerTokens/ServerSignature (Apache) sau server_tokens off (Nginx).',
                evidence: ['Server' => $server]
            );
        }

        $xpb = $h['x-powered-by'] ?? null;
        if (is_string($xpb) && $xpb !== '') {
            $findings[] = $this->finding(
                id: 'headers.x_powered_by.present',
                category: 'Hardening',
                severity: 'LOW',
                title: 'X-Powered-By expus',
                description: 'X-Powered-By poate expune tehnologia/versiunea (ex: PHP).',
                recommendation: 'Dezactivează expunerea: expose_php=0 (php.ini) și filtrează header-ele la nivel de server dacă este posibil.',
                evidence: ['X-Powered-By' => $xpb]
            );
        }

        return $findings;
    }

    /**
     * Verifică TLS: certificat expirat și suport pentru protocoale slabe (TLS 1.0/1.1).
     *
     * @return array{summary:array<string,mixed>,findings:list<array<string,mixed>>}
     */
    public function checkTls(string $host, string $ip): array
    {
        $findings = [];
        $summary = [
            'cert' => null,
            'protocols' => [],
        ];

        try {
            $cert = $this->fetchPeerCertificate($host, $ip);
            $summary['cert'] = $cert;
            if (isset($cert['valid_to']) && is_int($cert['valid_to']) && $cert['valid_to'] < time()) {
                $findings[] = $this->finding(
                    id: 'tls.cert.expired',
                    category: 'SSL/TLS',
                    severity: 'HIGH',
                    title: 'Certificat TLS expirat',
                    description: 'Certificatul TLS pare expirat.',
                    recommendation: 'Reînnoiește certificatul și verifică lanțul (intermediate).',
                    evidence: $cert
                );
            }
            if (isset($cert['valid_to']) && is_int($cert['valid_to'])) {
                $remaining = $cert['valid_to'] - time();
                if ($remaining > 0 && $remaining < (30 * 86400)) {
                    $findings[] = $this->finding(
                        id: 'tls.cert.expiring_soon',
                        category: 'SSL/TLS',
                        severity: 'MEDIUM',
                        title: 'Certificat TLS expiră curând',
                        description: 'Certificatul TLS expiră în mai puțin de 30 de zile.',
                        recommendation: 'Planifică reînnoirea certificatului înainte de expirare.',
                        evidence: $cert
                    );
                }
            }
            if (isset($cert['subject'], $cert['issuer']) && $cert['subject'] === $cert['issuer']) {
                $findings[] = $this->finding(
                    id: 'tls.cert.self_signed',
                    category: 'SSL/TLS',
                    severity: 'MEDIUM',
                    title: 'Certificat TLS posibil self-signed',
                    description: 'Issuer și Subject coincid, sugerând un certificat self-signed.',
                    recommendation: 'Folosește un certificat emis de o CA publică (ex: Let’s Encrypt) pentru site-uri publice.',
                    evidence: $cert
                );
            }
        } catch (Throwable $e) {
            $findings[] = $this->finding(
                id: 'tls.cert.unavailable',
                category: 'SSL/TLS',
                severity: 'MEDIUM',
                title: 'Nu se poate obține certificatul TLS',
                description: 'Handshake-ul TLS nu a permis extragerea certificatului.',
                recommendation: 'Verifică configurarea TLS/SNI și disponibilitatea portului 443.',
                evidence: ['error' => $e->getMessage()]
            );
        }

        $protocolChecks = [
            'TLSv1.0' => defined('STREAM_CRYPTO_METHOD_TLSv1_0_CLIENT') ? STREAM_CRYPTO_METHOD_TLSv1_0_CLIENT : null,
            'TLSv1.1' => defined('STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT') ? STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT : null,
            'TLSv1.2' => defined('STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT') ? STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT : null,
            'TLSv1.3' => defined('STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT') ? STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT : null,
        ];

        foreach ($protocolChecks as $name => $method) {
            if ($method === null) {
                continue;
            }
            $ok = $this->tryTlsProtocol($host, $ip, (int)$method);
            $summary['protocols'][$name] = $ok ? 'SUPPORTED' : 'NOT_SUPPORTED';
            if (in_array($name, ['TLSv1.0', 'TLSv1.1'], true) && $ok) {
                $findings[] = $this->finding(
                    id: 'tls.weak_protocol.' . strtolower(str_replace(['.', 'v'], ['', ''], $name)),
                    category: 'SSL/TLS',
                    severity: 'HIGH',
                    title: 'Protocol TLS slab acceptat: ' . $name,
                    description: 'Serverul acceptă handshake cu ' . $name . ', considerat slab/legacy.',
                    recommendation: 'Dezactivează TLS 1.0/1.1 și păstrează minim TLS 1.2.',
                    evidence: ['protocol' => $name]
                );
            }
        }

        return ['summary' => $summary, 'findings' => $findings];
    }

    /**
     * Expuneri comune (semi-active, request-uri către câteva fișiere/URL-uri standard).
     *
     * @return array{summary:array<string,mixed>,findings:list<array<string,mixed>>}
     */
    public function checkExposures(string $host, string $ip, HttpClient $http, int $timeoutSeconds): array
    {
        $findings = [];
        $summary = [];

        $checks = [
            ['id' => 'exposure.robots', 'path' => '/robots.txt', 'title' => 'robots.txt accesibil', 'severity' => 'INFO'],
            ['id' => 'exposure.env', 'path' => '/.env', 'title' => '.env expus', 'severity' => 'HIGH'],
            ['id' => 'exposure.git', 'path' => '/.git/config', 'title' => '.git/config expus', 'severity' => 'HIGH'],
            ['id' => 'exposure.phpinfo', 'path' => '/phpinfo.php', 'title' => 'phpinfo.php expus', 'severity' => 'MEDIUM'],
            ['id' => 'exposure.admin', 'path' => '/admin/', 'title' => 'Panou admin comun expus (/admin/)', 'severity' => 'LOW'],
            ['id' => 'exposure.wp_admin', 'path' => '/wp-admin/', 'title' => 'WordPress admin expus (/wp-admin/)', 'severity' => 'LOW'],
            ['id' => 'exposure.joomla_admin', 'path' => '/administrator/', 'title' => 'Joomla admin expus (/administrator/)', 'severity' => 'LOW'],
        ];

        foreach ($checks as $c) {
            $resp = $http->fetch('https', $host, $ip, $c['path'], $timeoutSeconds, 6000);
            if (!$resp['ok'] || (int)$resp['status'] === 0) {
                $resp = $http->fetch('http', $host, $ip, $c['path'], $timeoutSeconds, 6000);
            }

            $status = (int)($resp['status'] ?? 0);
            $summary[$c['id']] = ['status' => $status, 'url' => $resp['url'] ?? null];

            if (in_array($status, [200, 206], true)) {
                $findings[] = $this->finding(
                    id: $c['id'],
                    category: 'Expuneri',
                    severity: $c['severity'],
                    title: $c['title'],
                    description: 'Resursa pare accesibilă public (HTTP ' . $status . ').',
                    recommendation: $this->recommendationForExposure($c['id']),
                    evidence: ['url' => $resp['url'] ?? null, 'status' => $status]
                );
            }
        }

        $home = $http->fetch('http', $host, $ip, '/', $timeoutSeconds, 50000);
        if (!$home['ok']) {
            $home = $http->fetch('https', $host, $ip, '/', $timeoutSeconds, 50000);
        }
        if ($home['ok']) {
            $body = strtolower((string)$home['body']);
            if (str_contains($body, '<title>index of /') || str_contains($body, 'index of /')) {
                $findings[] = $this->finding(
                    id: 'exposure.dir_listing',
                    category: 'Configurări',
                    severity: 'MEDIUM',
                    title: 'Directory listing posibil activ',
                    description: 'Pagina pare să indice un listing de directoare (Index of /).',
                    recommendation: 'Dezactivează autoindex/directory listing (Apache Options -Indexes).',
                    evidence: ['url' => $home['url'] ?? null]
                );
            }
        }

        return ['summary' => $summary, 'findings' => $findings];
    }

    /**
     * Încarcă baza statică locală de referințe (actualizabilă manual).
     *
     * @return array<string,mixed>
     */
    public function loadVulnDb(): array
    {
        $path = dirname(__DIR__, 3) . '/data/vuln_db.json';
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

    /**
     * @param array<string,string> $headers
     * @return array<string,string>
     */
    private function normalizeHeaders(array $headers): array
    {
        $out = [];
        foreach ($headers as $k => $v) {
            $out[strtolower((string)$k)] = (string)$v;
        }
        return $out;
    }

    /**
     * @return array{id:string,category:string,severity:string,title:string,description:string,recommendation:string,evidence:mixed}
     */
    private function finding(string $id, string $category, string $severity, string $title, string $description, string $recommendation, mixed $evidence): array
    {
        return [
            'id' => $id,
            'category' => $category,
            'severity' => $severity,
            'title' => $title,
            'description' => $description,
            'recommendation' => $recommendation,
            'evidence' => $evidence,
        ];
    }

    private function recommendationForExposure(string $id): string
    {
        return match ($id) {
            'exposure.robots' => 'Verifică dacă robots.txt nu expune zone sensibile. Nu include URL-uri interne sau directoare critice.',
            'exposure.env' => 'Blochează accesul public la .env și mută secretele în afara webroot-ului. Verifică și istoricul de commit-uri.',
            'exposure.git' => 'Dezactivează accesul la .git și verifică dacă repository-ul nu a fost expus. Regenerarea secretelor este recomandată.',
            'exposure.phpinfo' => 'Șterge fișierul phpinfo.php din producție; acesta expune setări și extensii.',
            default => 'Restricționează accesul (auth, allowlist, IP restrictions) sau mută resursa în afara webroot-ului.',
        };
    }

    /**
     * @return array<string,mixed>
     */
    private function fetchPeerCertificate(string $host, string $ip): array
    {
        $ctx = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => true,
                'verify_peer' => false,
                'verify_peer_name' => false,
                'peer_name' => $host,
                'SNI_enabled' => true,
                'SNI_server_name' => $host,
                'allow_self_signed' => true,
            ],
        ]);

        $errno = 0;
        $errstr = '';
        $fp = @stream_socket_client(
            'ssl://' . $ip . ':443',
            $errno,
            $errstr,
            (float)$this->config['scan']['tls_timeout_seconds'],
            STREAM_CLIENT_CONNECT,
            $ctx
        );
        if (!is_resource($fp)) {
            throw new RuntimeException($errstr !== '' ? $errstr : 'Conexiune TLS eșuată.');
        }

        $params = stream_context_get_params($fp);
        fclose($fp);

        $cert = $params['options']['ssl']['peer_certificate'] ?? null;
        if (!$cert) {
            throw new RuntimeException('Certificat indisponibil.');
        }

        $parsed = openssl_x509_parse($cert);
        if (!is_array($parsed)) {
            throw new RuntimeException('Nu se poate parsa certificatul.');
        }

        return [
            'subject' => $parsed['subject'] ?? null,
            'issuer' => $parsed['issuer'] ?? null,
            'valid_from' => $parsed['validFrom_time_t'] ?? null,
            'valid_to' => $parsed['validTo_time_t'] ?? null,
            'serial' => $parsed['serialNumberHex'] ?? null,
        ];
    }

    private function tryTlsProtocol(string $host, string $ip, int $cryptoMethod): bool
    {
        $ctx = stream_context_create([
            'ssl' => [
                'verify_peer' => false,
                'verify_peer_name' => false,
                'peer_name' => $host,
                'SNI_enabled' => true,
                'SNI_server_name' => $host,
            ],
        ]);

        $errno = 0;
        $errstr = '';
        $fp = @stream_socket_client(
            'tcp://' . $ip . ':443',
            $errno,
            $errstr,
            (float)$this->config['scan']['tls_timeout_seconds'],
            STREAM_CLIENT_CONNECT,
            $ctx
        );
        if (!is_resource($fp)) {
            return false;
        }

        stream_set_timeout($fp, (int)$this->config['scan']['tls_timeout_seconds']);
        try {
            $ok = @stream_socket_enable_crypto($fp, true, $cryptoMethod);
        } finally {
            fclose($fp);
        }

        return $ok === true;
    }
}
