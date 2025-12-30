<?php
declare(strict_types=1);

namespace WSSC\Scanner;

use RuntimeException;
use Throwable;
use WSSC\Http\HttpClient;
use WSSC\Storage\ScanRepository;
use WSSC\Util\Semver;

final class DomainScanner
{
    private readonly HttpClient $http;
    private readonly PortScanner $portScanner;
    private readonly TechDetector $techDetector;
    private readonly VulnScanner $vulnScanner;

    public function __construct(private readonly array $config)
    {
        $this->http = new HttpClient();
        $this->portScanner = new PortScanner();
        $this->techDetector = new TechDetector();
        $this->vulnScanner = new VulnScanner($this->config);
    }

    /**
     * Rulează cât permite un timebox (în secunde) procesând pași incrementali.
     * Scop: evitarea timeout-urilor pe shared hosting.
     *
     * @return array<string,mixed> Scan row actualizat din DB
     */
    public function runTimeboxed(ScanRepository $repo, int $scanId, float $maxSeconds): array
    {
        $start = microtime(true);
        $repo->markRunningIfQueued($scanId);

        while ((microtime(true) - $start) < $maxSeconds) {
            $scan = $repo->getById($scanId);
            if (!$scan) {
                throw new RuntimeException('Scanare inexistentă.');
            }
            if ($scan['status'] === 'done' || $scan['status'] === 'error') {
                return $scan;
            }

            try {
                $this->processOneStep($repo, $scan);
            } catch (Throwable $e) {
                $repo->markError($scanId, $e->getMessage());
                return $repo->getById($scanId) ?? $scan;
            }
        }

        return $repo->getById($scanId) ?? ['status' => 'running', 'progress' => 1];
    }

    /**
     * Procesează un singur pas din pipeline.
     *
     * @param array<string,mixed> $scan
     */
    private function processOneStep(ScanRepository $repo, array $scan): void
    {
        $mode = (string)$scan['mode'];
        $host = (string)$scan['domain'];
        $ip = (string)$scan['resolved_ip'];

        $timeout = (int)$this->config['scan']['http_timeout_seconds'];
        $maxBody = (int)$this->config['scan']['http_max_body_bytes'];
        $ports = $this->config['scan']['ports_common'];

        $steps = $mode === 'full'
            ? ['http', 'https', 'ports', 'tech', 'headers', 'tls', 'exposures', 'cms_versions', 'finalize']
            : ['https', 'http', 'ports_quick', 'tech', 'headers', 'finalize'];

        $next = (int)$scan['next_step'];
        $total = count($steps);
        if ($next >= $total) {
            $repo->markDone((int)$scan['id']);
            return;
        }

        $result = $scan['result_json'] ? json_decode((string)$scan['result_json'], true) : [];
        if (!is_array($result)) {
            $result = [];
        }
        $result['meta'] ??= [
            'domain' => $host,
            'ip' => $ip,
            'mode' => $mode,
            'scan_version' => '1.0',
            'created_at' => $scan['created_at'] ?? null,
        ];
        $result['findings'] ??= [];

        $step = $steps[$next];

        switch ($step) {
            case 'http':
                $resp = $this->http->fetch('http', $host, $ip, '/', $timeout, $maxBody);
                $result['http']['http'] = $this->sanitizeHttpResult($resp);
                break;

            case 'https':
                $resp = $this->http->fetch('https', $host, $ip, '/', $timeout, $maxBody);
                $result['http']['https'] = $this->sanitizeHttpResult($resp);
                if (!$resp['ok']) {
                    $result['findings'][] = $this->finding(
                        id: 'tls.https.disabled',
                        category: 'SSL/TLS',
                        severity: 'MEDIUM',
                        title: 'HTTPS indisponibil',
                        description: 'Nu s-a putut accesa endpoint-ul HTTPS al domeniului.',
                        recommendation: 'Activează HTTPS cu un certificat valid (ex: Let’s Encrypt) și redirecționează traficul HTTP către HTTPS.',
                        evidence: ['error' => $resp['error'] ?? null]
                    );
                }
                break;

            case 'ports':
                $portMap = $this->portScanner->scanPorts($ip, $ports, (float)$this->config['scan']['port_timeout_seconds']);
                $result['ports'] = $portMap;
                foreach ($portMap as $p => $st) {
                    if ($st === 'OPEN') {
                        $result['findings'][] = $this->finding(
                            id: 'port.open.' . $p,
                            category: 'Porturi',
                            severity: in_array((int)$p, [22, 21, 3306], true) ? 'MEDIUM' : 'LOW',
                            title: 'Port deschis: ' . $p,
                            description: 'Portul ' . $p . ' răspunde la conexiune TCP (OPEN).',
                            recommendation: 'Restricționează expunerea la internet: firewall, allowlist, VPN sau dezactivare serviciu neutilizat.',
                            evidence: ['port' => (int)$p, 'status' => $st]
                        );
                    }
                }
                break;

            case 'ports_quick':
                $quickPorts = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 8080];
                $portMap = $this->portScanner->scanPorts($ip, $quickPorts, (float)$this->config['scan']['port_timeout_seconds']);
                $result['ports'] = $portMap;
                foreach ($portMap as $p => $st) {
                    if ($st === 'OPEN') {
                        $result['findings'][] = $this->finding(
                            id: 'port.open.' . $p,
                            category: 'Porturi',
                            severity: in_array((int)$p, [22, 21, 3306], true) ? 'MEDIUM' : 'LOW',
                            title: 'Port deschis: ' . $p,
                            description: 'Portul ' . $p . ' răspunde la conexiune TCP (OPEN).',
                            recommendation: 'Restricționează expunerea la internet dacă serviciul nu trebuie public.',
                            evidence: ['port' => (int)$p, 'status' => $st]
                        );
                    }
                }
                break;

            case 'tech':
                $primary = $this->pickPrimaryHttp($result);
                $tech = $this->techDetector->detect($primary);
                $result['tech'] = $tech;
                if (!empty($tech['cms']['name'])) {
                    $result['findings'][] = $this->finding(
                        id: 'tech.cms.detected',
                        category: 'Tehnologii',
                        severity: 'INFO',
                        title: 'CMS detectat: ' . $tech['cms']['name'],
                        description: 'Aplicația pare să folosească un CMS (' . $tech['cms']['name'] . ').',
                        recommendation: 'Menține CMS-ul și plugin-urile actualizate și limitează accesul la panoul de administrare.',
                        evidence: $tech['cms']
                    );
                }
                break;

            case 'headers':
                $primary = $this->pickPrimaryHttp($result);
                $isHttpsOk = (bool)($result['http']['https']['ok'] ?? false);
                if ($primary) {
                    $checks = $this->vulnScanner->checkSecurityHeaders($primary, $isHttpsOk);
                    foreach ($checks as $f) {
                        $result['findings'][] = $f;
                    }
                }
                break;

            case 'tls':
                $tls = $this->vulnScanner->checkTls($host, $ip);
                $result['tls'] = $tls['summary'];
                foreach ($tls['findings'] as $f) {
                    $result['findings'][] = $f;
                }
                break;

            case 'exposures':
                $exp = $this->vulnScanner->checkExposures($host, $ip, $this->http, $timeout);
                $result['exposures'] = $exp['summary'];
                foreach ($exp['findings'] as $f) {
                    $result['findings'][] = $f;
                }
                break;

            case 'cms_versions':
                $tech = $result['tech'] ?? [];
                $db = $this->vulnScanner->loadVulnDb();
                $v = $tech['cms']['version'] ?? null;
                $cms = $tech['cms']['name'] ?? null;
                if (is_string($cms) && $cms !== '' && is_string($v) && $v !== '') {
                    foreach (($db['cms'] ?? []) as $entry) {
                        if (!is_array($entry) || ($entry['name'] ?? '') !== $cms) {
                            continue;
                        }
                        $minInc = $entry['min_version_inclusive'] ?? null;
                        $minExc = $entry['min_version_exclusive'] ?? null;
                        $maxInc = $entry['max_version_inclusive'] ?? null;
                        $maxExc = $entry['max_version_exclusive'] ?? null;
                        if (is_string($minInc) && Semver::compare($v, $minInc) < 0) {
                            continue;
                        }
                        if (is_string($minExc) && Semver::compare($v, $minExc) <= 0) {
                            continue;
                        }
                        if (is_string($maxInc) && Semver::compare($v, $maxInc) > 0) {
                            continue;
                        }
                        if (is_string($maxExc) && Semver::compare($v, $maxExc) >= 0) {
                            continue;
                        }
                        $result['findings'][] = $this->finding(
                            id: 'cms.vuln.' . strtolower($cms) . '.' . ($entry['cve'] ?? 'ref'),
                            category: 'Vulnerabilități',
                            severity: 'MEDIUM',
                            title: 'Versiune CMS potențial vulnerabilă',
                            description: 'Versiunea detectată (' . $cms . ' ' . $v . ') se încadrează într-un interval asociat cu vulnerabilități publice.',
                            recommendation: 'Actualizează CMS-ul la ultima versiune stabilă și verifică buletinele de securitate oficiale.',
                            evidence: [
                                'cms' => $cms,
                                'version' => $v,
                                'reference' => $entry,
                            ]
                        );
                    }
                }
                break;

            case 'finalize':
                $result['meta']['finished_at'] = gmdate('c');
                $result['meta']['target'] = ['domain' => $host, 'ip' => $ip];
                $result['meta']['notes'] = 'Scanare pasivă/semi-activă. Nu se execută exploit-uri.';
                break;
        }

        $next++;
        $progress = (int)floor(($next / $total) * 100);
        $repo->updateProgressAndResult((int)$scan['id'], $next, $progress, $result);

        if ($next >= $total) {
            $repo->markDone((int)$scan['id']);
        }
    }

    /**
     * @param array<string,mixed> $result
     * @return array<string,mixed>|null
     */
    private function pickPrimaryHttp(array $result): ?array
    {
        $https = $result['http']['https'] ?? null;
        $http = $result['http']['http'] ?? null;
        if (is_array($https) && (int)($https['status'] ?? 0) > 0) {
            return $https;
        }
        return is_array($http) ? $http : null;
    }

    /**
     * @param array{ok:bool,status:int,headers:array<string,string>,body:string,url:string,error?:string} $resp
     * @return array<string,mixed>
     */
    private function sanitizeHttpResult(array $resp): array
    {
        $headers = [];
        foreach (($resp['headers'] ?? []) as $k => $v) {
            if (!is_string($k) || !is_string($v)) {
                continue;
            }
            $headers[$k] = mb_substr($v, 0, 500);
        }

        $body = (string)($resp['body'] ?? '');
        if (strlen($body) > 200000) {
            $body = substr($body, 0, 200000);
        }

        return [
            'ok' => (bool)$resp['ok'],
            'status' => (int)$resp['status'],
            'headers' => $headers,
            'body' => $body,
            'url' => (string)($resp['url'] ?? ''),
            'error' => isset($resp['error']) ? (string)$resp['error'] : null,
        ];
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
}
