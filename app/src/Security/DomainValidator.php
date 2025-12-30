<?php
declare(strict_types=1);

namespace WSSC\Security;

use RuntimeException;

final class DomainValidator
{
    /**
     * Validează inputul și rezolvă către un IP public (A/AAAA).
     *
     * @return array{domain:string,ip:string}
     */
    public function validateAndResolve(string $input): array
    {
        $input = trim($input);
        $input = preg_replace('#^https?://#i', '', $input) ?? $input;
        $input = preg_replace('#/.*$#', '', $input) ?? $input;
        $input = preg_replace('#:\d+$#', '', $input) ?? $input;

        if ($input === '') {
            throw new RuntimeException('Domeniu gol.');
        }

        $domain = $this->normalizeDomain($input);
        if (!$this->isValidHostname($domain)) {
            throw new RuntimeException('Domeniu invalid.');
        }

        $ip = $this->resolvePublicIp($domain);
        if ($ip === null) {
            throw new RuntimeException('DNS: nu s-a găsit un IP public pentru domeniu.');
        }

        return ['domain' => $domain, 'ip' => $ip];
    }

    private function normalizeDomain(string $domain): string
    {
        $domain = strtolower(trim($domain, ". \t\n\r\0\x0B"));
        if (function_exists('idn_to_ascii')) {
            $converted = idn_to_ascii($domain, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
            if (is_string($converted) && $converted !== '') {
                return $converted;
            }
        }
        return $domain;
    }

    private function isValidHostname(string $host): bool
    {
        if (strlen($host) > 253) {
            return false;
        }
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return false;
        }
        return (bool)preg_match('/^(?=.{1,253}$)(?!-)(?:[a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$/', $host);
    }

    private function resolvePublicIp(string $host): ?string
    {
        $records = @dns_get_record($host, DNS_A + DNS_AAAA);
        if (!is_array($records)) {
            return null;
        }

        $ips = [];
        foreach ($records as $r) {
            if (isset($r['ip']) && is_string($r['ip'])) {
                $ips[] = $r['ip'];
            }
            if (isset($r['ipv6']) && is_string($r['ipv6'])) {
                $ips[] = $r['ipv6'];
            }
        }

        foreach ($ips as $ip) {
            if ($this->isPublicIp($ip)) {
                return $ip;
            }
        }
        return null;
    }

    private function isPublicIp(string $ip): bool
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }
        $flags = FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE;
        return (bool)filter_var($ip, FILTER_VALIDATE_IP, $flags);
    }
}

