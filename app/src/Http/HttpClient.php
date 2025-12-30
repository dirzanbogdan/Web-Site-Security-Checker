<?php
declare(strict_types=1);

namespace WSSC\Http;

use RuntimeException;

final class HttpClient
{
    /**
     * Execută cereri HTTP/HTTPS către un host, forțând rezolvarea către un IP (anti-DNS rebinding).
     * Fără redirect-uri (anti-SSRF prin redirect).
     *
     * @return array{ok:bool,status:int,headers:array<string,string>,body:string,url:string,error?:string}
     */
    public function fetch(string $scheme, string $host, string $ip, string $path, int $timeoutSeconds, int $maxBytes): array
    {
        $scheme = strtolower($scheme);
        if (!in_array($scheme, ['http', 'https'], true)) {
            throw new RuntimeException('Schema invalidă.');
        }

        $path = $path === '' ? '/' : $path;
        if ($path[0] !== '/') {
            $path = '/' . $path;
        }

        $url = $scheme . '://' . $host . $path;
        $port = $scheme === 'https' ? 443 : 80;

        $ch = curl_init();
        if ($ch === false) {
            throw new RuntimeException('cURL indisponibil.');
        }

        $headers = [];
        $body = '';

        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => false,
            CURLOPT_HEADER => false,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_MAXREDIRS => 0,
            CURLOPT_CONNECTTIMEOUT => $timeoutSeconds,
            CURLOPT_TIMEOUT => $timeoutSeconds,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_USERAGENT => 'WSSC/1.0 (+internal-security-audit)',
            CURLOPT_RESOLVE => [$host . ':' . $port . ':' . $ip],
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_SSLVERSION => CURL_SSLVERSION_DEFAULT,
            CURLOPT_HEADERFUNCTION => static function ($curl, string $headerLine) use (&$headers): int {
                $len = strlen($headerLine);
                $headerLine = trim($headerLine);
                if ($headerLine === '' || !str_contains($headerLine, ':')) {
                    return $len;
                }
                [$k, $v] = explode(':', $headerLine, 2);
                $headers[trim($k)] = trim($v);
                return $len;
            },
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
        curl_close($ch);

        if ($ok === false) {
            return [
                'ok' => false,
                'status' => $status ?: 0,
                'headers' => $headers,
                'body' => '',
                'url' => $url,
                'error' => $err !== '' ? $err : 'Eroare HTTP.',
            ];
        }

        return [
            'ok' => true,
            'status' => $status,
            'headers' => $headers,
            'body' => $body,
            'url' => $url,
        ];
    }
}

