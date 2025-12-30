<?php
declare(strict_types=1);

namespace WSSC\Scanner;

final class PortScanner
{
    /**
     * @param list<int> $ports
     * @return array<int,string> port => OPEN|CLOSED|FILTERED
     */
    public function scanPorts(string $ip, array $ports, float $timeoutSeconds): array
    {
        $timeoutSeconds = max(0.2, min(10.0, $timeoutSeconds));
        $out = [];

        foreach ($ports as $port) {
            $port = (int)$port;
            if ($port <= 0 || $port > 65535) {
                continue;
            }

            $errno = 0;
            $errstr = '';
            $fp = @stream_socket_client(
                'tcp://' . $ip . ':' . $port,
                $errno,
                $errstr,
                $timeoutSeconds,
                STREAM_CLIENT_CONNECT
            );

            if (is_resource($fp)) {
                fclose($fp);
                $out[$port] = 'OPEN';
                continue;
            }

            $out[$port] = $this->classifyFail($errno, $errstr);
        }

        ksort($out);
        return $out;
    }

    private function classifyFail(int $errno, string $errstr): string
    {
        $timeoutErrnos = [110, 10060];
        $refusedErrnos = [111, 61, 10061];

        if (in_array($errno, $timeoutErrnos, true)) {
            return 'FILTERED';
        }
        if (in_array($errno, $refusedErrnos, true)) {
            return 'CLOSED';
        }

        $s = strtolower($errstr);
        if (str_contains($s, 'timed out')) {
            return 'FILTERED';
        }
        if (str_contains($s, 'refused')) {
            return 'CLOSED';
        }

        return 'CLOSED';
    }
}

