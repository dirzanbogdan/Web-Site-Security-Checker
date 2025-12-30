<?php
declare(strict_types=1);

namespace WSSC\Storage;

use PDO;

final class AuditLogger
{
    public function __construct(private readonly PDO $db)
    {
    }

    /**
     * Log minimal de activitate (fără date sensibile).
     *
     * @param array<string,mixed> $meta
     */
    public function log(string $event, array $meta = []): void
    {
        $ip = (string)($_SERVER['REMOTE_ADDR'] ?? '');
        $stmt = $this->db->prepare(
            'INSERT INTO audit_log (ip, event, meta_json, created_at) VALUES (:ip, :e, :m, NOW())'
        );
        $stmt->execute([
            ':ip' => $ip,
            ':e' => mb_substr($event, 0, 120),
            ':m' => json_encode($meta, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
        ]);
    }
}

