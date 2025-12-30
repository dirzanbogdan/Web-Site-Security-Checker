<?php
declare(strict_types=1);

namespace WSSC\Storage;

use PDO;
use RuntimeException;

final class ScanRepository
{
    public function __construct(private readonly PDO $db)
    {
    }

    /**
     * Creează o scanare în stare QUEUED.
     */
    public function createQueuedScan(string $domain, string $ip, string $mode, string $createdIp, string $sessionHash): int
    {
        $stmt = $this->db->prepare(
            'INSERT INTO scans (domain, mode, status, progress, next_step, resolved_ip, created_ip, session_hash, created_at)
             VALUES (:d, :m, :s, 0, 0, :ip, :cip, :sh, NOW())'
        );
        $stmt->execute([
            ':d' => $domain,
            ':m' => $mode,
            ':s' => 'queued',
            ':ip' => $ip,
            ':cip' => $createdIp,
            ':sh' => $sessionHash,
        ]);

        return (int)$this->db->lastInsertId();
    }

    /**
     * @return array<string,mixed>|null
     */
    public function getById(int $id): ?array
    {
        $stmt = $this->db->prepare('SELECT * FROM scans WHERE id = :id');
        $stmt->execute([':id' => $id]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    public function markRunningIfQueued(int $id): void
    {
        $stmt = $this->db->prepare(
            'UPDATE scans
             SET status = IF(status="queued","running",status),
                 started_at = IF(started_at IS NULL AND status="queued", NOW(), started_at)
             WHERE id = :id'
        );
        $stmt->execute([':id' => $id]);
    }

    /**
     * @param array<string,mixed> $result
     */
    public function updateProgressAndResult(int $id, int $nextStep, int $progress, array $result): void
    {
        $stmt = $this->db->prepare(
            'UPDATE scans
             SET next_step = :ns, progress = :p, result_json = :r
             WHERE id = :id'
        );
        $stmt->execute([
            ':ns' => $nextStep,
            ':p' => max(0, min(100, $progress)),
            ':r' => json_encode($result, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            ':id' => $id,
        ]);
    }

    public function markDone(int $id): void
    {
        $stmt = $this->db->prepare('UPDATE scans SET status="done", progress=100, finished_at=NOW() WHERE id=:id');
        $stmt->execute([':id' => $id]);
    }

    public function markError(int $id, string $message): void
    {
        $stmt = $this->db->prepare(
            'UPDATE scans SET status="error", error_message=:m, finished_at=NOW() WHERE id=:id'
        );
        $stmt->execute([':m' => mb_substr($message, 0, 2000), ':id' => $id]);
    }

    /**
     * @return list<array<string,mixed>>
     */
    public function listRecentScans(?string $domainFilter, int $limit): array
    {
        $limit = max(1, min(200, $limit));
        if ($domainFilter !== null && $domainFilter !== '') {
            $stmt = $this->db->prepare('SELECT * FROM scans WHERE domain = :d ORDER BY id DESC LIMIT ' . $limit);
            $stmt->execute([':d' => $domainFilter]);
        } else {
            $stmt = $this->db->query('SELECT * FROM scans ORDER BY id DESC LIMIT ' . $limit);
        }
        $rows = $stmt->fetchAll();
        return is_array($rows) ? $rows : [];
    }
}

