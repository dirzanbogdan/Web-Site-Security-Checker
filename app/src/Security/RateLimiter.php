<?php
declare(strict_types=1);

namespace WSSC\Security;

use PDO;
use RuntimeException;

final class RateLimiter
{
    /**
     * @param array{enabled:bool,window_seconds:int,max_requests:int} $cfg
     */
    public function __construct(
        private readonly PDO $db,
        private readonly array $cfg
    ) {
    }

    public function hitOrThrow(string $ip): void
    {
        if (!$this->cfg['enabled']) {
            return;
        }

        $window = max(10, (int)$this->cfg['window_seconds']);
        $max = max(1, (int)$this->cfg['max_requests']);
        $now = time();
        $windowStart = $now - ($now % $window);

        $this->db->beginTransaction();
        try {
            $stmt = $this->db->prepare('SELECT count FROM rate_limits WHERE ip = :ip AND window_start = :ws FOR UPDATE');
            $stmt->execute([':ip' => $ip, ':ws' => $windowStart]);
            $row = $stmt->fetch();

            if ($row) {
                $count = (int)$row['count'] + 1;
                $upd = $this->db->prepare('UPDATE rate_limits SET count = :c WHERE ip = :ip AND window_start = :ws');
                $upd->execute([':c' => $count, ':ip' => $ip, ':ws' => $windowStart]);
            } else {
                $count = 1;
                $ins = $this->db->prepare('INSERT INTO rate_limits (ip, window_start, count) VALUES (:ip, :ws, 1)');
                $ins->execute([':ip' => $ip, ':ws' => $windowStart]);
            }

            $this->db->commit();
        } catch (\Throwable $e) {
            $this->db->rollBack();
            throw $e;
        }

        if ($count > $max) {
            throw new RuntimeException('Prea multe cereri. Încearcă din nou mai târziu.');
        }
    }
}

