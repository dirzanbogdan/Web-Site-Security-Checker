<?php
declare(strict_types=1);

namespace WSSC\Auth;

use PDO;

final class UserRepository
{
    public function __construct(private readonly PDO $db)
    {
    }

    /**
     * @return array<string,mixed>|null
     */
    public function findByUsername(string $username): ?array
    {
        $stmt = $this->db->prepare('SELECT * FROM users WHERE username = :u LIMIT 1');
        $stmt->execute([':u' => $username]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    /**
     * @return array<string,mixed>|null
     */
    public function findById(int $id): ?array
    {
        $stmt = $this->db->prepare('SELECT * FROM users WHERE id = :id LIMIT 1');
        $stmt->execute([':id' => $id]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    public function createUser(string $username, string $passwordHash, string $role): int
    {
        $stmt = $this->db->prepare(
            'INSERT INTO users (username, password_hash, role, is_disabled, created_at)
             VALUES (:u, :p, :r, 0, NOW())'
        );
        $stmt->execute([
            ':u' => $username,
            ':p' => $passwordHash,
            ':r' => $role,
        ]);
        return (int)$this->db->lastInsertId();
    }

    public function updateLastLogin(int $id): void
    {
        $stmt = $this->db->prepare('UPDATE users SET last_login_at = NOW() WHERE id = :id');
        $stmt->execute([':id' => $id]);
    }
}

