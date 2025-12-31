<?php
declare(strict_types=1);

namespace WSSC\Auth;

use PDO;
use RuntimeException;

final class Auth
{
    private const SESSION_ID = 'wssc_user_id';
    private const SESSION_ROLE = 'wssc_user_role';
    private const SESSION_NAME = 'wssc_user_name';

    private readonly UserRepository $users;

    public function __construct(private readonly PDO $db)
    {
        $this->users = new UserRepository($db);
    }

    public function login(string $username, string $password): void
    {
        $username = trim($username);
        if ($username === '' || $password === '') {
            throw new RuntimeException('Username/parolă invalide.');
        }

        $user = $this->users->findByUsername($username);
        if (!$user || (int)($user['is_disabled'] ?? 0) === 1) {
            throw new RuntimeException('Autentificare eșuată.');
        }

        $hash = (string)($user['password_hash'] ?? '');
        if ($hash === '' || !password_verify($password, $hash)) {
            throw new RuntimeException('Autentificare eșuată.');
        }

        session_regenerate_id(true);
        $_SESSION[self::SESSION_ID] = (int)$user['id'];
        $_SESSION[self::SESSION_ROLE] = (string)$user['role'];
        $_SESSION[self::SESSION_NAME] = (string)$user['username'];
        $_SESSION['wssc_last_seen'] = time();

        $this->users->updateLastLogin((int)$user['id']);
    }

    public function logout(): void
    {
        $_SESSION[self::SESSION_ID] = 0;
        unset($_SESSION[self::SESSION_ROLE], $_SESSION[self::SESSION_NAME]);
        session_regenerate_id(true);
    }

    public function isAuthenticated(): bool
    {
        if (!isset($_SESSION[self::SESSION_ID]) || (int)$_SESSION[self::SESSION_ID] <= 0) {
            return false;
        }
        $last = isset($_SESSION['wssc_last_seen']) && is_int($_SESSION['wssc_last_seen']) ? (int)$_SESSION['wssc_last_seen'] : time();
        if ((time() - $last) > 300) {
            $this->logout();
            return false;
        }
        $_SESSION['wssc_last_seen'] = time();
        return true;
    }

    public function requireAuthenticated(): void
    {
        if (!$this->isAuthenticated()) {
            throw new RuntimeException('Neautentificat.');
        }
    }

    public function role(): ?string
    {
        $r = $_SESSION[self::SESSION_ROLE] ?? null;
        return is_string($r) && $r !== '' ? $r : null;
    }

    public function username(): ?string
    {
        $u = $_SESSION[self::SESSION_NAME] ?? null;
        return is_string($u) && $u !== '' ? $u : null;
    }

    public function requireRole(string $role): void
    {
        $this->requireAuthenticated();
        if ($this->role() !== $role) {
            throw new RuntimeException('Acces interzis.');
        }
    }
}
