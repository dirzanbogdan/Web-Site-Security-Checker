<?php
declare(strict_types=1);

namespace WSSC\Security;

use RuntimeException;

final class Csrf
{
    private const SESSION_KEY = 'wssc_csrf_token';

    public function getToken(): string
    {
        if (!isset($_SESSION[self::SESSION_KEY]) || !is_string($_SESSION[self::SESSION_KEY])) {
            $_SESSION[self::SESSION_KEY] = bin2hex(random_bytes(32));
        }
        return (string)$_SESSION[self::SESSION_KEY];
    }

    public function requireValidToken(null|string $token): void
    {
        $expected = $this->getToken();
        if (!is_string($token) || $token === '' || !hash_equals($expected, $token)) {
            throw new RuntimeException('CSRF token invalid.');
        }
    }
}

