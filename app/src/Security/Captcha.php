<?php
declare(strict_types=1);

namespace WSSC\Security;

final class Captcha
{
    private const SESSION_A = 'wssc_captcha_a';

    /**
     * @param array{enabled:bool} $cfg
     */
    public function __construct(private readonly array $cfg)
    {
    }

    public function newChallenge(): string
    {
        $a = random_int(2, 9);
        $b = random_int(2, 9);
        $op = random_int(0, 1) === 0 ? '+' : '*';
        $q = $a . ' ' . $op . ' ' . $b . ' = ?';
        $ans = $op === '+' ? ($a + $b) : ($a * $b);

        $_SESSION[self::SESSION_A] = (string)$ans;
        return $q;
    }

    public function verify(string $answer): bool
    {
        $expected = $_SESSION[self::SESSION_A] ?? null;
        if (!is_string($expected) || $expected === '') {
            return false;
        }
        $ok = hash_equals($expected, trim($answer));
        if ($ok) {
            unset($_SESSION[self::SESSION_A]);
        }
        return $ok;
    }
}

