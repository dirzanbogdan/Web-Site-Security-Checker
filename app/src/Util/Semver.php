<?php
declare(strict_types=1);

namespace WSSC\Util;

final class Semver
{
    /**
     * Compară versiunile tip x.y.z (ignoră sufixe non-numerice).
     * Returnează: -1 (a<b), 0 (a=b), 1 (a>b)
     */
    public static function compare(string $a, string $b): int
    {
        $pa = self::parts($a);
        $pb = self::parts($b);

        $len = max(count($pa), count($pb));
        for ($i = 0; $i < $len; $i++) {
            $ai = $pa[$i] ?? 0;
            $bi = $pb[$i] ?? 0;
            if ($ai < $bi) return -1;
            if ($ai > $bi) return 1;
        }
        return 0;
    }

    /**
     * @return list<int>
     */
    private static function parts(string $v): array
    {
        $v = strtolower(trim($v));
        $v = preg_replace('/[^0-9.].*$/', '', $v) ?? $v;
        $chunks = array_filter(explode('.', $v), static fn($x) => $x !== '');
        $out = [];
        foreach ($chunks as $c) {
            $out[] = (int)$c;
        }
        return $out;
    }
}

