<?php
declare(strict_types=1);

namespace WSSC\Db;

use PDO;
use PDOException;
use RuntimeException;

final class Db
{
    /**
     * Creează conexiunea PDO către MySQL/MariaDB.
     *
     * @param array{host:string,port:int,dbname:string,user:string,pass:string,charset:string} $cfg
     */
    public static function connect(array $cfg): PDO
    {
        $dsn = sprintf(
            'mysql:host=%s;port=%d;dbname=%s;charset=%s',
            $cfg['host'],
            (int)$cfg['port'],
            $cfg['dbname'],
            $cfg['charset'] ?? 'utf8mb4'
        );

        try {
            $pdo = new PDO($dsn, $cfg['user'], $cfg['pass'], [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
            ]);
        } catch (PDOException $e) {
            throw new RuntimeException('Eroare conexiune DB: ' . $e->getMessage(), 0, $e);
        }

        return $pdo;
    }
}

