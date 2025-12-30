<?php
declare(strict_types=1);

/**
 * WSSC config sample.
 * Copiază acest fișier în config/config.php și completează.
 */

return [
    'app' => [
        'name' => 'Web Site Security Checker',
        'short_name' => 'WSSC',
        'version' => '1.0.20251230',
        'base_url' => 'https://sec.e-bm.eu/WSSC',
    ],
    'db' => [
        'host' => 'localhost',
        'port' => 3306,
        'dbname' => 'wssc',
        'user' => 'wssc_user',
        'pass' => 'CHANGE_ME',
        'charset' => 'utf8mb4',
    ],
    'scan' => [
        'http_timeout_seconds' => 10,
        'tls_timeout_seconds' => 8,
        'port_timeout_seconds' => 0.7,
        'http_max_body_bytes' => 200000,
        'ports_common' => [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 8080],
    ],
    'security' => [
        'rate_limit' => [
            'enabled' => true,
            'window_seconds' => 60,
            'max_requests' => 10,
        ],
        'captcha' => [
            'enabled' => false,
        ],
    ],
    'admin' => [
        'update_allowed_ips' => [],
        'default_update_branch' => 'main',
    ],
    'ui' => [
        'use_bootstrap_cdn' => true,
        'disclaimer_text' => '„Scanați doar domenii pe care le dețineți sau aveți permisiune explicită.”',
    ],
];
