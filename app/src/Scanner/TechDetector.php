<?php
declare(strict_types=1);

namespace WSSC\Scanner;

final class TechDetector
{
    /**
     * Detectează tehnologii dintr-un răspuns HTTP (headers + HTML).
     *
     * @param array<string,mixed>|null $resp
     * @return array<string,mixed>
     */
    public function detect(?array $resp): array
    {
        $headers = [];
        $html = '';
        if (is_array($resp)) {
            $headers = is_array($resp['headers'] ?? null) ? $resp['headers'] : [];
            $html = is_string($resp['body'] ?? null) ? (string)$resp['body'] : '';
        }

        $server = $this->getHeader($headers, 'Server');
        $xpb = $this->getHeader($headers, 'X-Powered-By');

        $webServer = null;
        if ($server) {
            $sv = strtolower($server);
            if (str_contains($sv, 'apache')) $webServer = 'Apache';
            elseif (str_contains($sv, 'nginx')) $webServer = 'Nginx';
            elseif (str_contains($sv, 'litespeed')) $webServer = 'LiteSpeed';
            else $webServer = $server;
        }

        $phpVersion = null;
        if ($xpb && preg_match('/php\/([0-9.]+)/i', $xpb, $m)) {
            $phpVersion = $m[1];
        }

        $cms = $this->detectCms($html);
        $js = $this->detectJs($html);
        $libs = $this->detectLibraries($html);

        return [
            'web_server' => $webServer,
            'php' => ['version_exposed' => $phpVersion, 'x_powered_by' => $xpb],
            'cms' => $cms,
            'js' => $js,
            'libraries' => $libs,
            'headers' => [
                'server' => $server,
            ],
        ];
    }

    /**
     * @param array<string,string> $headers
     */
    private function getHeader(array $headers, string $name): ?string
    {
        foreach ($headers as $k => $v) {
            if (strcasecmp((string)$k, $name) === 0) {
                return (string)$v;
            }
        }
        return null;
    }

    /**
     * @return array{name:string|null,version:string|null,evidence:array<int,string>}
     */
    private function detectCms(string $html): array
    {
        $evidence = [];
        $name = null;
        $version = null;

        if (preg_match('/<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']/i', $html, $m)) {
            $gen = $m[1];
            $evidence[] = 'meta generator: ' . $gen;
            $g = strtolower($gen);
            if (str_contains($g, 'wordpress')) $name = 'WordPress';
            elseif (str_contains($g, 'joomla')) $name = 'Joomla';
            elseif (str_contains($g, 'drupal')) $name = 'Drupal';
            if (preg_match('/([0-9]+(?:\.[0-9]+)+)/', $gen, $vm)) {
                $version = $vm[1];
            }
        }

        if ($name === null && str_contains($html, 'wp-content')) {
            $name = 'WordPress';
            $evidence[] = 'pattern: wp-content';
        }
        if ($name === null && (str_contains($html, '/sites/default/') || str_contains($html, 'drupal-settings-json'))) {
            $name = 'Drupal';
            $evidence[] = 'pattern: drupal';
        }
        if ($name === null && (str_contains($html, 'Joomla!') || str_contains($html, 'com_content'))) {
            $name = 'Joomla';
            $evidence[] = 'pattern: joomla';
        }

        return ['name' => $name, 'version' => $version, 'evidence' => $evidence];
    }

    /**
     * @return list<string>
     */
    private function detectJs(string $html): array
    {
        $out = [];

        $h = strtolower($html);
        if (preg_match('/jquery([-.][0-9.]+)?(\.min)?\.js/', $h)) $out[] = 'jQuery';
        if (preg_match('/react([-.][0-9.]+)?(\.min)?\.(js|mjs)/', $h) || str_contains($h, 'data-reactroot') || str_contains($h, '__react')) $out[] = 'React';
        if (preg_match('/vue([-.][0-9.]+)?(\.min)?\.(js|mjs)/', $h) || str_contains($h, 'data-v-')) $out[] = 'Vue';
        if (preg_match('/angular([-.][0-9.]+)?(\.min)?\.(js|mjs)/', $h) || str_contains($h, 'ng-version')) $out[] = 'Angular';

        return array_values(array_unique($out));
    }

    /**
     * @return list<string>
     */
    private function detectLibraries(string $html): array
    {
        $out = [];
        $h = strtolower($html);

        if (str_contains($h, 'bootstrap')) $out[] = 'Bootstrap';
        if (str_contains($h, 'font-awesome') || str_contains($h, 'fontawesome')) $out[] = 'Font Awesome';
        if (str_contains($h, 'tailwind')) $out[] = 'Tailwind CSS';

        return array_values(array_unique($out));
    }
}

