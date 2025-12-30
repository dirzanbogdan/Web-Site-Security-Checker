# WSSC (Web Site Security Checker)

**Versiune:** `1.0.20251230` (format `Majora.Minora.YYYYMMDD`)

WSSC este un tool web pentru scanări pasive/semi-active de securitate (fără exploit-uri), cu:
- scanare HTTP/TLS/porturi comune + configurări uzuale
- detecție tehnologie/CMS și corelare cu o bază locală de referințe (CVE/intervale de versiuni)
- pagină admin pentru update prin Git și backup (download sau pe server)

## Cerințe
- PHP 8.4+
- Extensii PHP: `mysqli`, `curl`, `openssl`
- MySQL/MariaDB
- Pentru backup: extensia `zip` (ZipArchive)
- Pentru update automat din UI: `shell_exec` activ și `git` disponibil pe server (altfel update manual)

## Instalare (shared hosting / cPanel)
1. Urcă fișierele în webroot, de ex. `https://sec.e-bm.eu/WSSC/`
2. Rulează installer-ul o singură dată:
   - `https://sec.e-bm.eu/WSSC/install/first_use.php`
3. Completează:
   - DB host/port, DB name/user/pass
   - (opțional) cont MySQL cu privilegii pentru a crea DB + user (dacă ai)
   - contul de administrator (username/parolă) pentru zona de admin
4. După finalizare, șterge folderul `install` (automat din installer sau manual).

## Configurare
Config-ul este în `config/config.php` și este generat de installer.
Chei utile:
- `app.base_url` – URL-ul aplicației
- `app.version` – versiunea aplicației (format `Majora.Minora.YYYYMMDD`)
- `admin.update_allowed_ips` – allowlist IP pentru `/admin/*` (opțional)
- `admin.default_update_branch` – branch implicit pentru update

## Admin: update + backup
- Pagina de admin: `admin/update.php`
  - afișează versiunea/branch/commit (dacă `git` este disponibil)
  - update automat: `git fetch` + `git pull --ff-only origin <branch>`
  - backup:
    - download în browser (laptop)
    - sau scriere într-un folder din proiect (ex. `backups/`), protejat cu `.htaccess`
    - include un dump SQL în `backup/db.sql`

## Admin: populare automată vuln_db.json (surse CVE)
- Pagina: `admin/vuln_sources.php`
- Permite selectarea surselor publice, salvarea selecției și generarea fișierului `data/vuln_db.json`.
- Surse incluse:
  - NVD (NIST) CVE API 2.0 (CMS core + recent)
  - CISA KEV
  - CIRCL CVE Search

## Note de securitate
- După instalare, folderul `install/` trebuie șters.
- Restricționează accesul la admin prin `admin.update_allowed_ips` (recomandat).
- Nu rula aplicația pe domenii fără permisiune explicită.

## Licență
Vezi fișierul `LICENSE`.
