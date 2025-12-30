CREATE TABLE IF NOT EXISTS scans (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  domain VARCHAR(253) NOT NULL,
  mode ENUM('quick','full') NOT NULL,
  status ENUM('queued','running','done','error') NOT NULL,
  progress TINYINT UNSIGNED NOT NULL DEFAULT 0,
  next_step INT UNSIGNED NOT NULL DEFAULT 0,
  resolved_ip VARCHAR(45) NOT NULL,
  result_json MEDIUMTEXT NULL,
  error_message TEXT NULL,
  created_ip VARCHAR(45) NOT NULL DEFAULT '',
  session_hash CHAR(64) NOT NULL DEFAULT '',
  created_at DATETIME NOT NULL,
  started_at DATETIME NULL,
  finished_at DATETIME NULL,
  PRIMARY KEY (id),
  INDEX idx_scans_domain (domain),
  INDEX idx_scans_created_at (created_at),
  INDEX idx_scans_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS rate_limits (
  ip VARCHAR(45) NOT NULL,
  window_start INT UNSIGNED NOT NULL,
  count INT UNSIGNED NOT NULL,
  PRIMARY KEY (ip, window_start)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS audit_log (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  ip VARCHAR(45) NOT NULL,
  event VARCHAR(120) NOT NULL,
  meta_json MEDIUMTEXT NULL,
  created_at DATETIME NOT NULL,
  PRIMARY KEY (id),
  INDEX idx_audit_created_at (created_at),
  INDEX idx_audit_ip (ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS users (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  username VARCHAR(64) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role VARCHAR(32) NOT NULL,
  is_disabled TINYINT(1) NOT NULL DEFAULT 0,
  last_login_at DATETIME NULL,
  created_at DATETIME NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_users_username (username),
  INDEX idx_users_role (role),
  INDEX idx_users_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
