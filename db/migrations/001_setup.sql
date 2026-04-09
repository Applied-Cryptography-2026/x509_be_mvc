-- Migration: 001_setup.sql
-- Creates the core x509 certificate management tables.

-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS certificates (
    id              INT UNSIGNED NOT NULL AUTO_INCREMENT,
    subject         VARCHAR(1024) NOT NULL COMMENT 'Certificate subject DN',
    issuer          VARCHAR(1024) NOT NULL COMMENT 'Issuer DN',
    serial          VARCHAR(128) NOT NULL COMMENT 'Serial number (hex)',
    fingerprint     VARCHAR(128) NOT NULL COMMENT 'SHA-256 fingerprint (colon-separated hex)',
    not_before      DATETIME NOT NULL COMMENT 'Validity start',
    not_after       DATETIME NOT NULL COMMENT 'Validity end',
    key_usage       JSON DEFAULT NULL COMMENT 'Key usage flags as JSON array',
    ext_key_usage   JSON DEFAULT NULL COMMENT 'Extended key usage as JSON array',
    dns_names       JSON DEFAULT NULL COMMENT 'SAN DNS names',
    ip_addresses    JSON DEFAULT NULL COMMENT 'SAN IP addresses',
    is_ca           BOOLEAN NOT NULL DEFAULT FALSE COMMENT 'Is this a CA certificate',
    is_revoked      BOOLEAN NOT NULL DEFAULT FALSE COMMENT 'Has this cert been revoked',
    revoked_at      DATETIME DEFAULT NULL COMMENT 'Revocation timestamp',
    crl_url         VARCHAR(512) DEFAULT NULL COMMENT 'CRL distribution point URL',
    ocsp_url        VARCHAR(512) DEFAULT NULL COMMENT 'OCSP responder URL',
    cert_pem        LONGTEXT NOT NULL COMMENT 'PEM-encoded certificate',
    key_pem         LONGTEXT DEFAULT NULL COMMENT 'PEM-encoded private key (encrypted at rest)',
    parent_id       INT UNSIGNED DEFAULT NULL COMMENT 'FK to issuer CA certificate',
    profile         VARCHAR(64) DEFAULT NULL COMMENT 'Profile: tls-server, tls-client, ca, etc.',
    status          VARCHAR(32) NOT NULL DEFAULT 'active' COMMENT 'active|expired|revoked|pending|hold',
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    deleted_at      DATETIME DEFAULT NULL COMMENT 'Soft-delete timestamp',

    PRIMARY KEY (id),
    UNIQUE KEY uq_serial (serial),
    UNIQUE KEY uq_fingerprint (fingerprint),
    INDEX idx_subject (subject(255)),
    INDEX idx_issuer (issuer(255)),
    INDEX idx_status (status),
    INDEX idx_profile (profile),
    INDEX idx_not_after (not_after),
    INDEX idx_parent_id (parent_id),
    CONSTRAINT fk_parent_cert FOREIGN KEY (parent_id) REFERENCES certificates(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_ci;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS certificates;
-- +goose StatementEnd
