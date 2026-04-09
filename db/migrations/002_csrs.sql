-- Migration: 002_csrs.sql
-- Creates the CSRs table for Certificate Signing Request management.

-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS csrs (
    id                  INT UNSIGNED NOT NULL AUTO_INCREMENT,
    subject             VARCHAR(1024) NOT NULL COMMENT 'CN requested by the requester',
    pem                 LONGTEXT NOT NULL COMMENT 'PEM-encoded CSR',
    key_algorithm       VARCHAR(64) DEFAULT NULL COMMENT 'RSA, ECDSA, Ed25519',
    signature_algorithm  VARCHAR(64) DEFAULT NULL COMMENT 'e.g. SHA256 and RSA',
    dns_names           JSON DEFAULT NULL COMMENT 'SAN DNS names from CSR',
    ip_addresses        JSON DEFAULT NULL COMMENT 'SAN IP addresses from CSR',
    status              VARCHAR(32) NOT NULL DEFAULT 'pending' COMMENT 'pending|approved|rejected|issued',
    approved_at         DATETIME DEFAULT NULL COMMENT 'Timestamp of approval',
    rejected_at         DATETIME DEFAULT NULL COMMENT 'Timestamp of rejection',
    approver_id         INT UNSIGNED DEFAULT NULL COMMENT 'FK to users table (admin who approved/rejected)',
    notes               TEXT DEFAULT NULL COMMENT 'Admin notes on rejection',
    requester_id        INT UNSIGNED NOT NULL COMMENT 'FK to users table (customer who submitted)',
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    deleted_at          DATETIME DEFAULT NULL COMMENT 'Soft-delete timestamp',

    PRIMARY KEY (id),
    INDEX idx_status (status),
    INDEX idx_requester_id (requester_id),
    INDEX idx_approver_id (approver_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_ci;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS csrs;
-- +goose StatementEnd
