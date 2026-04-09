-- Migration: 003_chains.sql
-- Creates the certificate_chains table for trust chain management.

-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS certificate_chains (
    id          INT UNSIGNED NOT NULL AUTO_INCREMENT,
    name        VARCHAR(255) NOT NULL COMMENT 'Human-readable name for the chain',
    chain_type  VARCHAR(64) NOT NULL DEFAULT 'custom' COMMENT 'tls-server|tls-client|code-signing|smime|custom',
    cert_ids    JSON NOT NULL COMMENT 'Ordered list of certificate IDs (leaf first)',
    pem_chain   LONGTEXT NOT NULL COMMENT 'Concatenated PEM chain (leaf → root)',
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    deleted_at  DATETIME DEFAULT NULL COMMENT 'Soft-delete timestamp',

    PRIMARY KEY (id),
    UNIQUE KEY uq_name (name),
    INDEX idx_chain_type (chain_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_ci;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS certificate_chains;
-- +goose StatementEnd
