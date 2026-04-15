-- Migration: 007_key_pairs.sql
-- Creates the key_pairs table for storing customer-generated cryptographic key pairs.

-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS key_pairs (
    id               INT UNSIGNED NOT NULL AUTO_INCREMENT,
    name             VARCHAR(255) NOT NULL,
    algorithm        VARCHAR(16) NOT NULL,
    key_size         INT UNSIGNED NOT NULL,
    public_key_pem   LONGTEXT NOT NULL,
    private_key_pem  LONGTEXT NOT NULL,
    fingerprint      VARCHAR(128) NOT NULL,
    owner_id         INT UNSIGNED NOT NULL,
    created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at       DATETIME DEFAULT NULL,

    PRIMARY KEY (id),
    INDEX idx_owner_id (owner_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_ci;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS key_pairs;

-- +goose StatementEnd
