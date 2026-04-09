-- Migration: 005_refresh_tokens.sql
-- Creates the refresh_tokens table for JWT token rotation.

-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          INT UNSIGNED NOT NULL AUTO_INCREMENT,
    token_id    VARCHAR(64) NOT NULL COMMENT 'JWT jti claim (unique token identifier)',
    user_id     INT UNSIGNED NOT NULL COMMENT 'FK to users table',
    expires_at  DATETIME NOT NULL COMMENT 'Token expiration time',
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at  DATETIME DEFAULT NULL COMMENT 'Timestamp when token was revoked',
    is_used     BOOLEAN NOT NULL DEFAULT FALSE COMMENT 'Whether token has been used for rotation',

    PRIMARY KEY (id),
    UNIQUE KEY uq_token_id (token_id),
    INDEX idx_user_id (user_id),
    INDEX idx_expires_at (expires_at),
    CONSTRAINT fk_refresh_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_ci;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS refresh_tokens;
-- +goose StatementEnd