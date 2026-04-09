-- Migration: 004_users.sql
-- Creates the users table for authentication.

-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS users (
    id          INT UNSIGNED NOT NULL AUTO_INCREMENT,
    username    VARCHAR(50) NOT NULL COMMENT 'Unique username',
    password    VARCHAR(255) NOT NULL COMMENT 'bcrypt hashed password',
    name        VARCHAR(255) DEFAULT NULL COMMENT 'Display name',
    role        VARCHAR(20) NOT NULL DEFAULT 'customer' COMMENT 'admin|customer',
    email       VARCHAR(255) DEFAULT NULL COMMENT 'Email address',
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    deleted_at  DATETIME DEFAULT NULL COMMENT 'Soft-delete timestamp',

    PRIMARY KEY (id),
    UNIQUE KEY uq_username (username),
    INDEX idx_role (role)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_ci;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS users;
-- +goose StatementEnd