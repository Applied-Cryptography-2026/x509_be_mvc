-- Migration: 006_add_requester_id.sql
-- Adds requester_id to certificates table to link issued certs to customers.

-- +goose Up
-- +goose StatementBegin

ALTER TABLE certificates
  ADD COLUMN requester_id INT UNSIGNED DEFAULT NULL COMMENT 'FK to the customer who submitted the CSR'
  AFTER parent_id;

CREATE INDEX idx_requester_id ON certificates(requester_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE certificates DROP COLUMN IF EXISTS requester_id;

-- +goose StatementEnd
