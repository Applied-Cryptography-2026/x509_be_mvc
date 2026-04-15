-- Migration: 008_add_key_pair_id_to_csrs.sql
-- Links CSRs to the key pair used to generate them.

-- +goose Up
-- +goose StatementBegin

ALTER TABLE csrs
  ADD COLUMN key_pair_id INT UNSIGNED DEFAULT NULL COMMENT 'FK to key_pairs.id'
  AFTER requester_id;

CREATE INDEX idx_key_pair_id ON csrs(key_pair_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE csrs DROP COLUMN IF EXISTS key_pair_id;

-- +goose StatementEnd
