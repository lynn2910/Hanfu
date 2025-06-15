-- Add migration script here
ALTER TABLE files
    ADD COLUMN iv VARCHAR(32) NOT NULL,
    ADD COLUMN total_size BIGINT NOT NULL;