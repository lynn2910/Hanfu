-- Add migration script here
ALTER TABLE files
    DROP COLUMN iv,
    DROP COLUMN total_size;