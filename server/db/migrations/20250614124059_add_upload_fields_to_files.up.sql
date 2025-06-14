ALTER TABLE files
    ADD COLUMN upload_finished    BOOLEAN  NOT NULL DEFAULT false,
    ADD COLUMN upload_finished_at DATETIME NULL; -- Can be NULL until finished
