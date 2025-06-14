DROP TABLE upload_sessions;

ALTER TABLE files
    DROP COLUMN upload_finished;
ALTER TABLE files
    DROP COLUMN upload_finished_at;
