CREATE OR REPLACE PROCEDURE clear_old_upload_data()
BEGIN
    CREATE TEMPORARY TABLE IF NOT EXISTS files_to_delete (
        file_id UUID PRIMARY KEY
    );

    CREATE TEMPORARY TABLE IF NOT EXISTS cleaned_session_ids (
        session_id VARCHAR(36) PRIMARY KEY
    );

    INSERT INTO cleaned_session_ids (session_id)
    SELECT us.id
    FROM upload_sessions us
    WHERE (
        (us.status = 'pending' AND us.expires_at < NOW())
        OR(us.status IN ('failed', 'cancelled') AND us.updated_at < NOW() - INTERVAL 1 DAY)
    );

    INSERT INTO files_to_delete (file_id)
    SELECT DISTINCT us.file_id
    FROM upload_sessions us
    JOIN files f ON us.file_id = f.file_id
    WHERE us.id IN (SELECT session_id FROM cleaned_session_ids)
        AND f.upload_finished = FALSE;

    START TRANSACTION;

    DELETE FROM upload_sessions
    WHERE id IN (SELECT session_id FROM cleaned_session_ids);

    DELETE FROM file_edition
    WHERE file_edited IN (SELECT file_id FROM files_to_delete);

    DELETE FROM files
    WHERE file_id IN (SELECT file_id FROM files_to_delete);

    COMMIT;

    SELECT session_id FROM cleaned_session_ids;

    DROP TEMPORARY TABLE IF EXISTS files_to_delete;
    DROP TEMPORARY TABLE IF EXISTS cleaned_session_ids;
END;
