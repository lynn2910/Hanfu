CREATE TABLE IF NOT EXISTS upload_sessions
(
    id             VARCHAR(36)                                          NOT NULL PRIMARY KEY,
    user_id        VARCHAR(36)                                          NOT NULL,
    file_name      VARCHAR(255)                                         NOT NULL,
    total_size     BIGINT                                               NOT NULL,
    iv             VARCHAR(32)                                          NOT NULL,
    uploaded_bytes BIGINT                                               NOT NULL DEFAULT 0,
    status         ENUM ('pending', 'completed', 'failed', 'cancelled') NOT NULL DEFAULT 'pending',

    file_id        VARCHAR(36)                                          NOT NULL,

    created_at     DATETIME                                             NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     DATETIME                                             NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    expires_at     DATETIME,

    FOREIGN KEY (user_id) REFERENCES users (id),
    FOREIGN KEY (file_id) REFERENCES files (file_id)
);

CREATE INDEX idx_upload_sessions_user_id ON upload_sessions (user_id);
CREATE INDEX idx_upload_sessions_status ON upload_sessions (status);
