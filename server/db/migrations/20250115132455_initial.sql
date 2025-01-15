DROP TABLE IF EXISTS file_edition;
DROP TABLE IF EXISTS files;
DROP TABLE IF EXISTS users;

--
--      USERS
--

CREATE OR REPLACE TABLE users
(
    id         UUID         NOT NULL PRIMARY KEY DEFAULT UUID(),
    first_name VARCHAR(64)  NOT NULL,
    last_name  VARCHAR(64),

    email      VARCHAR(255) NOT NULL,

    password   CHAR(97)     NOT NULL
);

--
--      FILES
--

CREATE OR REPLACE TABLE files
(
    file_id       UUID     NOT NULL PRIMARY KEY DEFAULT UUID(),
    owner_id      UUID     NOT NULL,
    creation_date DATETIME NOT NULL             DEFAULT NOW(),
    signature     CHAR(64) NOT NULL,
    path          TEXT     NOT NULL,

    FOREIGN KEY (owner_id) REFERENCES users (id)
);

CREATE OR REPLACE TABLE file_edition
(
    modification_id   INT      NOT NULL AUTO_INCREMENT PRIMARY KEY,
    author_id         UUID     NOT NULL,
    file_edited       UUID     NOT NULL,
    modification_date DATETIME NOT NULL DEFAULT NOW(),
    file_signature    CHAR(64) NOT NULL,

    FOREIGN KEY (author_id) REFERENCES users (id),
    FOREIGN KEY (file_edited) REFERENCES files (file_id)
);
