-- Session schema. One case per database file (docs/05-data-model.md).

CREATE TABLE IF NOT EXISTS case_meta (
    case_id     VARCHAR PRIMARY KEY,
    input_dir   VARCHAR NOT NULL,
    started_at  TIMESTAMP NOT NULL,
    finished_at TIMESTAMP,
    status      VARCHAR NOT NULL,
    rule_set    VARCHAR,
    app_version VARCHAR NOT NULL
);

CREATE TABLE IF NOT EXISTS files (
    file_id      UINTEGER PRIMARY KEY,
    path         VARCHAR NOT NULL,
    size_bytes   UBIGINT NOT NULL,
    sha256       VARCHAR,
    log_type     VARCHAR NOT NULL,
    confidence   VARCHAR,
    record_count UBIGINT,
    status       VARCHAR NOT NULL,
    note         VARCHAR
);

CREATE TABLE IF NOT EXISTS events (
    event_id          UBIGINT PRIMARY KEY,
    file_id           UINTEGER NOT NULL,
    record_index      UBIGINT NOT NULL,
    event_time        TIMESTAMP,
    event_source      VARCHAR,
    event_name        VARCHAR,
    aws_region        VARCHAR,
    account_id        VARCHAR,
    source_ip         VARCHAR,
    user_agent        VARCHAR,
    identity_type     VARCHAR,
    identity_arn      VARCHAR,
    identity_name     VARCHAR,
    mfa_authenticated BOOLEAN,
    error_code        VARCHAR,
    error_message     VARCHAR,
    read_only         BOOLEAN,
    management_event  BOOLEAN,
    request           JSON,
    response          JSON,
    resources         JSON,
    raw               JSON
);

-- Rules used for the stored matches, so results stay explainable when the
-- case directory is copied without the rule files.
CREATE TABLE IF NOT EXISTS rules (
    rule_id     VARCHAR PRIMARY KEY,
    severity    VARCHAR NOT NULL,
    description VARCHAR NOT NULL
);
-- Added after the first cases shipped; NULL means the rule applies to
-- every log type (rule `meta: log_type` absent).
ALTER TABLE rules ADD COLUMN IF NOT EXISTS log_type VARCHAR;
-- Rules are registered at parse time and evaluated when first opened. Older
-- cases were evaluated in full at parse time, hence the default.
ALTER TABLE rules ADD COLUMN IF NOT EXISTS evaluated BOOLEAN DEFAULT true;
-- Display name (`meta: name`); NULL on rows from builds without it, read
-- back as the rule id.
ALTER TABLE rules ADD COLUMN IF NOT EXISTS name VARCHAR;

-- One row per rule hit. The event summary the results table shows is copied
-- in when the hit is recorded, so listing, counting, searching and scoping
-- matches never touch `events` (docs/05 "룰 매치 요약"). Cases written
-- before these columns existed are rebuilt in `Store::open`.
CREATE TABLE IF NOT EXISTS rule_matches (
    match_id       UBIGINT PRIMARY KEY,
    rule_id        VARCHAR NOT NULL,
    event_id       UBIGINT NOT NULL,
    matched_fields JSON NOT NULL,
    log_type       VARCHAR NOT NULL,
    event_time     TIMESTAMP,
    event_name     VARCHAR,
    event_source   VARCHAR,
    identity_arn   VARCHAR,
    source_ip      VARCHAR,
    user_agent     VARCHAR,
    aws_region     VARCHAR,
    error_code     VARCHAR,
    url            VARCHAR,
    status         VARCHAR,
    target         VARCHAR,
    resource       VARCHAR,
    country        VARCHAR,
    rule           VARCHAR,
    method         VARCHAR
);

-- Leaf paths seen inside the payload columns while parsing, per log type,
-- with the number of events that carried each (docs/04 "페이로드 키"). The
-- rule editor offers these; nothing has to be declared before parsing.
CREATE TABLE IF NOT EXISTS payload_keys (
    log_type VARCHAR NOT NULL,
    path     VARCHAR NOT NULL,
    events   UBIGINT NOT NULL
);
