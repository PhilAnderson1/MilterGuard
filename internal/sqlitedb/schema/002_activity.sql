-- Activity reporting and the singleton status of the serving process.

CREATE TABLE activity (
    id               INTEGER PRIMARY KEY,
    occurred_at_ms   INTEGER NOT NULL,
    event_type       INTEGER NOT NULL CHECK (event_type IN (1, 2, 3, 4, 5, 6)),
    outcome          INTEGER NOT NULL CHECK (outcome IN (1, 2, 3, 4)),
    analysis_failed  INTEGER CHECK (analysis_failed IN (0, 1)),
    token_cost       REAL CHECK (token_cost >= 0),
    CHECK (
        (event_type = 1 AND analysis_failed IS NOT NULL AND token_cost IS NOT NULL)
        OR
        (event_type IN (2, 3, 4, 5, 6) AND analysis_failed IS NULL AND token_cost IS NULL)
    ),
    CHECK (
        event_type = 1
        OR (event_type IN (2, 5, 6) AND outcome IN (2, 4))
        OR (event_type IN (3, 4) AND outcome IN (1, 4))
    )
);

CREATE INDEX activity_occurred_at_idx ON activity(occurred_at_ms);

CREATE TABLE service_status (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    started_at_ms INTEGER NOT NULL,
    mode          INTEGER NOT NULL CHECK (mode IN (1, 2))
);
