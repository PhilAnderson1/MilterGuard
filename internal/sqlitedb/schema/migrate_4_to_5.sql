DROP INDEX activity_occurred_at_idx;
ALTER TABLE activity RENAME TO activity_v4;

CREATE TABLE activity (
    id               INTEGER PRIMARY KEY,
    occurred_at_ms   INTEGER NOT NULL,
    event_type       INTEGER NOT NULL CHECK (event_type IN (1, 2, 3, 4, 5, 6, 7, 8)),
    outcome          INTEGER NOT NULL CHECK (outcome IN (1, 2, 3, 4)),
    analysis_failed  INTEGER CHECK (analysis_failed IN (0, 1)),
    token_cost       REAL CHECK (token_cost >= 0),
    quantity         INTEGER NOT NULL DEFAULT 1 CHECK (quantity > 0),
    CHECK (
        (event_type = 1 AND analysis_failed IS NOT NULL AND token_cost IS NOT NULL)
        OR
        (event_type IN (2, 3, 4, 5, 6, 7, 8) AND analysis_failed IS NULL AND token_cost IS NULL)
    ),
    CHECK (
        event_type = 1
        OR (event_type IN (2, 5, 6) AND outcome IN (2, 4))
        OR (event_type IN (3, 4) AND outcome IN (1, 4))
        OR (event_type = 7 AND outcome IN (1, 2))
        OR (event_type = 8 AND outcome IN (1, 2, 4))
    )
);

INSERT INTO activity
    (id, occurred_at_ms, event_type, outcome, analysis_failed, token_cost, quantity)
SELECT id, occurred_at_ms, event_type, outcome, analysis_failed, token_cost, quantity
FROM activity_v4;

DROP TABLE activity_v4;
CREATE INDEX activity_occurred_at_idx ON activity(occurred_at_ms);
