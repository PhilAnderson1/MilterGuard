DROP INDEX activity_occurred_at_idx;
ALTER TABLE activity RENAME TO activity_v5;

CREATE TABLE activity (
    id               INTEGER PRIMARY KEY,
    occurred_at_ms   INTEGER NOT NULL,
    event_type       INTEGER NOT NULL CHECK (event_type > 0),
    outcome          INTEGER NOT NULL CHECK (outcome IN (1, 2, 3, 4)),
    analysis_failed  INTEGER CHECK (analysis_failed IN (0, 1)),
    token_cost       REAL CHECK (token_cost >= 0),
    quantity         INTEGER NOT NULL DEFAULT 1 CHECK (quantity > 0),
    CHECK (
        (event_type = 1 AND analysis_failed IS NOT NULL AND token_cost IS NOT NULL)
        OR
        (event_type <> 1 AND analysis_failed IS NULL AND token_cost IS NULL)
    )
);

INSERT INTO activity
    (id, occurred_at_ms, event_type, outcome, analysis_failed, token_cost, quantity)
SELECT id, occurred_at_ms, event_type, outcome, analysis_failed, token_cost, quantity
FROM activity_v5;

DROP TABLE activity_v5;
CREATE INDEX activity_occurred_at_idx ON activity(occurred_at_ms);
