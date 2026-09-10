-- Initial MilterGuard persistent-state schema. Timestamps are Unix
-- milliseconds in UTC.

CREATE TABLE ip_reputation (
    id                  INTEGER PRIMARY KEY,
    ip                  TEXT NOT NULL UNIQUE,
    block_level         TEXT CHECK (block_level IN ('short', 'repeat')),
    blocked_until_ms    INTEGER,
    legitimate_count    INTEGER NOT NULL DEFAULT 0 CHECK (legitimate_count >= 0),
    last_activity_at_ms INTEGER NOT NULL,
    CHECK (
        (block_level IS NULL AND blocked_until_ms IS NULL) OR
        (block_level IS NOT NULL AND blocked_until_ms IS NOT NULL)
    )
);

CREATE TABLE ip_strikes (
    id               INTEGER PRIMARY KEY,
    ip_reputation_id INTEGER NOT NULL REFERENCES ip_reputation(id) ON DELETE CASCADE,
    struck_at_ms     INTEGER NOT NULL
);

CREATE INDEX ip_reputation_blocked_until_idx
    ON ip_reputation(blocked_until_ms) WHERE blocked_until_ms IS NOT NULL;
CREATE INDEX ip_reputation_last_activity_idx ON ip_reputation(last_activity_at_ms);
CREATE INDEX ip_strikes_struck_at_idx ON ip_strikes(struck_at_ms);
CREATE INDEX ip_strikes_reputation_time_idx
    ON ip_strikes(ip_reputation_id, struck_at_ms);

CREATE TABLE correspondents (
    id                     INTEGER PRIMARY KEY,
    local_address          TEXT NOT NULL,
    correspondent          TEXT NOT NULL,
    learned_at_ms          INTEGER NOT NULL,
    last_activity_at_ms    INTEGER NOT NULL,
    whitelist_type         TEXT NOT NULL CHECK (whitelist_type IN (
                               'authenticated_outbound',
                               'repeated_legitimate_inbound',
                               'manual'
                           )),
    legitimate_email_count INTEGER NOT NULL DEFAULT 0 CHECK (legitimate_email_count >= 0),
    UNIQUE (local_address, correspondent)
);

CREATE INDEX correspondents_correspondent_idx ON correspondents(correspondent);
CREATE INDEX correspondents_local_activity_idx
    ON correspondents(local_address, last_activity_at_ms DESC);
CREATE INDEX correspondents_last_activity_idx ON correspondents(last_activity_at_ms);

CREATE TABLE rejections (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    sender         TEXT NOT NULL,
    subject        TEXT NOT NULL DEFAULT '',
    rejected_at_ms INTEGER NOT NULL,
    reason         TEXT NOT NULL DEFAULT ''
);

CREATE TABLE rejection_recipients (
    rejection_id INTEGER NOT NULL REFERENCES rejections(id) ON DELETE CASCADE,
    recipient    TEXT NOT NULL,
    PRIMARY KEY (rejection_id, recipient)
);

CREATE INDEX rejections_rejected_at_idx ON rejections(rejected_at_ms DESC);
CREATE INDEX rejection_recipients_recipient_idx
    ON rejection_recipients(recipient, rejection_id);

CREATE TABLE domain_registrations (
    id               INTEGER PRIMARY KEY,
    domain           TEXT NOT NULL UNIQUE,
    registered_at_ms INTEGER NOT NULL,
    expires_at_ms    INTEGER NOT NULL,
    CHECK (expires_at_ms >= registered_at_ms)
);

CREATE INDEX domain_registrations_expires_at_idx
    ON domain_registrations(expires_at_ms);
