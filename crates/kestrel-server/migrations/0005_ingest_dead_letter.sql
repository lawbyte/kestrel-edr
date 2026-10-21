-- Security review v1.1 V-L4: agent messages the database rejects for their
-- content (specific SQLSTATE class-22 errors) are acked so they cannot wedge
-- the agent's outbox, but are kept here for an administrator to inspect
-- instead of being silently dropped. The payload is the decoded JSON,
-- truncated to 64 KB.
CREATE TABLE ingest_dead_letters (
    id           bigserial PRIMARY KEY,
    device_id    uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    seq          bigint NOT NULL,
    payload_type text NOT NULL,
    error        text NOT NULL,
    received_at  bigint NOT NULL,
    payload      bytea NOT NULL,
    truncated    boolean NOT NULL DEFAULT false
);
CREATE INDEX ingest_dead_letters_device_idx ON ingest_dead_letters (device_id, received_at DESC);
