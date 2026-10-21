-- Security re-review v1.1 NEW-5: dead letters stored the decoded agent
-- payload *before* the server-side privacy scrub (up to 64 KB per row, no
-- retention, no cap). They now keep metadata only: the payload's length and
-- SHA-256 (enough to match it against the agent's outbox or logs), never its
-- content. The table is new in this release and holds nothing worth keeping,
-- so it is recreated. Rows expire after 30 days and each device keeps at most
-- its newest 1000 (enforced on insert and by the hourly retention job).
DROP TABLE IF EXISTS ingest_dead_letters;
CREATE TABLE ingest_dead_letters (
    id             bigserial PRIMARY KEY,
    device_id      uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    seq            bigint NOT NULL,
    payload_type   text NOT NULL,
    error          text NOT NULL,
    payload_bytes  bigint NOT NULL,
    payload_sha256 text NOT NULL,
    received_at    bigint NOT NULL
);
CREATE INDEX ingest_dead_letters_device_idx ON ingest_dead_letters (device_id, received_at DESC, id DESC);
CREATE INDEX ingest_dead_letters_received_idx ON ingest_dead_letters (received_at);
