-- Evidence capture for suspected data theft (owner decision 2026-10-25,
-- docs/DECISIONS.md). One row per bundle the agent captured after an ST-02 /
-- ST-04 alert. Only metadata lives here (the privacy-filtered manifest the
-- agent reported, scrubbed again by the server); the bundle content stays on
-- the PC until an administrator collects it, then lives sealed in
-- KESTREL_EVIDENCE_DIR (`<id>.kes`). Nothing of it is ever written to the
-- telemetry store.
--
-- status: capturing | ready_on_device | collecting | stored | failed | expired | deleted
CREATE TABLE evidence_bundles (
    id                    uuid PRIMARY KEY,
    device_id             uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    alert_id              uuid NOT NULL,
    alert_ids             uuid[] NOT NULL DEFAULT '{}',
    rule_id               text NOT NULL,
    status                text NOT NULL CHECK (status IN ('capturing','ready_on_device','collecting','stored','failed','expired','deleted')),
    manifest              jsonb,
    bundle_size           bigint NOT NULL DEFAULT 0,
    bundle_sha256         text,
    created_at            bigint NOT NULL,
    captured_at           bigint,
    local_expires_at      bigint,
    collect_action_id     uuid,
    collect_requested_at  bigint,
    collect_requested_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    collected_at          bigint,
    stored_size           bigint,
    expires_at            bigint,
    deleted_at            bigint,
    deleted_by            uuid REFERENCES users(id) ON DELETE SET NULL,
    last_error            text,
    attempts              int NOT NULL DEFAULT 0,
    -- A failed upload is retried once automatically when the PC reconnects.
    auto_retry            boolean NOT NULL DEFAULT false,
    -- Random per-bundle data key of the sealed blob, wrapped with the master
    -- key (MasterKey::seal). NULLed on deletion / expiry (crypto-shredding).
    data_key_enc          text,
    downloads             int NOT NULL DEFAULT 0,
    last_downloaded_at    bigint,
    updated_at            bigint NOT NULL
);

CREATE INDEX evidence_bundles_device_idx ON evidence_bundles (device_id, created_at DESC);
CREATE INDEX evidence_bundles_alert_ids_idx ON evidence_bundles USING gin (alert_ids);
CREATE INDEX evidence_bundles_status_idx ON evidence_bundles (status, expires_at);
CREATE INDEX evidence_bundles_created_idx ON evidence_bundles (created_at DESC);
