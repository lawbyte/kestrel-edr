-- Security review 2026-10-21 (server side).

-- H2: enrollment never re-binds an existing device; hardware-UUID matches are
-- flagged on both devices for an admin to merge / decommission / dismiss.
ALTER TABLE devices ADD COLUMN possible_duplicate_ids uuid[] NOT NULL DEFAULT '{}';
-- M5: per-device uninstall token (sealed with the master key). `pending` holds a
-- rotated token until the agent can be told about it.
ALTER TABLE devices ADD COLUMN uninstall_token_enc text;
ALTER TABLE devices ADD COLUMN uninstall_token_pending_enc text;
-- M8: agent outbox epoch; a change resets last_agent_seq.
ALTER TABLE devices ADD COLUMN outbox_epoch uuid;

-- H3: renewal bookkeeping. The certificate a renewal replaced is revoked once the
-- device connects with the new one.
ALTER TABLE agent_certs ADD COLUMN replaces_serial text;
ALTER TABLE agent_certs ADD COLUMN last_used_at bigint;

-- L1: last accepted TOTP time step (replay protection).
ALTER TABLE users ADD COLUMN totp_last_step bigint;

-- L2: API token expiry (NULL only for tokens created before this migration).
ALTER TABLE api_tokens ADD COLUMN expires_at bigint;

-- Structured action results (ActionOutcome.artifact).
ALTER TABLE response_actions ADD COLUMN artifact text;
