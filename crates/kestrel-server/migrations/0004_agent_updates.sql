-- Signed agent auto-update with staged rings (canary → early → broad).
-- The server never holds the signing key: releases are manifests signed
-- offline and verified against KESTREL_UPDATE_PUBKEY at registration.

-- Rollout ring of every device in the group; 'pinned' never auto-updates.
ALTER TABLE groups ADD COLUMN update_ring text NOT NULL DEFAULT 'broad'
    CHECK (update_ring IN ('canary', 'early', 'broad', 'pinned'));

CREATE TABLE agent_releases (
    id          uuid PRIMARY KEY,
    version     text NOT NULL UNIQUE,
    url         text NOT NULL,
    sha256      text NOT NULL,
    signature   text NOT NULL,
    notes       text NOT NULL DEFAULT '',
    created_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at  bigint NOT NULL,
    -- Halting is terminal: no further deliveries; updated agents stay updated.
    halted_at   bigint,
    halted_by   uuid REFERENCES users(id) ON DELETE SET NULL,
    halt_reason text NOT NULL DEFAULT ''
);

-- Rings a release was promoted to (a release starts with none).
CREATE TABLE agent_release_rings (
    release_id  uuid NOT NULL REFERENCES agent_releases(id) ON DELETE CASCADE,
    ring        text NOT NULL CHECK (ring IN ('canary', 'early', 'broad')),
    enabled_at  bigint NOT NULL,
    enabled_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    PRIMARY KEY (release_id, ring)
);

-- Per-device delivery and outcome. 'sent' → 'succeeded' when a later Hello
-- reports the new version, 'failed' when the agent reports an UpdateResult.
CREATE TABLE agent_update_deliveries (
    release_id    uuid NOT NULL REFERENCES agent_releases(id) ON DELETE CASCADE,
    device_id     uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    ring          text NOT NULL,
    from_version  text NOT NULL DEFAULT '',
    first_sent_at bigint NOT NULL,
    last_sent_at  bigint NOT NULL,
    attempts      int NOT NULL DEFAULT 1,
    status        text NOT NULL DEFAULT 'sent' CHECK (status IN ('sent', 'succeeded', 'failed')),
    completed_at  bigint,
    error         text NOT NULL DEFAULT '',
    PRIMARY KEY (release_id, device_id)
);
CREATE INDEX agent_update_deliveries_device_idx ON agent_update_deliveries (device_id);
