-- Kestrel EDR control plane schema.
-- All timestamps are ms since epoch (bigint) to match the REST contract.

CREATE OR REPLACE FUNCTION kestrel_now_ms() RETURNS bigint
LANGUAGE sql VOLATILE AS $$ SELECT (extract(epoch from clock_timestamp()) * 1000)::bigint $$;

-- Singleton org/settings row (id = 1). Secrets live encrypted in `secrets_enc`.
CREATE TABLE settings (
    id              int PRIMARY KEY CHECK (id = 1),
    org_name        text NOT NULL DEFAULT '',
    body            jsonb NOT NULL,
    secrets_enc     text,
    rules_version   bigint NOT NULL DEFAULT 1,
    created_at      bigint NOT NULL DEFAULT kestrel_now_ms(),
    updated_at      bigint NOT NULL DEFAULT kestrel_now_ms()
);

-- Encrypted server material (agent CA, self-signed web certificate).
CREATE TABLE server_secrets (
    name        text PRIMARY KEY,
    data        jsonb NOT NULL,
    created_at  bigint NOT NULL DEFAULT kestrel_now_ms()
);

CREATE TABLE roles (
    name        text PRIMARY KEY,
    description text NOT NULL DEFAULT '',
    privileges  text[] NOT NULL,
    builtin     boolean NOT NULL DEFAULT false
);

CREATE TABLE users (
    id              uuid PRIMARY KEY,
    email           text NOT NULL,
    name            text NOT NULL DEFAULT '',
    password_hash   text,
    role            text NOT NULL REFERENCES roles(name) ON UPDATE CASCADE,
    disabled        boolean NOT NULL DEFAULT false,
    mfa_enabled     boolean NOT NULL DEFAULT false,
    totp_secret_enc text,
    oidc_sub        text,
    last_login      bigint,
    created_at      bigint NOT NULL DEFAULT kestrel_now_ms()
);
CREATE UNIQUE INDEX users_email_idx ON users (lower(email));
CREATE UNIQUE INDEX users_oidc_sub_idx ON users (oidc_sub) WHERE oidc_sub IS NOT NULL;

CREATE TABLE sessions (
    token_hash  text PRIMARY KEY,
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token  text NOT NULL,
    auth_method text NOT NULL DEFAULT 'password',
    ip          text,
    user_agent  text,
    created_at  bigint NOT NULL,
    last_seen   bigint NOT NULL,
    expires_at  bigint NOT NULL
);
CREATE INDEX sessions_user_idx ON sessions (user_id);

CREATE TABLE api_tokens (
    id          uuid PRIMARY KEY,
    name        text NOT NULL,
    token_hash  text NOT NULL UNIQUE,
    prefix      text NOT NULL,
    privileges  text[] NOT NULL,
    created_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at  bigint NOT NULL,
    last_used   bigint
);

-- Global, monotonic policy version source: moving a device between policies
-- must never hand it a version lower than the one it already applied.
CREATE SEQUENCE policy_version_seq START 1;

CREATE TABLE policies (
    id          text PRIMARY KEY,
    name        text NOT NULL,
    version     bigint NOT NULL,
    body        jsonb NOT NULL,
    created_at  bigint NOT NULL,
    updated_at  bigint NOT NULL
);

CREATE TABLE groups (
    id          uuid PRIMARY KEY,
    name        text NOT NULL UNIQUE,
    description text NOT NULL DEFAULT '',
    policy_id   text NOT NULL REFERENCES policies(id),
    is_default  boolean NOT NULL DEFAULT false,
    created_at  bigint NOT NULL
);

CREATE TABLE enrollment_tokens (
    id          uuid PRIMARY KEY,
    group_id    uuid NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    token_hash  text NOT NULL UNIQUE,
    token_prefix text NOT NULL,
    created_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at  bigint NOT NULL,
    expires_at  bigint NOT NULL,
    max_uses    int NOT NULL,
    uses        int NOT NULL DEFAULT 0,
    revoked     boolean NOT NULL DEFAULT false
);

CREATE TABLE devices (
    id                      uuid PRIMARY KEY,
    hostname                text NOT NULL,
    os_name                 text NOT NULL DEFAULT '',
    os_build                text NOT NULL DEFAULT '',
    arch                    text NOT NULL DEFAULT '',
    domain                  text,
    hw_uuid                 text,
    agent_version           text NOT NULL DEFAULT '',
    group_id                uuid REFERENCES groups(id) ON DELETE SET NULL,
    tags                    text[] NOT NULL DEFAULT '{}',
    first_seen              bigint NOT NULL,
    last_seen               bigint NOT NULL,
    ip_addresses            text[] NOT NULL DEFAULT '{}',
    logged_on_user          text,
    health                  jsonb NOT NULL DEFAULT '{}',
    boot_id                 text,
    policy_version_applied  bigint NOT NULL DEFAULT 0,
    rules_version_applied   bigint NOT NULL DEFAULT 0,
    last_hb_seq             bigint,
    -- High-water mark of agent envelope seqs durably processed (outbox dedupe).
    last_agent_seq          bigint NOT NULL DEFAULT 0,
    last_hb_ts              bigint,
    etw_lost_increased_at   bigint,
    tamper_state            jsonb NOT NULL DEFAULT '{}',
    status                  text NOT NULL DEFAULT 'offline',
    inventory               jsonb NOT NULL DEFAULT '{}',
    inventory_updated_at    bigint,
    decommissioned_at       bigint
);
CREATE INDEX devices_group_idx ON devices (group_id);
CREATE INDEX devices_hw_uuid_idx ON devices (hw_uuid);

-- Device status rule from docs/contracts.md.
CREATE OR REPLACE FUNCTION device_status(health jsonb, last_seen bigint, lost_at bigint) RETURNS text
LANGUAGE sql VOLATILE AS $$
SELECT CASE
    WHEN COALESCE((health->>'isolated')::boolean, false) THEN 'isolated'
    WHEN last_seen < kestrel_now_ms() - 180000 THEN 'offline'
    WHEN NOT COALESCE((health->>'etw_ok')::boolean, false)
         OR COALESCE(lost_at, 0) > kestrel_now_ms() - 3600000 THEN 'degraded'
    ELSE 'online'
END $$;

CREATE TABLE agent_certs (
    serial      text PRIMARY KEY,
    device_id   uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    not_before  bigint NOT NULL,
    not_after   bigint NOT NULL,
    issued_at   bigint NOT NULL,
    revoked_at  bigint
);
CREATE INDEX agent_certs_device_idx ON agent_certs (device_id);

CREATE TABLE rules (
    id          text PRIMARY KEY,
    kind        text NOT NULL DEFAULT 'sigma',
    meta        jsonb NOT NULL,
    source      text NOT NULL,
    enabled     boolean NOT NULL DEFAULT true,
    created_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at  bigint NOT NULL,
    updated_at  bigint NOT NULL
);

CREATE TABLE exclusions (
    id          text PRIMARY KEY,
    policy_id   text REFERENCES policies(id) ON DELETE CASCADE,
    kind        text NOT NULL,
    value       text NOT NULL,
    rule_id     text,
    expires_at  bigint,
    reason      text NOT NULL DEFAULT '',
    created_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at  bigint NOT NULL
);

CREATE TABLE iocs (
    id          text PRIMARY KEY,
    policy_id   text REFERENCES policies(id) ON DELETE CASCADE,
    kind        text NOT NULL,
    value       text NOT NULL,
    action      text NOT NULL,
    description text NOT NULL DEFAULT '',
    created_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at  bigint NOT NULL,
    hits        bigint NOT NULL DEFAULT 0
);
CREATE INDEX iocs_value_idx ON iocs (lower(value));

CREATE TABLE incidents (
    id              uuid PRIMARY KEY,
    title           text NOT NULL,
    severity        text NOT NULL,
    severity_rank   int NOT NULL,
    priority        int NOT NULL,
    status          text NOT NULL DEFAULT 'open',
    classification  text,
    assignee_id     uuid REFERENCES users(id) ON DELETE SET NULL,
    device_id       uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    root_guid       text NOT NULL,
    user_name       text,
    storyline       text NOT NULL DEFAULT '',
    alert_count     int NOT NULL DEFAULT 0,
    rule_ids        text[] NOT NULL DEFAULT '{}',
    attack          text[] NOT NULL DEFAULT '{}',
    data_at_risk    text[] NOT NULL DEFAULT '{}',
    contained       boolean NOT NULL DEFAULT false,
    first_alert_at  bigint NOT NULL,
    last_alert_at   bigint NOT NULL,
    created_at      bigint NOT NULL,
    updated_at      bigint NOT NULL,
    resolved_at     bigint
);
CREATE INDEX incidents_group_idx ON incidents (device_id, root_guid, last_alert_at);
CREATE INDEX incidents_status_idx ON incidents (status, priority DESC);

CREATE TABLE alerts (
    id              uuid PRIMARY KEY,
    incident_id     uuid REFERENCES incidents(id) ON DELETE CASCADE,
    device_id       uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    ts              bigint NOT NULL,
    rule_id         text NOT NULL,
    rule_name       text NOT NULL,
    rule_author     text,
    severity        text NOT NULL,
    severity_rank   int NOT NULL,
    attack          text[] NOT NULL DEFAULT '{}',
    mode            text NOT NULL,
    summary         text NOT NULL,
    process_guid    text NOT NULL,
    root_guid       text NOT NULL,
    image           text NOT NULL,
    sha256          text,
    signer          text,
    user_name       text,
    data_at_risk    text[] NOT NULL DEFAULT '{}',
    actions         jsonb NOT NULL DEFAULT '[]',
    status          text NOT NULL DEFAULT 'new',
    body            jsonb NOT NULL,
    received_at     bigint NOT NULL
);
CREATE INDEX alerts_ts_idx ON alerts (ts DESC);
CREATE INDEX alerts_incident_idx ON alerts (incident_id);
CREATE INDEX alerts_device_idx ON alerts (device_id, ts DESC);
CREATE INDEX alerts_rule_idx ON alerts (rule_id, ts);

CREATE TABLE incident_comments (
    id          uuid PRIMARY KEY,
    incident_id uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    author_id   uuid REFERENCES users(id) ON DELETE SET NULL,
    body        text NOT NULL,
    ts          bigint NOT NULL
);
CREATE INDEX incident_comments_idx ON incident_comments (incident_id, ts);

CREATE TABLE incident_checklist (
    id                  uuid PRIMARY KEY,
    incident_id         uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    position            int NOT NULL,
    kind                text NOT NULL,
    text                text NOT NULL,
    done                boolean NOT NULL DEFAULT false,
    action              jsonb,
    dedupe_key          text NOT NULL,
    response_action_id  uuid,
    done_by             uuid REFERENCES users(id) ON DELETE SET NULL,
    done_at             bigint,
    UNIQUE (incident_id, dedupe_key)
);

CREATE TABLE incident_activity (
    id          bigserial PRIMARY KEY,
    incident_id uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    ts          bigint NOT NULL,
    kind        text NOT NULL,
    title       text NOT NULL,
    detail      text NOT NULL DEFAULT '',
    actor_id    uuid REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX incident_activity_idx ON incident_activity (incident_id, ts);

CREATE TABLE response_actions (
    id              uuid PRIMARY KEY,
    device_id       uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    incident_id     uuid REFERENCES incidents(id) ON DELETE SET NULL,
    action          jsonb NOT NULL,
    action_type     text NOT NULL,
    status          text NOT NULL DEFAULT 'pending',
    requested_by    uuid REFERENCES users(id) ON DELETE SET NULL,
    comment         text NOT NULL DEFAULT '',
    created_at      bigint NOT NULL,
    sent_at         bigint,
    delivered_at    bigint,
    completed_at    bigint,
    expires_at      bigint NOT NULL,
    result_detail   text NOT NULL DEFAULT ''
);
CREATE INDEX response_actions_device_idx ON response_actions (device_id, status);
CREATE INDEX response_actions_created_idx ON response_actions (created_at DESC);

-- Non-command server→agent messages queued for offline agents (e.g. ReviewDecision).
CREATE TABLE pending_messages (
    id          bigserial PRIMARY KEY,
    device_id   uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    payload     jsonb NOT NULL,
    created_at  bigint NOT NULL,
    expires_at  bigint NOT NULL
);

CREATE TABLE quarantine_items (
    id              text PRIMARY KEY,
    device_id       uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    sha256          text,
    original_path   text NOT NULL,
    alert_id        uuid,
    state           text NOT NULL DEFAULT 'held',
    created_at      bigint NOT NULL,
    updated_at      bigint NOT NULL
);

CREATE TABLE review_requests (
    id                  uuid PRIMARY KEY,
    device_id           uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    user_name           text NOT NULL,
    alert_id            uuid NOT NULL,
    justification       text NOT NULL,
    state               text NOT NULL DEFAULT 'requested',
    decided_by          uuid REFERENCES users(id) ON DELETE SET NULL,
    decided_at          bigint,
    decision_message    text,
    created_at          bigint NOT NULL
);

-- Hash-chained console audit log: hash = sha256(prev_hash || canonical_json(row)).
CREATE TABLE audit_log (
    id          bigint PRIMARY KEY,
    ts          bigint NOT NULL,
    actor_id    uuid,
    actor_email text,
    action      text NOT NULL,
    target      text NOT NULL DEFAULT '',
    details     jsonb NOT NULL DEFAULT '{}',
    prev_hash   text NOT NULL,
    hash        text NOT NULL
);
CREATE SEQUENCE audit_log_id_seq START 1;
CREATE INDEX audit_log_ts_idx ON audit_log (ts);

-- Telemetry fallback store (used when CLICKHOUSE_URL is unset; 7-day retention).
CREATE TABLE events (
    id              bigserial PRIMARY KEY,
    ts              bigint NOT NULL,
    device_id       uuid NOT NULL,
    hostname        text NOT NULL DEFAULT '',
    event_type      text NOT NULL,
    process_guid    text NOT NULL DEFAULT '',
    pid             bigint NOT NULL DEFAULT 0,
    ppid            bigint NOT NULL DEFAULT 0,
    parent_guid     text NOT NULL DEFAULT '',
    image           text NOT NULL DEFAULT '',
    cmdline         text NOT NULL DEFAULT '',
    user_name       text NOT NULL DEFAULT '',
    signer          text NOT NULL DEFAULT '',
    signed          text NOT NULL DEFAULT '',
    sha256          text NOT NULL DEFAULT '',
    file_path       text NOT NULL DEFAULT '',
    file_op         text NOT NULL DEFAULT '',
    reg_key         text NOT NULL DEFAULT '',
    dst_ip          text NOT NULL DEFAULT '',
    dst_port        int NOT NULL DEFAULT 0,
    dst_host        text NOT NULL DEFAULT '',
    dns_qname       text NOT NULL DEFAULT '',
    target_guid     text NOT NULL DEFAULT '',
    target_image    text NOT NULL DEFAULT '',
    dpapi_desc      text NOT NULL DEFAULT '',
    raw             jsonb NOT NULL
);
CREATE INDEX events_device_ts_idx ON events (device_id, ts DESC);
CREATE INDEX events_ts_idx ON events (ts);
CREATE INDEX events_guid_idx ON events (device_id, process_guid);
