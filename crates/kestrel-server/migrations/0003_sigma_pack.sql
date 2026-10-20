-- Vendored SigmaHQ Audit pack (rules/sigmahq, DRL 1.1): which pack rules the
-- server seeded into `rules` and the source it last wrote, so pack updates never
-- overwrite an admin's edits, deletions, enable/disable or mode choices.
CREATE TABLE sigma_pack_rules (
    id              text PRIMARY KEY,
    sigma_id        text NOT NULL,
    source_sha256   text NOT NULL,
    pack_commit     text NOT NULL,
    seeded_at       bigint NOT NULL
);
