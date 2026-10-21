-- "Remove device" (2026-10-22): remote uninstall + removal from the device list.
--
-- * `capabilities`: `Hello.capabilities` of the last connect, so the console
--   can tell (also for offline devices) whether the agent understands
--   `uninstall_agent` (`agent.uninstall`).
-- * `removal_action_id`: the device's latest remote-removal command
--   (`response_actions`, action_type `uninstall_agent`). The removal state
--   shown in the API is derived from that command's status:
--   pending/sent = queued, running = uninstall started, failed, expired.
--   Cancelling clears the pointer.
-- * `removed_at` / `removed_by`: set when the device went silent after the
--   uninstall started; the device is then also decommissioned (certificates
--   revoked) and hidden from the device list unless asked for.
--
-- The uninstall token itself is never stored with the command: the server
-- attaches it (from the sealed `uninstall_token_enc`) at delivery time only.
ALTER TABLE devices ADD COLUMN capabilities text[] NOT NULL DEFAULT '{}';
ALTER TABLE devices ADD COLUMN removal_action_id uuid;
ALTER TABLE devices ADD COLUMN removed_at bigint;
ALTER TABLE devices ADD COLUMN removed_by uuid REFERENCES users(id) ON DELETE SET NULL;

-- Per-admin rate limit on removal requests.
CREATE INDEX response_actions_uninstall_idx ON response_actions (requested_by, created_at)
    WHERE action_type = 'uninstall_agent';
