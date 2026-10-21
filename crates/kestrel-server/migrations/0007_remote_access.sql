-- Remote access (2026-10-21): remote-access profile bound to each enrollment
-- token, pinned on the device as its install-time ceiling; MFA step-up time
-- per console session. Existing tokens / devices = RemoteAccessProfile::none().
ALTER TABLE enrollment_tokens ADD COLUMN IF NOT EXISTS remote_profile JSONB NOT NULL DEFAULT
  '{"desktop":"off","files":"off","guardrails":{"require_consent":true,"consent_timeout_secs":60,"require_reason":true,"require_mfa_reauth":true,"allow_upload":true,"allow_delete":false,"max_session_minutes":60,"idle_timeout_minutes":15,"allowed_hours":null,"blocked_paths":["C:\\Windows\\System32\\config"]}}'::jsonb;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS remote_ceiling JSONB NOT NULL DEFAULT
  '{"desktop":"off","files":"off","guardrails":{"require_consent":true,"consent_timeout_secs":60,"require_reason":true,"require_mfa_reauth":true,"allow_upload":true,"allow_delete":false,"max_session_minutes":60,"idle_timeout_minutes":15,"allowed_hours":null,"blocked_paths":["C:\\Windows\\System32\\config"]}}'::jsonb;
-- Ceiling the agent reported in its last Hello (NULL: never reported / older agent).
ALTER TABLE devices ADD COLUMN IF NOT EXISTS agent_remote_ceiling JSONB;
-- Last successful POST /api/me/reauth (TOTP step-up) of this session.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS reauth_at BIGINT;
