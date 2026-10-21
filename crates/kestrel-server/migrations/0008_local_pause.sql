-- Local "turn protection off" switch (2026-10-21): an agent whose protection
-- was turned off with the tray switch reports `health.pause`. Status
-- priority: isolated > offline > paused > degraded > online. The status
-- follows what the agent reports (it turns protection back on by itself at
-- `until_ms`); a pause still reported well after its `until_ms` raises
-- TP-SRV-PAUSE-OVERDUE instead of being hidden.
CREATE OR REPLACE FUNCTION device_status(health jsonb, last_seen bigint, lost_at bigint) RETURNS text
LANGUAGE sql VOLATILE AS $$
SELECT CASE
    WHEN COALESCE((health->>'isolated')::boolean, false) THEN 'isolated'
    WHEN last_seen < kestrel_now_ms() - 180000 THEN 'offline'
    WHEN jsonb_typeof(health->'pause') = 'object' THEN 'paused'
    WHEN NOT COALESCE((health->>'etw_ok')::boolean, false)
         OR COALESCE(lost_at, 0) > kestrel_now_ms() - 3600000 THEN 'degraded'
    ELSE 'online'
END $$;
