-- Sentinel-SOAR — canonical threat-hunting SQL over the event store.
-- These are the exact queries behind `python -m cli.hunt` (see cli/hunt.py),
-- reproduced here so the SQL is reviewable on its own. Schema:
--   events(id, ts, event_type, username, source_ip, host, source, raw)
--   alerts(id, rule_id, title, severity, source_ip, username, verdict, escalated, ...)
--   audit_log(id, ts, actor, action, target, detail)
-- Failure events: event_type LIKE '%fail%' (auth_failure, cloud_login_failure).
-- Success events: event_type IN ('auth_success','cloud_login','cloud_root_login').

-- 1) Top talkers: which sources are hammering auth, and against how many accounts.
SELECT source_ip,
       COUNT(*)                 AS failures,
       COUNT(DISTINCT username) AS distinct_users
  FROM events
 WHERE event_type LIKE '%fail%' AND source_ip IS NOT NULL
 GROUP BY source_ip
 ORDER BY failures DESC
 LIMIT 20;

-- 2) Per-user outcome: failed vs. successful attempts (spot compromised accounts).
SELECT username,
       SUM(event_type LIKE '%fail%')                                        AS failed,
       SUM(event_type IN ('auth_success','cloud_login','cloud_root_login')) AS succeeded
  FROM events
 WHERE username IS NOT NULL
 GROUP BY username
 ORDER BY failed DESC;

-- 3) Password spray: one source failing across MANY distinct accounts.
SELECT source_ip,
       COUNT(DISTINCT username) AS distinct_users,
       COUNT(*)                 AS attempts
  FROM events
 WHERE event_type LIKE '%fail%' AND source_ip IS NOT NULL
 GROUP BY source_ip
HAVING distinct_users >= 4
 ORDER BY distinct_users DESC, attempts DESC;

-- 4) Brute-force shape in pure SQL: >= N failures within a time window.
--    (This mirrors detections/rules/brute_force.yml. Sources that stay UNDER the
--     threshold — low-and-slow — are exactly the gap the ML risk scorer covers.)
SELECT source_ip,
       COUNT(*) AS failures,
       CAST(MAX(strftime('%s', ts)) - MIN(strftime('%s', ts)) AS INTEGER) AS span_seconds
  FROM events
 WHERE event_type LIKE '%fail%' AND source_ip IS NOT NULL
 GROUP BY source_ip
HAVING failures >= 5 AND span_seconds <= 120
 ORDER BY failures DESC;

-- 5) Timeline for one entity (parameterized: :src_ip / :user / :since).
SELECT ts, event_type, username, source_ip, host
  FROM events
 WHERE (:src_ip IS NULL OR source_ip = :src_ip)
   AND (:user   IS NULL OR username  = :user)
   AND (:since  IS NULL OR ts >= :since)
 ORDER BY ts;

-- 6) Investigated alerts (populated after `python -m core.detect`).
SELECT id, severity, rule_id, source_ip, verdict, escalated
  FROM alerts
 ORDER BY id DESC;

-- 7) Governance: recent audit-log actions.
SELECT ts, actor, action, target
  FROM audit_log
 ORDER BY id DESC
 LIMIT 20;
