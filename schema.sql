CREATE TABLE IF NOT EXISTS public_state (
  id INTEGER PRIMARY KEY CHECK (id=1),
  active_generation INTEGER NOT NULL DEFAULT 0,
  previous_generation INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL,
  coverage TEXT NOT NULL DEFAULT 'Bootstrap pending'
);
INSERT OR IGNORE INTO public_state(id, updated_at) VALUES (1, '1970-01-01T00:00:00Z');
CREATE TABLE IF NOT EXISTS intel_records (
  cve_id TEXT NOT NULL,
  generation INTEGER NOT NULL,
  vendor TEXT NOT NULL,
  severity TEXT NOT NULL,
  known_exploited INTEGER NOT NULL,
  modified_at TEXT NOT NULL,
  payload TEXT NOT NULL,
  checksum TEXT NOT NULL,
  PRIMARY KEY(cve_id, generation)
);
CREATE INDEX IF NOT EXISTS intel_vendor ON intel_records(vendor, cve_id);
CREATE INDEX IF NOT EXISTS intel_modified ON intel_records(modified_at DESC, cve_id);
CREATE TABLE IF NOT EXISTS published_generations (generation INTEGER PRIMARY KEY);
CREATE VIEW IF NOT EXISTS current_intel AS
SELECT r.* FROM intel_records r, public_state s
WHERE s.id=1 AND r.generation<=s.active_generation
AND EXISTS (SELECT 1 FROM published_generations p WHERE p.generation=r.generation)
AND NOT EXISTS (SELECT 1 FROM intel_records n WHERE n.cve_id=r.cve_id
  AND n.generation>r.generation AND n.generation<=s.active_generation
  AND EXISTS (SELECT 1 FROM published_generations p WHERE p.generation=n.generation));
CREATE TABLE IF NOT EXISTS feed_write_budget(day TEXT PRIMARY KEY, used INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS feed_state (
  source TEXT PRIMARY KEY,
  cursor TEXT NOT NULL DEFAULT '{}',
  last_attempt_at TEXT,
  last_success_at TEXT,
  status TEXT NOT NULL DEFAULT 'pending'
);
CREATE TABLE IF NOT EXISTS feed_runs (
  id INTEGER PRIMARY KEY,
  source TEXT NOT NULL,
  status TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  records_changed INTEGER NOT NULL DEFAULT 0,
  cursor TEXT NOT NULL DEFAULT '{}',
  detail TEXT
);
CREATE TABLE IF NOT EXISTS public_summaries (
  generation INTEGER PRIMARY KEY,
  payload TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS publish_catalog BEFORE INSERT ON published_generations BEGIN
  SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM public_summaries WHERE generation=NEW.generation)
    THEN RAISE(ABORT,'summary_required') END;
  UPDATE public_state SET previous_generation=active_generation,active_generation=NEW.generation,
    updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now'),
    coverage=(SELECT json_extract(payload,'$.coverage') FROM public_summaries WHERE generation=NEW.generation)
    WHERE id=1 AND active_generation<NEW.generation;
END;
CREATE TABLE IF NOT EXISTS scheduler_status (
  id INTEGER PRIMARY KEY CHECK(id=1),
  attempted_at TEXT NOT NULL,
  status TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ai_quota (
  day TEXT NOT NULL,
  subject TEXT NOT NULL,
  calls INTEGER NOT NULL DEFAULT 0,
  neurons INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(day, subject)
);
CREATE TABLE IF NOT EXISTS ai_reservations (
  id TEXT PRIMARY KEY,
  day TEXT NOT NULL,
  visitor TEXT NOT NULL,
  address TEXT NOT NULL,
  minute TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
-- A single INSERT owns all reservations. A RAISE rolls back every trigger write.
CREATE TRIGGER IF NOT EXISTS reserve_ai BEFORE INSERT ON ai_reservations BEGIN
  SELECT CASE WHEN EXISTS(SELECT 1 FROM ai_quota WHERE day=NEW.day AND subject='global'
    AND (calls>=100 OR neurons+80>8000)) THEN RAISE(ABORT,'quota_exhausted') END;
  SELECT CASE WHEN EXISTS(SELECT 1 FROM ai_quota WHERE day=NEW.day
    AND subject IN (NEW.visitor,NEW.address) AND calls>=10) THEN RAISE(ABORT,'quota_exhausted') END;
  SELECT CASE WHEN (SELECT COUNT(*) FROM ai_reservations WHERE day=NEW.day AND minute=NEW.minute
    AND (visitor=NEW.visitor OR address=NEW.address))>=2 THEN RAISE(ABORT,'rate_limited') END;
  INSERT INTO ai_quota(day,subject,calls,neurons) VALUES(NEW.day,'global',1,80)
    ON CONFLICT(day,subject) DO UPDATE SET calls=calls+1,neurons=neurons+80;
  INSERT INTO ai_quota(day,subject,calls) VALUES(NEW.day,NEW.visitor,1)
    ON CONFLICT(day,subject) DO UPDATE SET calls=calls+1;
  INSERT INTO ai_quota(day,subject,calls) VALUES(NEW.day,NEW.address,1)
    ON CONFLICT(day,subject) DO UPDATE SET calls=calls+1;
END;
CREATE INDEX IF NOT EXISTS ai_reservation_window ON ai_reservations(day,minute);
CREATE TABLE IF NOT EXISTS feed_lock (
  id INTEGER PRIMARY KEY CHECK(id=1), owner TEXT NOT NULL, expires_at TEXT NOT NULL
);
