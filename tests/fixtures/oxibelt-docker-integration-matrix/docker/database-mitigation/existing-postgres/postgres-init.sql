CREATE TABLE existing_mitigation_events (
  namespace text NOT NULL,
  dedupe_key text NOT NULL,
  status text NOT NULL DEFAULT 'pending',
  count bigint NOT NULL DEFAULT 0,
  first_seen timestamptz NOT NULL,
  last_seen timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  record jsonb NOT NULL,
  UNIQUE (namespace, dedupe_key)
);
