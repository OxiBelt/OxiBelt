-- OxiBelt external Admin audit checkpoint authority, schema v1.
--
-- Run this file as the dedicated authority owner after setting a stable ID:
--   SET oxibelt.anchor_authority_id = 'production-audit-authority-1';
--   \i deploy/postgres/admin-audit-anchor-v1.sql
--
-- The OxiBelt runtime should receive EXECUTE only on authority_info(),
-- append_checkpoint(jsonb), and lookup_checkpoint(text,text,bigint). An
-- independent verifier should receive EXECUTE only on authority_info(),
-- checkpoints(text,text), and head(text,text). Neither role needs direct table
-- privileges. Keep this database outside the OxiBelt host and backup boundary.

BEGIN;

CREATE SCHEMA IF NOT EXISTS oxibelt_audit_anchor_v1;

CREATE TABLE IF NOT EXISTS oxibelt_audit_anchor_v1.authority (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  authority_id text NOT NULL CHECK (
    authority_id = btrim(authority_id)
    AND length(authority_id) BETWEEN 1 AND 256
    AND authority_id !~ '[[:cntrl:]]'
  ),
  schema_version text NOT NULL
    CHECK (schema_version = 'oxibelt.audit-anchor.postgres/v1'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

DO $authority_configuration$
DECLARE
  configured_id text := current_setting('oxibelt.anchor_authority_id', true);
  stored_id text;
BEGIN
  IF configured_id IS NULL OR configured_id = '' OR configured_id <> btrim(configured_id)
     OR length(configured_id) > 256 OR configured_id ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION
      'set oxibelt.anchor_authority_id to a stable non-empty identifier before installing the authority';
  END IF;
  SELECT authority_id INTO stored_id
    FROM oxibelt_audit_anchor_v1.authority WHERE singleton;
  IF stored_id IS NULL THEN
    INSERT INTO oxibelt_audit_anchor_v1.authority
      (singleton, authority_id, schema_version)
    VALUES (true, configured_id, 'oxibelt.audit-anchor.postgres/v1');
  ELSIF stored_id <> configured_id THEN
    RAISE EXCEPTION
      'refusing to change audit anchor authority ID from % to %', stored_id, configured_id;
  END IF;
END
$authority_configuration$;

CREATE TABLE IF NOT EXISTS oxibelt_audit_anchor_v1.checkpoint_log (
  namespace text NOT NULL,
  stream_id text NOT NULL,
  checkpoint_ordinal bigint NOT NULL CHECK (checkpoint_ordinal > 0),
  checkpoint_digest text NOT NULL CHECK (
    checkpoint_digest ~ '^sha256:[0-9a-f]{64}$'
  ),
  previous_checkpoint_digest text NOT NULL CHECK (
    previous_checkpoint_digest ~ '^sha256:[0-9a-f]{64}$'
  ),
  first_sequence bigint NOT NULL CHECK (first_sequence >= 0),
  last_sequence bigint NOT NULL CHECK (last_sequence >= first_sequence),
  checkpoint jsonb NOT NULL,
  authority_received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (namespace, stream_id, checkpoint_ordinal),
  UNIQUE (namespace, stream_id, checkpoint_digest),
  CHECK (jsonb_typeof(checkpoint) = 'object')
);

CREATE OR REPLACE FUNCTION oxibelt_audit_anchor_v1.authority_info()
RETURNS TABLE(authority_id text, schema_version text)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, oxibelt_audit_anchor_v1
AS $function$
  SELECT authority.authority_id, authority.schema_version
    FROM oxibelt_audit_anchor_v1.authority
   WHERE singleton
$function$;

CREATE OR REPLACE FUNCTION oxibelt_audit_anchor_v1.validate_checkpoint(
  candidate jsonb
)
RETURNS void
LANGUAGE plpgsql
IMMUTABLE
SECURITY DEFINER
SET search_path = pg_catalog, oxibelt_audit_anchor_v1
AS $function$
DECLARE
  body jsonb := candidate->'body';
  top_key text;
  body_key text;
BEGIN
  IF pg_column_size(candidate) > 65536 THEN
    RAISE EXCEPTION 'signed Admin audit checkpoint exceeds 65536 bytes';
  END IF;
  IF jsonb_typeof(candidate) <> 'object'
     OR jsonb_typeof(body) <> 'object'
     OR candidate->>'signature' !~ '^[A-Za-z0-9_-]{86}$'
     OR candidate->>'checkpoint_digest' !~ '^sha256:[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'invalid signed Admin audit checkpoint envelope';
  END IF;
  FOR top_key IN SELECT jsonb_object_keys(candidate) LOOP
    IF top_key <> ALL (ARRAY['body', 'signature', 'checkpoint_digest']) THEN
      RAISE EXCEPTION 'unexpected signed checkpoint field %', top_key;
    END IF;
  END LOOP;
  IF NOT (candidate ?& ARRAY['body', 'signature', 'checkpoint_digest']) THEN
    RAISE EXCEPTION 'signed checkpoint is missing a required field';
  END IF;
  FOR body_key IN SELECT jsonb_object_keys(body) LOOP
    IF body_key <> ALL (ARRAY[
      'format_version', 'namespace', 'stream_id', 'instance_id', 'cluster_id',
      'membership_epoch', 'deployment_epoch', 'checkpoint_ordinal', 'chain_id',
      'first_sequence', 'last_sequence', 'chain_head',
      'previous_checkpoint_digest', 'wall_timestamp',
      'source_database_timestamp', 'signing_key_id', 'signing_algorithm'
    ]) THEN
      RAISE EXCEPTION 'unexpected checkpoint body field %', body_key;
    END IF;
  END LOOP;
  IF NOT (body ?& ARRAY[
    'format_version', 'namespace', 'stream_id', 'instance_id',
    'membership_epoch', 'deployment_epoch', 'checkpoint_ordinal', 'chain_id',
    'first_sequence', 'last_sequence', 'chain_head',
    'previous_checkpoint_digest', 'wall_timestamp',
    'source_database_timestamp', 'signing_key_id', 'signing_algorithm'
  ])
     OR EXISTS (
       SELECT 1
         FROM unnest(ARRAY[
           'format_version', 'namespace', 'stream_id', 'instance_id',
           'membership_epoch', 'deployment_epoch', 'chain_id', 'chain_head',
           'previous_checkpoint_digest', 'wall_timestamp',
           'source_database_timestamp', 'signing_key_id', 'signing_algorithm'
         ]) AS required_string(field_name)
        WHERE jsonb_typeof(body -> field_name) <> 'string'
     )
     OR body->>'format_version' <> 'oxibelt.admin.audit.checkpoint/v1'
     OR body->>'signing_algorithm' <> 'ed25519'
     OR body->>'namespace' = '' OR body->>'stream_id' = ''
     OR body->>'instance_id' = '' OR body->>'membership_epoch' = ''
     OR body->>'deployment_epoch' = '' OR body->>'signing_key_id' = ''
     OR jsonb_typeof(body->'checkpoint_ordinal') <> 'number'
     OR jsonb_typeof(body->'first_sequence') <> 'number'
     OR jsonb_typeof(body->'last_sequence') <> 'number'
     OR body->>'checkpoint_ordinal' !~ '^[1-9][0-9]*$'
     OR body->>'first_sequence' !~ '^[0-9]+$'
     OR body->>'last_sequence' !~ '^[0-9]+$'
     OR (body->>'last_sequence')::numeric < (body->>'first_sequence')::numeric
     OR body->>'chain_id' !~ '^[0-9a-f]{32}$'
     OR body->>'stream_id' !~ '^sha256:[0-9a-f]{64}$'
     OR body->>'chain_head' !~ '^sha256:[0-9a-f]{64}$'
     OR body->>'previous_checkpoint_digest' !~ '^sha256:[0-9a-f]{64}$'
     OR length(body->>'namespace') > 253
     OR length(body->>'instance_id') > 253
     OR length(body->>'membership_epoch') > 253
     OR length(body->>'deployment_epoch') > 253
     OR length(body->>'signing_key_id') > 253
     OR length(body->>'wall_timestamp') NOT BETWEEN 1 AND 253
     OR length(body->>'source_database_timestamp') NOT BETWEEN 1 AND 253
     OR body->>'namespace' ~ '[[:cntrl:]]'
     OR body->>'instance_id' ~ '[[:cntrl:]]'
     OR body->>'membership_epoch' ~ '[[:cntrl:]]'
     OR body->>'deployment_epoch' ~ '[[:cntrl:]]'
     OR body->>'signing_key_id' ~ '[[:cntrl:]]'
     OR body->>'wall_timestamp' ~ '[[:cntrl:]]'
     OR body->>'source_database_timestamp' ~ '[[:cntrl:]]'
     OR (body ? 'cluster_id' AND (
       jsonb_typeof(body->'cluster_id') <> 'string'
       OR length(body->>'cluster_id') NOT BETWEEN 1 AND 253
       OR body->>'cluster_id' ~ '[[:cntrl:]]'
     )) THEN
    RAISE EXCEPTION 'invalid Admin audit checkpoint body';
  END IF;
END
$function$;

CREATE OR REPLACE FUNCTION oxibelt_audit_anchor_v1.append_checkpoint(
  candidate jsonb
)
RETURNS TABLE(
  authority_id text,
  namespace text,
  stream_id text,
  checkpoint_ordinal bigint,
  checkpoint_digest text,
  authority_received_at text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, oxibelt_audit_anchor_v1
AS $function$
DECLARE
  candidate_namespace text;
  candidate_stream_id text;
  candidate_ordinal bigint;
  candidate_digest text;
  candidate_previous text;
  candidate_first bigint;
  candidate_last bigint;
  prior_ordinal bigint;
  prior_digest text;
  prior_chain_id text;
  prior_last_sequence bigint;
  prior_instance_id text;
  prior_cluster_id text;
  existing_checkpoint jsonb;
  received timestamptz;
BEGIN
  PERFORM oxibelt_audit_anchor_v1.validate_checkpoint(candidate);
  candidate_namespace := candidate#>>'{body,namespace}';
  candidate_stream_id := candidate#>>'{body,stream_id}';
  candidate_ordinal := (candidate#>>'{body,checkpoint_ordinal}')::bigint;
  candidate_digest := candidate->>'checkpoint_digest';
  candidate_previous := candidate#>>'{body,previous_checkpoint_digest}';
  candidate_first := (candidate#>>'{body,first_sequence}')::bigint;
  candidate_last := (candidate#>>'{body,last_sequence}')::bigint;

  PERFORM pg_advisory_xact_lock(
    hashtextextended(candidate_namespace || chr(31) || candidate_stream_id, 0)
  );
  SELECT log.checkpoint, log.authority_received_at
    INTO existing_checkpoint, received
    FROM oxibelt_audit_anchor_v1.checkpoint_log AS log
   WHERE log.namespace=candidate_namespace
     AND log.stream_id=candidate_stream_id
     AND log.checkpoint_ordinal=candidate_ordinal;
  IF existing_checkpoint IS NOT NULL THEN
    IF existing_checkpoint <> candidate THEN
      RAISE EXCEPTION 'conflicting Admin audit checkpoint at ordinal %', candidate_ordinal;
    END IF;
  ELSE
    SELECT log.checkpoint_ordinal, log.checkpoint_digest,
           log.checkpoint#>>'{body,chain_id}', log.last_sequence,
           log.checkpoint#>>'{body,instance_id}',
           log.checkpoint#>>'{body,cluster_id}'
      INTO prior_ordinal, prior_digest, prior_chain_id, prior_last_sequence,
           prior_instance_id, prior_cluster_id
      FROM oxibelt_audit_anchor_v1.checkpoint_log AS log
     WHERE log.namespace=candidate_namespace AND log.stream_id=candidate_stream_id
     ORDER BY log.checkpoint_ordinal DESC
     LIMIT 1;
    IF prior_ordinal IS NULL THEN
      IF candidate_ordinal <> 1
         OR candidate_previous <> 'sha256:0000000000000000000000000000000000000000000000000000000000000000' THEN
        RAISE EXCEPTION 'first Admin audit checkpoint must use ordinal 1 and the genesis predecessor';
      END IF;
    ELSE
      IF candidate_ordinal <> prior_ordinal + 1 OR candidate_previous <> prior_digest THEN
        RAISE EXCEPTION 'Admin audit checkpoint continuity conflict';
      END IF;
      IF candidate#>>'{body,instance_id}' <> prior_instance_id
         OR candidate#>>'{body,cluster_id}' IS DISTINCT FROM prior_cluster_id THEN
        RAISE EXCEPTION 'Admin audit checkpoint stream identity conflict';
      END IF;
      IF candidate#>>'{body,chain_id}' = prior_chain_id THEN
        IF candidate_first <> prior_last_sequence + 1 THEN
          RAISE EXCEPTION 'Admin audit checkpoint sequence continuity conflict';
        END IF;
      ELSIF candidate_first <> 0 THEN
        RAISE EXCEPTION 'a restarted Admin audit chain must begin at sequence 0';
      END IF;
    END IF;
    INSERT INTO oxibelt_audit_anchor_v1.checkpoint_log AS inserted
      (namespace, stream_id, checkpoint_ordinal, checkpoint_digest,
       previous_checkpoint_digest, first_sequence, last_sequence, checkpoint)
    VALUES
      (candidate_namespace, candidate_stream_id, candidate_ordinal,
       candidate_digest, candidate_previous, candidate_first, candidate_last,
       candidate)
    RETURNING inserted.authority_received_at INTO received;
  END IF;
  RETURN QUERY
    SELECT info.authority_id, candidate_namespace, candidate_stream_id,
           candidate_ordinal, candidate_digest, received::text
      FROM oxibelt_audit_anchor_v1.authority_info() AS info;
END
$function$;

CREATE OR REPLACE FUNCTION oxibelt_audit_anchor_v1.lookup_checkpoint(
  requested_namespace text,
  requested_stream_id text,
  requested_ordinal bigint
)
RETURNS TABLE(
  authority_id text,
  namespace text,
  stream_id text,
  checkpoint_ordinal bigint,
  checkpoint_digest text,
  authority_received_at text
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, oxibelt_audit_anchor_v1
AS $function$
  SELECT info.authority_id, log.namespace, log.stream_id,
         log.checkpoint_ordinal, log.checkpoint_digest,
         log.authority_received_at::text
    FROM oxibelt_audit_anchor_v1.checkpoint_log AS log
    CROSS JOIN oxibelt_audit_anchor_v1.authority_info() AS info
   WHERE log.namespace=requested_namespace
     AND log.stream_id=requested_stream_id
     AND log.checkpoint_ordinal=requested_ordinal
$function$;

CREATE OR REPLACE FUNCTION oxibelt_audit_anchor_v1.checkpoints(
  requested_namespace text,
  requested_stream_id text
)
RETURNS TABLE(checkpoint_ordinal bigint, checkpoint jsonb)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, oxibelt_audit_anchor_v1
AS $function$
  SELECT log.checkpoint_ordinal, log.checkpoint
    FROM oxibelt_audit_anchor_v1.checkpoint_log AS log
   WHERE log.namespace=requested_namespace AND log.stream_id=requested_stream_id
$function$;

CREATE OR REPLACE FUNCTION oxibelt_audit_anchor_v1.head(
  requested_namespace text,
  requested_stream_id text
)
RETURNS TABLE(checkpoint_ordinal bigint, checkpoint_digest text)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, oxibelt_audit_anchor_v1
AS $function$
  SELECT log.checkpoint_ordinal, log.checkpoint_digest
    FROM oxibelt_audit_anchor_v1.checkpoint_log AS log
   WHERE log.namespace=requested_namespace AND log.stream_id=requested_stream_id
   ORDER BY log.checkpoint_ordinal DESC
   LIMIT 1
$function$;

REVOKE ALL ON SCHEMA oxibelt_audit_anchor_v1 FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA oxibelt_audit_anchor_v1 FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA oxibelt_audit_anchor_v1 FROM PUBLIC;

COMMIT;
