CREATE TABLE ti_assessments (
  id uuid PRIMARY KEY,
  created_at timestamptz NOT NULL,
  visitor_id text,
  session_id text,
  ip_hash text NOT NULL,
  network_prefix text NOT NULL,
  asn bigint,
  campaign_id text,
  route text NOT NULL,
  paid boolean NOT NULL,
  score smallint NOT NULL,
  decision text NOT NULL,
  shadow_decision text,
  reasons text[] NOT NULL DEFAULT '{}',
  cohort text,
  policy_version text NOT NULL,
  detector_version text NOT NULL,
  model_version text,
  fraud_probability real,
  cluster_kind text
);

CREATE INDEX ti_assessments_created_idx ON ti_assessments (created_at);
CREATE INDEX ti_assessments_visitor_idx ON ti_assessments (visitor_id, created_at DESC) WHERE visitor_id IS NOT NULL;
CREATE INDEX ti_assessments_campaign_idx ON ti_assessments (campaign_id, created_at) WHERE campaign_id IS NOT NULL;
CREATE INDEX ti_assessments_decision_idx ON ti_assessments (decision, created_at);
CREATE INDEX ti_assessments_paid_idx ON ti_assessments (created_at) WHERE paid;

CREATE TABLE ti_labels (
  id uuid PRIMARY KEY,
  created_at timestamptz NOT NULL,
  subject_type text NOT NULL CHECK (subject_type IN ('assessment', 'visitor', 'lead', 'conversion', 'cluster')),
  subject_id text NOT NULL,
  label text NOT NULL CHECK (label IN (
    'legitimate', 'suspicious', 'fraud', 'qualified_conversion', 'unqualified_conversion',
    'duplicate', 'spam', 'customer', 'rejected_lead', 'chargeback'
  )),
  source text NOT NULL CHECK (source IN ('operator', 'crm', 'system', 'evaluation')),
  confidence real NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
  provenance text NOT NULL,
  notes text,
  UNIQUE (subject_type, subject_id, label, source)
);

CREATE INDEX ti_labels_subject_idx ON ti_labels (subject_type, subject_id, created_at DESC);
CREATE INDEX ti_labels_created_idx ON ti_labels (created_at);

CREATE TABLE ti_clusters (
  id text PRIMARY KEY,
  kind text NOT NULL,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  members integer NOT NULL,
  evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
  ttl_at timestamptz NOT NULL
);

CREATE INDEX ti_clusters_kind_idx ON ti_clusters (kind, updated_at DESC);

CREATE TABLE ti_edge_lists (
  id uuid PRIMARY KEY,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  action text NOT NULL CHECK (action IN ('challenge', 'block')),
  subject_type text NOT NULL CHECK (subject_type IN ('ip', 'network', 'asn', 'visitor')),
  subject_key text NOT NULL,
  reason text NOT NULL,
  confidence real NOT NULL,
  cluster_id text,
  UNIQUE (action, subject_type, subject_key)
);

CREATE INDEX ti_edge_lists_expiry_idx ON ti_edge_lists (expires_at);
CREATE INDEX ti_edge_lists_action_idx ON ti_edge_lists (action, expires_at);

CREATE TABLE ti_outcomes (
  id uuid PRIMARY KEY,
  created_at timestamptz NOT NULL,
  lead_id uuid,
  conversion_id uuid,
  visitor_id text,
  assessment_id uuid,
  outcome text NOT NULL,
  source text NOT NULL,
  details jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX ti_outcomes_created_idx ON ti_outcomes (created_at);
CREATE INDEX ti_outcomes_visitor_idx ON ti_outcomes (visitor_id, created_at DESC) WHERE visitor_id IS NOT NULL;
