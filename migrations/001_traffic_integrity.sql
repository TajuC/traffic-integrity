CREATE TABLE ti_paid_visits (
  id uuid PRIMARY KEY,
  landed_at timestamptz NOT NULL,
  visitor_id text NOT NULL,
  session_id text NOT NULL,
  click_hash text NOT NULL,
  gclid text,
  gbraid text,
  wbraid text,
  gad_source text,
  gad_campaign_id text,
  utm_source text,
  utm_medium text,
  utm_campaign text,
  utm_term text,
  utm_content text,
  landing_path text NOT NULL,
  referrer_host text,
  ip_hash text NOT NULL,
  network_prefix text NOT NULL,
  ip_address inet,
  asn bigint,
  as_org text,
  country text,
  network_category text NOT NULL,
  browser_family text NOT NULL,
  browser_major integer,
  os_family text NOT NULL,
  device_type text NOT NULL,
  edge_bot_score smallint,
  identity text NOT NULL CHECK (identity IN ('new', 'returning', 'forged')),
  risk_score smallint NOT NULL,
  decision text NOT NULL,
  reasons text[] NOT NULL DEFAULT '{}',
  enforced boolean NOT NULL,
  CONSTRAINT ti_paid_visits_visitor_click UNIQUE (visitor_id, click_hash)
);

CREATE INDEX ti_paid_visits_landed_idx ON ti_paid_visits (landed_at);
CREATE INDEX ti_paid_visits_visitor_idx ON ti_paid_visits (visitor_id, landed_at DESC);
CREATE INDEX ti_paid_visits_campaign_idx ON ti_paid_visits (gad_campaign_id, landed_at) WHERE gad_campaign_id IS NOT NULL;
CREATE INDEX ti_paid_visits_network_idx ON ti_paid_visits (network_prefix, landed_at);
CREATE INDEX ti_paid_visits_asn_idx ON ti_paid_visits (asn, landed_at) WHERE asn IS NOT NULL;
CREATE INDEX ti_paid_visits_suspicious_idx ON ti_paid_visits (landed_at) WHERE risk_score >= 20;

CREATE TABLE ti_conversion_attempts (
  id uuid PRIMARY KEY,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  idempotency_key text NOT NULL,
  form_nonce text,
  form_id text NOT NULL,
  visitor_id text NOT NULL,
  session_id text NOT NULL,
  ip_hash text NOT NULL,
  network_prefix text NOT NULL,
  asn bigint,
  country text,
  status text NOT NULL CHECK (status IN ('processing', 'challenged', 'rejected', 'duplicate', 'accepted', 'failed')),
  risk_score smallint,
  decision text,
  reasons text[] NOT NULL DEFAULT '{}',
  verification text CHECK (verification IN ('not_required', 'passed', 'failed', 'unavailable', 'missing')),
  response_status smallint,
  response_body jsonb,
  lead_id uuid,
  CONSTRAINT ti_attempts_idempotency UNIQUE (idempotency_key),
  CONSTRAINT ti_attempts_form_nonce UNIQUE (form_nonce)
);

CREATE INDEX ti_attempts_created_idx ON ti_conversion_attempts (created_at);
CREATE INDEX ti_attempts_visitor_idx ON ti_conversion_attempts (visitor_id, created_at DESC);

CREATE TABLE ti_leads (
  id uuid PRIMARY KEY,
  created_at timestamptz NOT NULL,
  attempt_id uuid REFERENCES ti_conversion_attempts (id) ON DELETE SET NULL,
  form_id text NOT NULL,
  visitor_id text NOT NULL,
  name text NOT NULL,
  email text,
  phone text,
  message text,
  extra jsonb NOT NULL DEFAULT '{}'::jsonb,
  email_fingerprint text,
  phone_fingerprint text,
  message_fingerprint text,
  delivery_status text NOT NULL DEFAULT 'pending' CHECK (delivery_status IN ('pending', 'delivered', 'failed')),
  delivery_attempts smallint NOT NULL DEFAULT 0,
  CONSTRAINT ti_leads_contact_present CHECK (email IS NOT NULL OR phone IS NOT NULL)
);

CREATE INDEX ti_leads_created_idx ON ti_leads (created_at);
CREATE INDEX ti_leads_email_idx ON ti_leads (email_fingerprint, created_at DESC) WHERE email_fingerprint IS NOT NULL;
CREATE INDEX ti_leads_phone_idx ON ti_leads (phone_fingerprint, created_at DESC) WHERE phone_fingerprint IS NOT NULL;
CREATE INDEX ti_leads_message_idx ON ti_leads (message_fingerprint, created_at DESC) WHERE message_fingerprint IS NOT NULL;
CREATE INDEX ti_leads_delivery_idx ON ti_leads (created_at) WHERE delivery_status = 'pending';

CREATE TABLE ti_conversions (
  id uuid PRIMARY KEY,
  created_at timestamptz NOT NULL,
  lead_id uuid NOT NULL REFERENCES ti_leads (id) ON DELETE CASCADE,
  conversion_action text NOT NULL,
  status text NOT NULL CHECK (status IN ('pending', 'review', 'qualified', 'disqualified')),
  qualify_after timestamptz,
  decided_at timestamptz,
  decided_by text,
  decision_reason text,
  value numeric(14, 2),
  currency char(3) NOT NULL,
  gclid text,
  gbraid text,
  wbraid text,
  gad_source text,
  gad_campaign_id text,
  hashed_email text,
  hashed_phone text,
  risk_score smallint NOT NULL,
  reasons text[] NOT NULL DEFAULT '{}',
  first_exported_at timestamptz,
  CONSTRAINT ti_conversions_lead UNIQUE (lead_id)
);

CREATE INDEX ti_conversions_due_idx ON ti_conversions (qualify_after) WHERE status = 'pending';
CREATE INDEX ti_conversions_qualified_idx ON ti_conversions (decided_at) WHERE status = 'qualified';
CREATE INDEX ti_conversions_created_idx ON ti_conversions (created_at);
