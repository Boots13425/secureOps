CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS scan_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  subnet cidr NOT NULL,
  status varchar(16) NOT NULL CHECK (status IN ('RUNNING','STOPPED','COMPLETED','FAILED')),
  mode varchar(16) NOT NULL DEFAULT 'continuous',
  duration_minutes integer,
  source varchar(24) NOT NULL DEFAULT 'manual',
  started_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz,
  devices_found integer NOT NULL DEFAULT 0,
  error_message text
);

CREATE TABLE IF NOT EXISTS assets (
  asset_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ip_address inet NOT NULL,
  mac_address macaddr,
  vendor text,
  hostname text,
  device_type varchar(16) NOT NULL DEFAULT 'unknown' CHECK (device_type IN ('PC','server','router','printer','phone','unknown')),
  os_family text,
  os_confidence numeric(4,3) CHECK (os_confidence BETWEEN 0 AND 1),
  status varchar(16) NOT NULL DEFAULT 'unknown' CHECK (status IN ('known','unknown','approved','missing','offline')),
  first_seen timestamptz NOT NULL,
  last_seen timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_assets_mac ON assets (mac_address) WHERE mac_address IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets (ip_address);
CREATE INDEX IF NOT EXISTS idx_assets_status_type ON assets (status, device_type);

CREATE TABLE IF NOT EXISTS asset_observations (
  observation_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_id uuid NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
  scan_id uuid NOT NULL REFERENCES scan_sessions(id) ON DELETE CASCADE,
  observed_at timestamptz NOT NULL DEFAULT now(),
  ip_address inet NOT NULL,
  mac_address macaddr,
  hostname text,
  vendor text,
  os_family text,
  os_confidence numeric(4,3),
  UNIQUE (asset_id, scan_id)
);
CREATE INDEX IF NOT EXISTS idx_observations_asset_time ON asset_observations (asset_id, observed_at DESC);

CREATE TABLE IF NOT EXISTS observed_services (
  service_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  observation_id uuid NOT NULL REFERENCES asset_observations(observation_id) ON DELETE CASCADE,
  port integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
  protocol varchar(8) NOT NULL,
  state varchar(16) NOT NULL,
  service_name text,
  product text,
  version text,
  cpe text,
  UNIQUE (observation_id, port, protocol)
);

ALTER TABLE observed_services ADD COLUMN IF NOT EXISTS detection_source varchar(32) NOT NULL DEFAULT 'nmap_service_probe';
ALTER TABLE observed_services ADD COLUMN IF NOT EXISTS confidence varchar(8) NOT NULL DEFAULT 'low';
ALTER TABLE observed_services ADD COLUMN IF NOT EXISTS confidence_score numeric(4,3);
ALTER TABLE observed_services ADD COLUMN IF NOT EXISTS enrichment_status varchar(20) NOT NULL DEFAULT 'not_enriched';
ALTER TABLE observed_services ADD COLUMN IF NOT EXISTS observed_at timestamptz NOT NULL DEFAULT now();

CREATE TABLE IF NOT EXISTS services (
  service_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_id uuid NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
  port integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
  protocol varchar(8) NOT NULL,
  state varchar(20) NOT NULL DEFAULT 'open',
  service_name text,
  product text,
  version text,
  cpe text,
  detection_source varchar(32) NOT NULL DEFAULT 'nmap_service_probe',
  confidence varchar(8) NOT NULL DEFAULT 'low' CHECK (confidence IN ('high','medium','low')),
  confidence_score numeric(4,3) CHECK (confidence_score BETWEEN 0 AND 1),
  enrichment_status varchar(20) NOT NULL DEFAULT 'not_enriched' CHECK (enrichment_status IN ('not_enriched','cpe_ready','enriched')),
  first_seen timestamptz NOT NULL,
  last_seen timestamptz NOT NULL,
  last_observation_id uuid REFERENCES asset_observations(observation_id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (asset_id, port, protocol)
);
CREATE INDEX IF NOT EXISTS idx_services_asset ON services (asset_id);
CREATE INDEX IF NOT EXISTS idx_services_exposure ON services (port, protocol, state);
CREATE INDEX IF NOT EXISTS idx_services_enrichment ON services (enrichment_status, confidence);

CREATE TABLE IF NOT EXISTS exposure_check_runs (
  check_run_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id uuid NOT NULL REFERENCES scan_sessions(id) ON DELETE CASCADE,
  asset_id uuid NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
  check_id varchar(40) NOT NULL,
  port integer,
  protocol varchar(8),
  status varchar(16) NOT NULL CHECK (status IN ('completed','no_result','failed')),
  output text,
  structured_output jsonb,
  executed_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_check_runs_asset_time ON exposure_check_runs (asset_id, executed_at DESC);

CREATE TABLE IF NOT EXISTS findings (
  finding_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  finding_key text NOT NULL UNIQUE,
  asset_id uuid NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
  service_id uuid REFERENCES services(service_id) ON DELETE SET NULL,
  check_id varchar(40) NOT NULL,
  title text NOT NULL,
  evidence text NOT NULL,
  severity varchar(16) NOT NULL CHECK (severity IN ('critical','high','medium','low','informational')),
  confidence varchar(8) NOT NULL CHECK (confidence IN ('high','medium','low')),
  why_it_matters text NOT NULL,
  recommendation text NOT NULL,
  source varchar(40) NOT NULL DEFAULT 'network_exposure_check',
  status varchar(16) NOT NULL DEFAULT 'open' CHECK (status IN ('open','accepted','resolved')),
  first_seen timestamptz NOT NULL,
  last_seen timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_findings_posture ON findings (status, severity, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings (asset_id, status);

CREATE TABLE IF NOT EXISTS finding_observations (
  finding_observation_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  finding_id uuid NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
  scan_id uuid NOT NULL REFERENCES scan_sessions(id) ON DELETE CASCADE,
  check_run_id uuid REFERENCES exposure_check_runs(check_run_id) ON DELETE SET NULL,
  evidence text NOT NULL,
  observed_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (finding_id, scan_id)
);

-- Preserve and surface fingerprints collected before the persistent Layer 2
-- inventory was introduced. Their confidence remains low because older rows
-- did not retain Nmap's confidence metadata.
WITH ranked_services AS (
  SELECT o.asset_id, os.observation_id, os.port, os.protocol, os.state,
         os.service_name, os.product, os.version, os.cpe,
         min(o.observed_at) OVER (PARTITION BY o.asset_id, os.port, os.protocol) AS first_seen,
         max(o.observed_at) OVER (PARTITION BY o.asset_id, os.port, os.protocol) AS last_seen,
         row_number() OVER (PARTITION BY o.asset_id, os.port, os.protocol ORDER BY o.observed_at DESC) AS recency
  FROM observed_services os
  JOIN asset_observations o ON o.observation_id = os.observation_id
)
INSERT INTO services(asset_id,port,protocol,state,service_name,product,version,cpe,detection_source,confidence,confidence_score,enrichment_status,first_seen,last_seen,last_observation_id)
SELECT asset_id,port,protocol,state,service_name,product,version,cpe,'nmap_service_probe','low',NULL,'not_enriched',first_seen,last_seen,observation_id
FROM ranked_services WHERE recency=1
ON CONFLICT (asset_id,port,protocol) DO NOTHING;

CREATE TABLE IF NOT EXISTS scan_activity (
  id bigserial PRIMARY KEY,
  scan_id uuid REFERENCES scan_sessions(id) ON DELETE CASCADE,
  event_type varchar(40) NOT NULL,
  message text NOT NULL,
  detail text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_scan_activity_time ON scan_activity (created_at DESC);
