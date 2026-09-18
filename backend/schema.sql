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
  status varchar(16) NOT NULL DEFAULT 'unknown' CHECK (status IN ('known','unknown','approved','missing')),
  first_seen timestamptz NOT NULL,
  last_seen timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
-- Layer 8: nothing in a network scan can tell the system how much an asset
-- matters to the organization — that has to come from a person. Defaults to
-- 'normal' so untagged assets don't silently skew the risk ranking.
ALTER TABLE assets ADD COLUMN IF NOT EXISTS criticality varchar(12) NOT NULL DEFAULT 'normal' CHECK (criticality IN ('low','normal','high','critical'));

-- Layer 8 realignment: the project guide's EARI formula (§12.1-12.4) scores
-- "asset criticality" and "network exposure" as two independent categorical
-- inputs, each with its own 6-value table and 0-100 mapping — not the earlier
-- ad hoc low/normal/high/critical scale, and not derived from open findings.
-- Widen the column first since the new category names are longer than varchar(12).
ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_criticality_check;
ALTER TABLE assets ALTER COLUMN criticality TYPE varchar(24);
UPDATE assets SET criticality = CASE criticality
  WHEN 'low' THEN 'test_temporary' WHEN 'normal' THEN 'standard_workstation'
  WHEN 'high' THEN 'privileged_workstation' WHEN 'critical' THEN 'critical_service'
  ELSE criticality END;
ALTER TABLE assets ALTER COLUMN criticality SET DEFAULT 'standard_workstation';
ALTER TABLE assets ADD CONSTRAINT assets_criticality_check CHECK (criticality IN
  ('test_temporary','peripheral','standard_workstation','privileged_workstation','business_server','critical_service'));

-- Network exposure context (isolated lab vs. internet-facing, etc.) is the
-- other organizational input the EARI formula needs and nothing in a scan
-- can infer it either, so it is a person-set field just like criticality.
ALTER TABLE assets ADD COLUMN IF NOT EXISTS exposure varchar(24) NOT NULL DEFAULT 'staff_network';
ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_exposure_check;
ALTER TABLE assets ADD CONSTRAINT assets_exposure_check CHECK (exposure IN
  ('isolated_lab','management_segment','server_vlan','staff_network','guest_network','internet_facing'));
CREATE UNIQUE INDEX IF NOT EXISTS uq_assets_mac ON assets (mac_address) WHERE mac_address IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets (ip_address);

-- Project guide §5.1 lists exactly four organizational status values (Known,
-- Unknown, Approved, Missing/Offline as one combined label) — 'offline' was
-- carried as a fifth, distinct value that no scan code path ever assigned,
-- so it was dead state duplicated defensively across the frontend. Fold any
-- pre-existing 'offline' rows into 'missing' (same meaning) and drop it.
UPDATE assets SET status='missing' WHERE status='offline';
ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_status_check;
ALTER TABLE assets ADD CONSTRAINT assets_status_check CHECK (status IN ('known','unknown','approved','missing'));
CREATE INDEX IF NOT EXISTS idx_assets_status_type ON assets (status, device_type);

CREATE TABLE IF NOT EXISTS device_criticality_policy (
  device_identifier text PRIMARY KEY,
  criticality varchar(12) NOT NULL CHECK (criticality IN ('low','normal','high','critical')),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS network_context_policy (
  subnet_cidr cidr PRIMARY KEY,
  context_label text NOT NULL,
  notes text NOT NULL DEFAULT '',
  updated_at timestamptz NOT NULL DEFAULT now()
);

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

CREATE TABLE IF NOT EXISTS nvd_enrichment_runs (
  enrichment_run_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id uuid REFERENCES scan_sessions(id) ON DELETE SET NULL,
  trigger_source varchar(16) NOT NULL CHECK (trigger_source IN ('scan','manual','startup')),
  status varchar(16) NOT NULL CHECK (status IN ('queued','running','completed','partial','failed')),
  cpes_queued integer NOT NULL DEFAULT 0,
  cpes_queried integer NOT NULL DEFAULT 0,
  cache_hits integer NOT NULL DEFAULT 0,
  cves_matched integer NOT NULL DEFAULT 0,
  error_message text,
  queued_at timestamptz NOT NULL DEFAULT now(),
  started_at timestamptz,
  finished_at timestamptz
);
CREATE INDEX IF NOT EXISTS idx_enrichment_runs_time ON nvd_enrichment_runs (queued_at DESC);

CREATE TABLE IF NOT EXISTS nvd_cpe_cache (
  cpe_name text PRIMARY KEY,
  query_cpe text NOT NULL,
  query_type varchar(24) NOT NULL,
  result_count integer NOT NULL DEFAULT 0,
  response_data jsonb,
  last_refreshed_at timestamptz NOT NULL,
  last_error text,
  next_retry_at timestamptz
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
  cve_id varchar(24) PRIMARY KEY,
  source_identifier text,
  published_at timestamptz,
  modified_at timestamptz,
  vuln_status text,
  description text NOT NULL,
  cvss_version varchar(8),
  cvss_base_score numeric(4,1),
  cvss_base_severity varchar(16),
  cvss_vector text,
  applicability_data jsonb,
  raw_nvd_data jsonb NOT NULL,
  nvd_last_refreshed_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cvss ON vulnerabilities (cvss_base_score DESC NULLS LAST);

-- Layer 5 originally attached EPSS directly to vulnerabilities (epss_score/
-- epss_percentile/epss_date). Superseded by the dedicated epss_current_scores/
-- epss_daily_snapshots tables below (daily-scheduled, snapshotted, bulk-loaded
-- via COPY) — drop the old columns so there's only one source of truth.
DROP INDEX IF EXISTS idx_vulnerabilities_epss;
ALTER TABLE vulnerabilities DROP COLUMN IF EXISTS epss_score;
ALTER TABLE vulnerabilities DROP COLUMN IF EXISTS epss_percentile;
ALTER TABLE vulnerabilities DROP COLUMN IF EXISTS epss_date;

-- Layer 6: CISA Known Exploited Vulnerabilities. A KEV match is confirmed
-- real-world exploitation, not a prediction, so it must outrank CVSS/EPSS
-- in prioritization (see the ORDER BY in list_vulnerabilities).
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS kev_flag boolean NOT NULL DEFAULT false;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS kev_date_added date;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS kev_required_action text;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS kev_due_date date;
-- Project guide §10 KEV field list includes this as an optional contextual
-- indicator alongside dateAdded/requiredAction/dueDate; it was fetched from
-- the catalog but discarded, so add the column and start persisting it.
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS kev_known_ransomware_use boolean;
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_kev ON vulnerabilities (kev_flag) WHERE kev_flag;

-- One row per KEV catalog check, same pattern as nvd_enrichment_runs and
-- epss_download_runs, so the dedicated KEV page can show its own history
-- and "last checked" time instead of inferring it from unrelated timestamps.
CREATE TABLE IF NOT EXISTS kev_refresh_runs (
  kev_run_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  trigger_source varchar(16) NOT NULL CHECK (trigger_source IN ('scan','manual')),
  status varchar(16) NOT NULL CHECK (status IN ('running','completed','failed')),
  catalog_entries integer NOT NULL DEFAULT 0,
  matched_cves integer NOT NULL DEFAULT 0,
  error_message text,
  started_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz
);
CREATE INDEX IF NOT EXISTS idx_kev_runs_time ON kev_refresh_runs (started_at DESC);

CREATE TABLE IF NOT EXISTS service_vulnerabilities (
  service_vulnerability_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  service_id uuid NOT NULL REFERENCES services(service_id) ON DELETE CASCADE,
  cve_id varchar(24) NOT NULL REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE,
  matched_cpe text NOT NULL,
  match_confidence varchar(12) NOT NULL CHECK (match_confidence IN ('high','medium','low')),
  match_wording text NOT NULL,
  match_reason text NOT NULL,
  applicability_status varchar(16) NOT NULL DEFAULT 'candidate' CHECK (applicability_status IN ('candidate','likely')),
  status varchar(16) NOT NULL DEFAULT 'active' CHECK (status IN ('active','dismissed','resolved')),
  first_seen timestamptz NOT NULL,
  last_seen timestamptz NOT NULL,
  last_checked_at timestamptz NOT NULL,
  UNIQUE (service_id, cve_id)
);
CREATE INDEX IF NOT EXISTS idx_service_vulns_posture ON service_vulnerabilities (status, match_confidence, last_seen DESC);

-- Project guide §8.3 defines a "Confirmed" match-confidence tier ("a specific
-- approved check produces positive evidence"), but the 4 whitelisted Layer 3
-- checks (SMBv1/anon-FTP/cert/RDP) are general misconfiguration checks, not
-- confirmations of any specific CVE — nothing here can honestly produce
-- 'confirmed' (or the matching 'rejected'/'confirmed' applicability values)
-- without fabricating certainty the checks don't provide, which §2.2
-- explicitly forbids. Drop the dead values rather than leave unreachable
-- scaffolding; fold any pre-existing rows to their nearest real value.
UPDATE service_vulnerabilities SET match_confidence='high' WHERE match_confidence='confirmed';
UPDATE service_vulnerabilities SET applicability_status='likely' WHERE applicability_status IN ('confirmed','rejected');
ALTER TABLE service_vulnerabilities DROP CONSTRAINT IF EXISTS service_vulnerabilities_match_confidence_check;
ALTER TABLE service_vulnerabilities ADD CONSTRAINT service_vulnerabilities_match_confidence_check CHECK (match_confidence IN ('high','medium','low'));
ALTER TABLE service_vulnerabilities DROP CONSTRAINT IF EXISTS service_vulnerabilities_applicability_status_check;
ALTER TABLE service_vulnerabilities ADD CONSTRAINT service_vulnerabilities_applicability_status_check CHECK (applicability_status IN ('candidate','likely'));
CREATE INDEX IF NOT EXISTS idx_service_vulns_cve ON service_vulnerabilities (cve_id);

-- Layer 5: FIRST.org EPSS, downloaded once daily on its own schedule rather
-- than chained to a scan. A snapshot preserves what FIRST published each day;
-- the current table makes dashboard joins inexpensive without losing history.
CREATE TABLE IF NOT EXISTS epss_download_runs (
  epss_run_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  target_date date NOT NULL,
  trigger_source varchar(16) NOT NULL CHECK (trigger_source IN ('scheduled','retry','manual','startup')),
  status varchar(16) NOT NULL CHECK (status IN ('queued','running','completed','failed')),
  source_url text NOT NULL,
  records_received integer NOT NULL DEFAULT 0,
  error_message text,
  queued_at timestamptz NOT NULL DEFAULT now(),
  started_at timestamptz,
  finished_at timestamptz,
  next_retry_at timestamptz
);
CREATE INDEX IF NOT EXISTS idx_epss_runs_date ON epss_download_runs (target_date DESC, queued_at DESC);

CREATE TABLE IF NOT EXISTS epss_daily_snapshots (
  epss_date date NOT NULL,
  cve_id varchar(24) NOT NULL,
  epss_score numeric(8,7) NOT NULL CHECK (epss_score >= 0 AND epss_score <= 1),
  epss_percentile numeric(8,7) NOT NULL CHECK (epss_percentile >= 0 AND epss_percentile <= 1),
  source_run_id uuid NOT NULL REFERENCES epss_download_runs(epss_run_id) ON DELETE RESTRICT,
  imported_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (epss_date, cve_id)
);
CREATE INDEX IF NOT EXISTS idx_epss_snapshot_cve ON epss_daily_snapshots (cve_id, epss_date DESC);

CREATE TABLE IF NOT EXISTS epss_current_scores (
  cve_id varchar(24) PRIMARY KEY,
  epss_score numeric(8,7) NOT NULL CHECK (epss_score >= 0 AND epss_score <= 1),
  epss_percentile numeric(8,7) NOT NULL CHECK (epss_percentile >= 0 AND epss_percentile <= 1),
  epss_date date NOT NULL,
  source_run_id uuid NOT NULL REFERENCES epss_download_runs(epss_run_id) ON DELETE RESTRICT,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_epss_current_score ON epss_current_scores (epss_score DESC);

-- A basic 0-100 prototype prioritization score (CVSS 50%, EPSS 35%, match
-- confidence 10%, asset context 5%) — a head start toward Layer 8, computed
-- automatically whenever EPSS scores are refreshed.
ALTER TABLE service_vulnerabilities ADD COLUMN IF NOT EXISTS organization_risk_score numeric(5,2);
ALTER TABLE service_vulnerabilities ADD COLUMN IF NOT EXISTS organization_risk_band varchar(12);
ALTER TABLE service_vulnerabilities ADD COLUMN IF NOT EXISTS risk_calculated_at timestamptz;

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

-- Layer 7 needs a RISK_CHANGED event type (project guide §11), but the EARI
-- score (Layer 8) is always computed live from current CVSS/EPSS/KEV/finding
-- state — nothing stores what an asset's score was "as of" a past scan, so
-- there is nothing to diff. This snapshot is that missing history: one row
-- per asset captured right after a scan's NVD/KEV enrichment pipeline
-- finishes (see nvd.py's NvdEnrichmentCoordinator), so telemetry_changes()
-- can compare two real points in time instead of comparing "now" to "now".
-- Note EPSS refreshes on its own independent daily schedule (Layer 5) and
-- is not re-snapshotted when it changes a score outside of a scan.
CREATE TABLE IF NOT EXISTS asset_risk_snapshots (
  snapshot_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id uuid NOT NULL REFERENCES scan_sessions(id) ON DELETE CASCADE,
  asset_id uuid NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
  risk_score numeric(5,2) NOT NULL,
  risk_band varchar(12) NOT NULL,
  captured_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (scan_id, asset_id)
);
CREATE INDEX IF NOT EXISTS idx_risk_snapshots_asset_time ON asset_risk_snapshots (asset_id, captured_at DESC);
