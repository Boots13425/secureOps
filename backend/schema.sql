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

CREATE TABLE IF NOT EXISTS scan_activity (
  id bigserial PRIMARY KEY,
  scan_id uuid REFERENCES scan_sessions(id) ON DELETE CASCADE,
  event_type varchar(40) NOT NULL,
  message text NOT NULL,
  detail text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_scan_activity_time ON scan_activity (created_at DESC);
