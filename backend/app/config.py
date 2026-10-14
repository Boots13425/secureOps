import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[2]
load_dotenv(ROOT / ".env")
load_dotenv(ROOT / "backend" / ".env", override=True)


@dataclass(frozen=True)
class Settings:
    db_host: str = os.getenv("DB_HOST", "127.0.0.1")
    db_port: int = int(os.getenv("DB_PORT", "5432"))
    db_name: str = os.getenv("DB_NAME", "network_telemetry")
    db_user: str = os.getenv("DB_USER", "postgres")
    db_password: str = os.getenv("DB_PASSWORD", "")
    port: int = int(os.getenv("PORT", "8007"))
    default_subnet: str = os.getenv("SCAN_DEFAULT_SUBNET", "auto")
    allowed_subnets: tuple[str, ...] = tuple(
        value.strip() for value in os.getenv("SCAN_ALLOWED_SUBNETS", "auto").split(",") if value.strip()
    )
    nmap_path: str = os.getenv("NMAP_PATH", "nmap")
    enable_os_detection: bool = os.getenv("NMAP_ENABLE_OS_DETECTION", "false").lower() == "true"
    # Layer 1 accuracy: instead of running -O against every host (noisy, slow,
    # frequently low-confidence), only fingerprint the OS of hosts that meet
    # Nmap's own documented precondition - at least one open AND one closed TCP
    # port. Hosts that don't qualify are skipped rather than guessed at.
    selective_os_detection: bool = os.getenv("NMAP_SELECTIVE_OS_DETECTION", "true").lower() == "true"
    scan_timeout_seconds: int = int(os.getenv("SCAN_TIMEOUT_SECONDS", "300"))
    fingerprint_top_ports: int = int(os.getenv("NMAP_TOP_PORTS", "100"))
    host_timeout_seconds: int = int(os.getenv("NMAP_HOST_TIMEOUT_SECONDS", "20"))
    parallel_fingerprint_hosts: int = int(os.getenv("NMAP_PARALLEL_HOSTS", "6"))
    # SNMP (v2c) is an authoritative, vendor-supplied source for name/OS/vendor
    # and - via ARP tables on routers/switches - for MAC/IP bindings on segments
    # the scanner has no direct Layer-2 visibility into.
    snmp_enabled: bool = os.getenv("SNMP_ENABLED", "true").lower() == "true"
    snmp_community: str = os.getenv("SNMP_COMMUNITY", "public")
    snmp_timeout_seconds: float = float(os.getenv("SNMP_TIMEOUT_SECONDS", "1.5"))
    snmp_parallel_hosts: int = int(os.getenv("SNMP_PARALLEL_HOSTS", "16"))
    snmp_arp_table_enabled: bool = os.getenv("SNMP_ARP_TABLE_ENABLED", "true").lower() == "true"
    # --- Cross-network discovery -------------------------------------------
    # Routers/switches the scanner can already see are asked, over read-only
    # SNMP, which other networks they have attached. Detection never probes
    # those networks; a deeper scan only happens when a user starts one.
    cross_network_discovery_enabled: bool = os.getenv("CROSS_NETWORK_DISCOVERY_ENABLED", "true").lower() == "true"
    # Background detection after a completed scan. Deliberately off the scan's
    # critical path: it runs on its own thread and must never block or fail a scan.
    cross_network_discovery_after_scan: bool = os.getenv("CROSS_NETWORK_DISCOVERY_AFTER_SCAN", "true").lower() == "true"
    cross_network_discovery_cooldown_minutes: int = int(os.getenv("CROSS_NETWORK_DISCOVERY_COOLDOWN_MINUTES", "10"))
    # Only devices seen this recently are treated as live infrastructure worth asking.
    cross_network_device_max_age_hours: int = int(os.getenv("CROSS_NETWORK_DEVICE_MAX_AGE_HOURS", "24"))
    cross_network_snmp_timeout_seconds: float = float(os.getenv("CROSS_NETWORK_SNMP_TIMEOUT_SECONDS", "1.5"))
    # Per-device read-only credential overrides. The values live only in the
    # database and are never selected into any API response or logged.
    # SNMPv3 is not implemented by the stdlib client in snmp.py (it is v2c only),
    # so the v3 columns are recorded but not yet used to authenticate.
    snmp_v3_supported: bool = False
    # Refuse a user-initiated remote scan wider than this unless an admin opts in.
    cross_network_max_scan_prefix: int = int(os.getenv("CROSS_NETWORK_MAX_SCAN_PREFIX", "22"))
    cross_network_allow_large_scans: bool = os.getenv("CROSS_NETWORK_ALLOW_LARGE_SCANS", "false").lower() == "true"
    # Remote host discovery uses ICMP + TCP ping probes instead of ARP, so it is
    # slower and must stay well behaved; these keep it modest.
    cross_network_scan_parallel_hosts: int = int(os.getenv("CROSS_NETWORK_SCAN_PARALLEL_HOSTS", "3"))
    cross_network_scan_timeout_seconds: int = int(os.getenv("CROSS_NETWORK_SCAN_TIMEOUT_SECONDS", "600"))
    # How many routers deep multi-router traversal may go, counted as routers in a
# chain: 1 is the seed router alone, so the default of 2 means "the local
    # router plus one hop beyond it". Capped so detection cannot end up mapping an
    # entire large estate by accident. Detection only; it never changes how a
    # confirmed subnet is scanned.
    cross_network_max_hops: int = int(os.getenv("CROSS_NETWORK_MAX_HOPS", "2"))
    # mDNS (.local) catches Apple/IoT/non-Windows devices that never appear in
    # reverse DNS or NetBIOS.
    mdns_enabled: bool = os.getenv("MDNS_ENABLED", "true").lower() == "true"
    mdns_timeout_seconds: float = float(os.getenv("MDNS_TIMEOUT_SECONDS", "1.5"))
    # NetBIOS name resolution (nbtstat -A) is opt-in and off by default.
    # It is a local-broadcast protocol, so it is useless for remote devices,
    # and on Windows the process cannot be reaped at its timeout: terminate
    # returns at the timeout but the handle is not signalled until the
    # NetBIOS/BROWSER call winds down, so one "2 second" lookup really costs
    # ~9-12s. Measured on a local /24 it resolved 1 of 7 hosts while adding
    # ~12s to the scan. Enable it only on networks with legacy Windows hosts
    # that genuinely need it.
    netbios_name_resolution_enabled: bool = os.getenv(
        "NETBIOS_NAME_RESOLUTION_ENABLED", "false").lower() == "true"
    netbios_timeout_seconds: float = float(os.getenv("NETBIOS_TIMEOUT_SECONDS", "2"))
    # Optional DHCP lease integration (authoritative client-reported hostnames).
    dhcp_lease_enabled: bool = os.getenv("DHCP_LEASE_ENABLED", "false").lower() == "true"
    dhcp_lease_path: str | None = os.getenv("DHCP_LEASE_PATH") or None
    dhcp_lease_format: str = os.getenv("DHCP_LEASE_FORMAT", "isc")
    dhcp_server_host: str | None = os.getenv("DHCP_SERVER_HOST") or None
    dhcp_api_url: str | None = os.getenv("DHCP_API_URL") or None
    dhcp_api_token: str | None = os.getenv("DHCP_API_TOKEN") or None
    dhcp_request_timeout_seconds: int = int(os.getenv("DHCP_REQUEST_TIMEOUT_SECONDS", "10"))
    # Authoritative sources override inferred ones (see identification.py).
    identification_source_priority: tuple[str, ...] = tuple(
        value.strip() for value in os.getenv(
            "IDENTIFICATION_SOURCE_PRIORITY",
            "dhcp_lease,snmp,os_signature,reverse_dns,netbios,mdns,nmap_heuristic",
        ).split(",") if value.strip()
    )
    # IP->MAC mappings learned from SNMP ARP tables are cached per scan so
    # cross-segment devices can still be deduped/vendored by MAC.
    snmp_arp_cache_max_age_minutes: int = int(os.getenv("SNMP_ARP_CACHE_MAX_AGE_MINUTES", "60"))
    exposure_checks_enabled: bool = os.getenv("NMAP_EXPOSURE_CHECKS_ENABLED", "true").lower() == "true"
    exposure_check_timeout_seconds: int = int(os.getenv("NMAP_EXPOSURE_CHECK_TIMEOUT_SECONDS", "25"))
    parallel_exposure_hosts: int = int(os.getenv("NMAP_EXPOSURE_PARALLEL_HOSTS", "4"))
    nvd_api_key: str | None = os.getenv("NVD_API_KEY") or None
    nvd_cache_hours: int = int(os.getenv("NVD_CACHE_HOURS", "24"))
    nvd_max_results_per_cpe: int = int(os.getenv("NVD_MAX_RESULTS_PER_CPE", "200"))
    nvd_request_timeout_seconds: int = int(os.getenv("NVD_REQUEST_TIMEOUT_SECONDS", "30"))
    epss_csv_url: str = os.getenv("EPSS_CSV_URL", "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz")
    epss_schedule_time: str = os.getenv("EPSS_SCHEDULE_TIME", "14:45")
    epss_timezone: str = os.getenv("EPSS_TIMEZONE", "Africa/Douala")
    epss_retry_minutes: int = int(os.getenv("EPSS_RETRY_MINUTES", "10"))
    epss_request_timeout_seconds: int = int(os.getenv("EPSS_REQUEST_TIMEOUT_SECONDS", "60"))
    epss_max_download_mb: int = int(os.getenv("EPSS_MAX_DOWNLOAD_MB", "50"))
    # Layer 8 on a FLAT network: there are no VLANs or segments to look up, so
    # every asset gets one network-wide exposure input. 65 is the spec 12.3
    # "General staff/user network" value.
    network_exposure_value: int = int(os.getenv("NETWORK_EXPOSURE_VALUE", "65"))
    # Freshness window for scan results: if a network's latest scan is older than
    # this, show a "not rescanned" notice instead of listing its devices.
    scan_freshness_window_minutes: int = int(os.getenv("SCAN_FRESHNESS_WINDOW_MINUTES", "30"))
    cors_origins: tuple[str, ...] = tuple(
        value.strip() for value in os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if value.strip()
    )
    # The Vite dev server is routinely opened by the machine's LAN address
    # (e.g. http://192.168.100.214:5173) as well as by localhost. Those origins
    # cannot be enumerated in advance - the address moves with DHCP - and an
    # origin that is not listed makes Starlette answer the preflight with
    # "400 Disallowed CORS origin", which silently blocks every POST from the
    # browser. Matching them by pattern fixes that durably.
    # Deliberately scoped to private address space and the Vite dev/preview
    # ports, so this never widens CORS to arbitrary public origins.
    # Set CORS_ORIGIN_REGEX=off to disable pattern matching entirely.
    cors_origin_regex: str | None = (
        os.getenv(
            "CORS_ORIGIN_REGEX",
            r"^https?://("
            r"localhost|127\.0\.0\.1|\[::1\]"
            r"|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
            r"|192\.168\.\d{1,3}\.\d{1,3}"
            r"):(?:5173|4173)$",
        ).strip()
        or None
    )
    if cors_origin_regex and cors_origin_regex.lower() == "off":
        cors_origin_regex = None

    @property
    def dsn(self) -> str:
        return (
            f"host={self.db_host} port={self.db_port} dbname={self.db_name} "
            f"user={self.db_user} password={self.db_password} connect_timeout=5"
        )


settings = Settings()
