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
    # mDNS (.local) catches Apple/IoT/non-Windows devices that never appear in
    # reverse DNS or NetBIOS.
    mdns_enabled: bool = os.getenv("MDNS_ENABLED", "true").lower() == "true"
    mdns_timeout_seconds: float = float(os.getenv("MDNS_TIMEOUT_SECONDS", "1.5"))
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
    cors_origins: tuple[str, ...] = tuple(
        value.strip() for value in os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if value.strip()
    )

    @property
    def dsn(self) -> str:
        return (
            f"host={self.db_host} port={self.db_port} dbname={self.db_name} "
            f"user={self.db_user} password={self.db_password} connect_timeout=5"
        )


settings = Settings()
