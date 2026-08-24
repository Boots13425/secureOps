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
    scan_timeout_seconds: int = int(os.getenv("SCAN_TIMEOUT_SECONDS", "300"))
    fingerprint_top_ports: int = int(os.getenv("NMAP_TOP_PORTS", "75"))
    host_timeout_seconds: int = int(os.getenv("NMAP_HOST_TIMEOUT_SECONDS", "20"))
    parallel_fingerprint_hosts: int = int(os.getenv("NMAP_PARALLEL_HOSTS", "6"))
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
