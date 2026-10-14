from typing import Literal

from pydantic import BaseModel, Field


AssetStatus = Literal["known", "unknown", "approved", "missing"]
DeviceType = Literal["PC", "server", "router", "switch", "network device", "printer", "phone", "unknown"]
# Project guide §12.4 — organizational value of the asset.
AssetCriticality = Literal[
    "test_temporary", "peripheral", "standard_workstation",
    "privileged_workstation", "business_server", "critical_service",
]
# Project guide §12.3 — how reachable the asset's network segment is.
AssetExposure = Literal[
    "isolated_lab", "management_segment", "server_vlan",
    "staff_network", "guest_network", "internet_facing",
]


class ScanStart(BaseModel):
    subnet: str | None = None
    durationMinutes: int | None = Field(default=None, ge=1, le=1440)


class NetworkScanRequest(BaseModel):
    """A per-VLAN cross-network scan request.

    `confirmed_authorization` is not advisory: the endpoint refuses to scan
    without it, and records the answer either way so the audit trail shows
    whether authorization was actually confirmed for this specific VLAN.
    """
    confirmed_authorization: bool = Field(default=False)
    durationMinutes: int | None = Field(default=None, ge=1, le=1440)


class AssetUpdate(BaseModel):
    status: AssetStatus | None = None
    device_type: DeviceType | None = None


class CriticalityUpdate(BaseModel):
    """Kept so the documented Layer 8 request shape still validates.

    Per-device criticality is no longer settable by hand: organizational
    criticality now comes from the uploaded asset document, and exposure is a
    single network-wide setting because the network is flat.
    """
    criticality_category: str


class FindingUpdate(BaseModel):
    status: Literal["open", "accepted", "resolved"]


class VulnerabilityMatchUpdate(BaseModel):
    status: Literal["active", "dismissed", "resolved"]
