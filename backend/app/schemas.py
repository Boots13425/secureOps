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


class AssetUpdate(BaseModel):
    status: AssetStatus | None = None
    device_type: DeviceType | None = None
    criticality: AssetCriticality | None = None
    exposure: AssetExposure | None = None


class CriticalityUpdate(BaseModel):
    criticality_category: str


class FindingUpdate(BaseModel):
    status: Literal["open", "accepted", "resolved"]


class VulnerabilityMatchUpdate(BaseModel):
    status: Literal["active", "dismissed", "resolved"]
