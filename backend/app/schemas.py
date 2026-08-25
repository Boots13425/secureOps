from typing import Literal

from pydantic import BaseModel, Field


AssetStatus = Literal["known", "unknown", "approved", "missing", "offline"]
DeviceType = Literal["PC", "server", "router", "printer", "phone", "unknown"]


class ScanStart(BaseModel):
    subnet: str | None = None
    durationMinutes: int | None = Field(default=None, ge=1, le=1440)


class AssetUpdate(BaseModel):
    status: AssetStatus | None = None
    device_type: DeviceType | None = None


class FindingUpdate(BaseModel):
    status: Literal["open", "accepted", "resolved"]
