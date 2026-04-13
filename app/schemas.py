from datetime import datetime

from pydantic import BaseModel


class SnapshotOut(BaseModel):
    id: int
    endpoint: str
    collected_at: datetime
    payload: dict

    class Config:
        from_attributes = True


class ParsedConfigOut(BaseModel):
    id: int
    snapshot_id: int
    object_type: str
    object_name: str
    control_id: str
    category: str
    field_name: str
    field_value: str
    is_compliant: bool

    class Config:
        from_attributes = True


class AssessmentOut(BaseModel):
    id: int
    snapshot_id: int
    generated_at: datetime
    overall_score: float
    maturity_level: str
    details: dict

    class Config:
        from_attributes = True


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str = "admin"
    username: str = "admin"


class ManagedDeviceCreate(BaseModel):
    name: str
    ip: str
    model: str
    environment: str
    region: str
    firmware: str
    apikey: str
    status: str = "Online"
    last_sync: str = "Just now"


class ManagedDeviceOut(BaseModel):
    id: int
    name: str
    ip: str
    model: str
    environment: str
    region: str
    firmware: str
    apikey: str
    status: str
    last_sync: str

    class Config:
        from_attributes = True
