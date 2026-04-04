from datetime import datetime

from pydantic import BaseModel


class LoginRequest(BaseModel):
    username: str
    password: str


class SnapshotResponse(BaseModel):
    id: int
    collected_at: datetime
    source_endpoint: str
    raw_payload: dict

    class Config:
        from_attributes = True


class ParsedConfigResponse(BaseModel):
    id: int
    snapshot_id: int
    object_type: str
    object_name: str
    attributes: dict

    class Config:
        from_attributes = True


class AssessmentResponse(BaseModel):
    id: int
    snapshot_id: int
    overall_score: float
    maturity_level: str
    per_control_scores: dict
    category_scores: dict

    class Config:
        from_attributes = True
