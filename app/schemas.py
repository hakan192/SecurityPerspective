from pydantic import BaseModel, field_validator


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

    @field_validator("apikey")
    @classmethod
    def validate_apikey_not_empty(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("APIKEY cannot be Empty")
        return value


class ManagedDeviceOut(BaseModel):
    id: int
    name: str
    ip: str
    model: str
    environment: str
    region: str
    firmware: str
    status: str
    last_sync: str

    class Config:
        from_attributes = True
