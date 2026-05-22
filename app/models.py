from sqlalchemy import Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class ManagedDevice(Base):
    __tablename__ = "managed_devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    ip: Mapped[str] = mapped_column(String(64), nullable=False)
    model: Mapped[str] = mapped_column(String(255), nullable=False)
    environment: Mapped[str] = mapped_column(String(120), nullable=False)
    region: Mapped[str] = mapped_column(String(120), nullable=False)
    firmware: Mapped[str] = mapped_column(String(64), nullable=False)
    apikey: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(64), nullable=False, default="Online")
    last_sync: Mapped[str] = mapped_column(String(120), nullable=False, default="Just now")


class LdapConfig(Base):
    __tablename__ = "ldap_config"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    enabled: Mapped[str] = mapped_column(String(8), nullable=False, default="false")
    server_uri: Mapped[str] = mapped_column(String(255), nullable=False)
    bind_dn: Mapped[str] = mapped_column(String(255), nullable=False)
    bind_password: Mapped[str] = mapped_column(String(255), nullable=False)
    search_base: Mapped[str] = mapped_column(String(255), nullable=False)
