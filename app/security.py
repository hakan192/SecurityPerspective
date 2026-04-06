from fastapi import Header, HTTPException
from ldap3 import ALL, Connection, Server

from app.config import settings


def require_role(x_role: str = Header(default="viewer")) -> str:
    if x_role not in {"viewer", "analyst", "admin"}:
        raise HTTPException(status_code=403, detail="Invalid role")
    return x_role


def require_analyst_or_admin(x_role: str = Header(default="viewer")) -> str:
    if x_role not in {"analyst", "admin"}:
        raise HTTPException(status_code=403, detail="Insufficient role")
    return x_role


def ldap_authenticate(username: str, password: str) -> bool:
    if not settings.ldap_enabled:
        return False

    server = Server(settings.ldap_server_uri, get_info=ALL)
    bind_connection = Connection(
        server,
        user=settings.ldap_bind_dn,
        password=settings.ldap_bind_password,
        auto_bind=True,
    )

    search_filter = f"(uid={username})"
    bind_connection.search(settings.ldap_search_base, search_filter, attributes=["distinguishedName"])
    if not bind_connection.entries:
        return False

    user_dn = bind_connection.entries[0].entry_dn
    user_connection = Connection(server, user=user_dn, password=password, auto_bind=True)
    return bool(user_connection.bound)
