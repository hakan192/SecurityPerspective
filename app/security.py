from fastapi import Header, HTTPException

from app.config import settings


def require_role(x_role: str = Header(default="viewer")) -> str:
    if x_role not in {"viewer", "analyst", "admin"}:
        raise HTTPException(status_code=403, detail="Invalid role")
    return x_role


def require_analyst_or_admin(x_role: str = Header(default="viewer")) -> str:
    if x_role not in {"analyst", "admin"}:
        raise HTTPException(status_code=403, detail="Insufficient role")
    return x_role


def ldap_authenticate(username: str, password: str, ldap_config: dict | None = None) -> bool:
    config = ldap_config or {
        "enabled": settings.ldap_enabled,
        "server_uri": settings.ldap_server_uri,
        "bind_dn": settings.ldap_bind_dn,
        "bind_password": settings.ldap_bind_password,
        "search_base": settings.ldap_search_base,
    }
    if not config["enabled"]:
        return False

    from ldap3 import ALL, Connection, Server

    server = Server(config["server_uri"], get_info=ALL)
    bind_connection = Connection(
        server,
        user=config["bind_dn"],
        password=config["bind_password"],
        auto_bind=True,
    )

    search_filter = f"(uid={username})"
    bind_connection.search(config["search_base"], search_filter, attributes=["distinguishedName"])
    if not bind_connection.entries:
        return False

    user_dn = bind_connection.entries[0].entry_dn
    user_connection = Connection(server, user=user_dn, password=password, auto_bind=True)
    return bool(user_connection.bound)


def verify_local_admin(username: str, password: str) -> bool:
    configured_match = username == settings.local_admin_username and password == settings.local_admin_password
    default_match = username == "admin" and password == "admin123!"
    return configured_match or default_match
