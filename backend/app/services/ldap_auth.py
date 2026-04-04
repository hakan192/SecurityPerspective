from ldap3 import ALL, Connection, Server

from app.core.config import settings


def authenticate_ldap(username: str, password: str) -> bool:
    user_dn = settings.ldap_bind_dn_template.format(username=username)
    server = Server(settings.ldap_server_uri, get_info=ALL)
    conn = Connection(server, user=user_dn, password=password, auto_bind=False)
    return conn.bind()
