from typing import Any

import httpx

from app.core.config import settings


def fetch_fortiweb_configuration(endpoint: str = '/cmdb') -> dict[str, Any]:
    url = f"{settings.fortiweb_base_url.rstrip('/')}/{endpoint.lstrip('/')}"
    headers = {'Authorization': f'Bearer {settings.fortiweb_token}'}
    with httpx.Client(verify=settings.fortiweb_verify_ssl, timeout=30) as client:
        response = client.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
