from urllib.parse import urlparse

import requests

from app.config import settings
from app.models import ManagedDevice


def _build_device_base_url(device_ip: str) -> str:
    parsed = urlparse(settings.fortiweb_base_url)
    scheme = parsed.scheme or "https"
    port = f":{parsed.port}" if parsed.port else ""
    return f"{scheme}://{device_ip}{port}"


def _extract_policy_names(payload: dict) -> list[str]:
    results = payload.get("results", []) if isinstance(payload, dict) else []
    names = []
    for item in results:
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            names.append(item["name"])
    return names


def fetch_fortiweb_server_policies_by_device(devices: list[ManagedDevice]) -> dict:
    per_device = []
    endpoint = settings.fortiweb_server_policy_endpoint

    for device in devices:
        headers = {}
        if device.apikey:
            headers["Authorization"] = device.apikey
        elif settings.fortiweb_token:
            headers["Authorization"] = settings.fortiweb_token

        device_result = {
            "device_id": device.id,
            "device_name": device.name,
            "device_ip": device.ip,
            "server_policies": [],
            "error": "",
        }

        try:
            url = f"{_build_device_base_url(device.ip).rstrip('/')}{endpoint}"
            response = requests.get(
                url,
                headers=headers,
                timeout=30,
                verify=settings.fortiweb_verify_ssl,
            )
            response.raise_for_status()
            payload = response.json()
            device_result["server_policies"] = _extract_policy_names(payload)
        except Exception as exc:
            device_result["error"] = str(exc)

        per_device.append(device_result)

    return {"devices": per_device}
