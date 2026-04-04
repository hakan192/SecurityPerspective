import os

import httpx


async def pull_config() -> dict:
    if os.getenv("FORTIWEB_MOCK", "true").lower() == "true":
        return {
            "protection": {"waf_policy_enabled": True, "bot_protection_enabled": False},
            "updates": {"signature_update_auto": True},
            "transport": {"https_redirect_enabled": True},
            "monitoring": {"logging_enabled": True},
        }

    base_url = os.getenv("FORTIWEB_BASE_URL")
    token = os.getenv("FORTIWEB_TOKEN")
    if not base_url or not token:
        raise RuntimeError("FORTIWEB_BASE_URL and FORTIWEB_TOKEN must be configured")

    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(f"{base_url.rstrip('/')}/configuration/export", headers=headers)
        resp.raise_for_status()
        return resp.json()
