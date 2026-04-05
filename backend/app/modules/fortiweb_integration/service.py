import httpx


class FortiWebClient:
    def __init__(self, base_url: str, token: str, verify_tls: bool = True):
        self.base_url = base_url.rstrip("/")
        self.headers = {"Authorization": f"Bearer {token}"}
        self.verify_tls = verify_tls

    async def collect(self) -> dict:
        endpoints = [
            "/api/v2.0/cmdb/server-policy",
            "/api/v2.0/cmdb/web-protection-profile",
            "/api/v2.0/cmdb/system-config",
        ]
        out = {}
        async with httpx.AsyncClient(timeout=30.0, verify=self.verify_tls) as client:
            for endpoint in endpoints:
                try:
                    response = await client.get(f"{self.base_url}{endpoint}", headers=self.headers)
                    response.raise_for_status()
                    out[endpoint] = response.json()
                except Exception as exc:
                    out[endpoint] = {"error": str(exc)}
        return out
