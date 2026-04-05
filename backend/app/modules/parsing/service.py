from app.core_config import settings
from app.models import ParsedRecord, RawArtifact


def parse_raw_artifact(artifact: RawArtifact) -> list[ParsedRecord]:
    payload = artifact.payload if isinstance(artifact.payload, dict) else {}
    records: list[ParsedRecord] = []

    if "server-policy" in artifact.endpoint:
        results = payload.get("results", [])
        records.append(
            ParsedRecord(
                snapshot_id=artifact.snapshot_id,
                raw_artifact_id=artifact.id,
                control_code="FW-POL-001",
                normalized_data={
                    "policy_count": len(results),
                    "https_enforced": any(isinstance(i, dict) and i.get("https-service") == "enable" for i in results),
                },
                parser_version=settings.parser_version,
            )
        )

    if "web-protection-profile" in artifact.endpoint:
        results = payload.get("results", [])
        records.append(
            ParsedRecord(
                snapshot_id=artifact.snapshot_id,
                raw_artifact_id=artifact.id,
                control_code="FW-PROF-001",
                normalized_data={
                    "profile_count": len(results),
                    "signatures_enabled": any(isinstance(i, dict) and i.get("signature-detection") == "enable" for i in results),
                },
                parser_version=settings.parser_version,
            )
        )

    if "system-config" in artifact.endpoint:
        settings_payload = payload.get("results", {})
        records.append(
            ParsedRecord(
                snapshot_id=artifact.snapshot_id,
                raw_artifact_id=artifact.id,
                control_code="FW-SYS-001",
                normalized_data={"admin_https": settings_payload.get("admin_https") == "enable"},
                parser_version=settings.parser_version,
            )
        )

    return records
