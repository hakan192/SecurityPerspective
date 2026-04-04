from app.models.entities import ParsedConfigItem


def extract_critical_configurations(snapshot_id: int, payload: dict) -> list[ParsedConfigItem]:
    extracted: list[ParsedConfigItem] = []
    for policy in payload.get('policies', []):
        extracted.append(
            ParsedConfigItem(
                snapshot_id=snapshot_id,
                object_type='policy',
                object_name=policy.get('name', 'unknown'),
                attributes={
                    'mode': policy.get('mode'),
                    'status': policy.get('status'),
                    'signature_set': policy.get('signature_set'),
                    'bot_mitigation': policy.get('bot_mitigation'),
                },
            )
        )

    for protection in payload.get('server_policies', []):
        extracted.append(
            ParsedConfigItem(
                snapshot_id=snapshot_id,
                object_type='server_policy',
                object_name=protection.get('name', 'unknown'),
                attributes=protection,
            )
        )
    return extracted
