# FortiWeb Configuration Inventory Schema Notes

## Design goals
- Track configuration objects from multiple FortiWeb devices.
- Enforce **device-local uniqueness** (`UNIQUE(device_id, object_name)`) instead of global uniqueness.
- Resolve cross-object relationships by attribute names **within the same device** via composite foreign keys.
- Preserve source payloads using `raw_json JSONB` on every config table.

## Core tables
- `devices`: authoritative inventory of source devices.
- `sync_runs`: tracks ingestion/sync executions per device.

## Referential pattern (composite keys)
All config relations follow this pattern:

- Child stores `device_id` + `<attribute_name>`.
- Child FK references parent's `UNIQUE(device_id, <attribute_name>)`.

Example implemented:
- `server_policies(device_id, server_pool_name)` → `server_pools(device_id, server_pool_name)`.

Additional required composite references implemented:
- `server_policies(device_id, web_protection_profile_name)` → `web_protection_profiles(device_id, web_protection_profile_name)`.
- `web_protection_profiles(device_id, signature_set_name)` → `signature_sets(device_id, signature_set_name)`.
- `web_protection_profiles(device_id, custom_access_policy_name)` → `custom_access_policies(device_id, custom_access_policy_name)`.
- `server_pools(device_id, certificate_name)` → `certificate_locals(device_id, certificate_name)`.
- `server_pools(device_id, sni_name)` → `certificate_snis(device_id, sni_name)`.
- `server_pools(device_id, intermediate_certificate_group_name)` → `intermediate_certificate_groups(device_id, intermediate_certificate_group_name)`.

## Notes
- The SQL is PostgreSQL-compatible and intended for bootstrap initialization (`sql/001_init.sql`).
- `ON DELETE SET NULL` is used for optional named references, preserving child records when a referenced profile/object is removed.
- `ON DELETE CASCADE` is used for all rows tied directly to `devices`.
