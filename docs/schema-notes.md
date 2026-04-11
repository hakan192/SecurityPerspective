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

## Historical retention for executive reporting
A second migration (`sql/002_history.sql`) adds durable history and reporting helpers:

- `config_change_log`: append-only audit history table populated by triggers on every config table.
  - Captures `device_id`, table/object name, operation (`INSERT|UPDATE|DELETE`), timestamp, and full row snapshot (`row_data`).
  - Enables point-in-time reconstruction and trend analysis.
- `executive_sync_summary`: optional sync-level KPI rollup table for executive dashboards.
  - One row per `sync_runs.id` with core object counts and optional `raw_json` payload for extra metrics.

This keeps operational tables normalized/current while preserving complete historical context for longitudinal reporting.

## Loading `server-policies` API payloads
A third migration (`sql/003_ingest_server_policies.sql`) adds:

- `fortiweb_text_to_bool(text)` to normalize API booleans like `enable/disable`.
- `ingest_server_policies(device_id, payload_jsonb)` to parse full API payloads and upsert rows into `server_policies`.

Supported payload shapes:
- `{ "results": [ ... ] }`
- `[ ... ]`
- `{ ...single object... }`

Example call:

```sql
SELECT ingest_server_policies(
  1,
  '{"results":[{"name":"sp-prod","server-pool":"pool-a","web-protection-profile":"wpp-a","traffic-mirror":"disable"}]}'::jsonb
);
```
