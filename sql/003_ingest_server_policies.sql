BEGIN;

-- Helper: normalize FortiWeb style booleans ('enable'/'disable') and common bool strings.
CREATE OR REPLACE FUNCTION fortiweb_text_to_bool(value_text TEXT)
RETURNS BOOLEAN AS $$
BEGIN
    IF value_text IS NULL THEN
        RETURN NULL;
    END IF;

    CASE lower(trim(value_text))
        WHEN 'enable' THEN RETURN TRUE;
        WHEN 'enabled' THEN RETURN TRUE;
        WHEN 'true' THEN RETURN TRUE;
        WHEN '1' THEN RETURN TRUE;
        WHEN 'yes' THEN RETURN TRUE;
        WHEN 'disable' THEN RETURN FALSE;
        WHEN 'disabled' THEN RETURN FALSE;
        WHEN 'false' THEN RETURN FALSE;
        WHEN '0' THEN RETURN FALSE;
        WHEN 'no' THEN RETURN FALSE;
        ELSE RETURN NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Ingest a full server-policy API response into server_policies.
-- Expected payload patterns handled:
-- 1) {"results": [ ... ]}
-- 2) [ ... ]
-- 3) {single object}
CREATE OR REPLACE FUNCTION ingest_server_policies(
    p_device_id BIGINT,
    p_payload JSONB
)
RETURNS INTEGER AS $$
DECLARE
    records_array JSONB;
    item JSONB;
    v_server_policy_name TEXT;
    v_count INTEGER := 0;
BEGIN
    IF p_payload ? 'results' AND jsonb_typeof(p_payload -> 'results') = 'array' THEN
        records_array := p_payload -> 'results';
    ELSIF jsonb_typeof(p_payload) = 'array' THEN
        records_array := p_payload;
    ELSE
        records_array := jsonb_build_array(p_payload);
    END IF;

    FOR item IN SELECT value FROM jsonb_array_elements(records_array)
    LOOP
        v_server_policy_name := COALESCE(
            item ->> 'server_policy_name',
            item ->> 'server-policy-name',
            item ->> 'server-policy',
            item ->> 'name'
        );

        IF v_server_policy_name IS NULL OR btrim(v_server_policy_name) = '' THEN
            CONTINUE;
        END IF;

        INSERT INTO server_policies (
            device_id,
            server_policy_name,
            web_protection_profile_name,
            server_pool_name,
            traffic_mirror,
            raw_json,
            updated_at
        ) VALUES (
            p_device_id,
            v_server_policy_name,
            COALESCE(
                item ->> 'web_protection_profile_name',
                item ->> 'web-protection-profile-name',
                item ->> 'web-protection-profile'
            ),
            COALESCE(
                item ->> 'server_pool_name',
                item ->> 'server-pool-name',
                item ->> 'server-pool'
            ),
            fortiweb_text_to_bool(COALESCE(
                item ->> 'traffic_mirror',
                item ->> 'traffic-mirror'
            )),
            item,
            NOW()
        )
        ON CONFLICT (device_id, server_policy_name)
        DO UPDATE SET
            web_protection_profile_name = EXCLUDED.web_protection_profile_name,
            server_pool_name = EXCLUDED.server_pool_name,
            traffic_mirror = EXCLUDED.traffic_mirror,
            raw_json = EXCLUDED.raw_json,
            updated_at = NOW();

        v_count := v_count + 1;
    END LOOP;

    RETURN v_count;
END;
$$ LANGUAGE plpgsql;

COMMIT;
