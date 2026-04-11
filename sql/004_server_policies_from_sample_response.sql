BEGIN;

-- Expand server_policies with frequently used fields from full FortiWeb response payloads.
ALTER TABLE server_policies
    ADD COLUMN IF NOT EXISTS fortiweb_id BIGINT,
    ADD COLUMN IF NOT EXISTS policy_id TEXT,
    ADD COLUMN IF NOT EXISTS deployment_mode TEXT,
    ADD COLUMN IF NOT EXISTS protocol TEXT,
    ADD COLUMN IF NOT EXISTS v_zone TEXT,
    ADD COLUMN IF NOT EXISTS status BOOLEAN,
    ADD COLUMN IF NOT EXISTS ssl_enabled BOOLEAN,
    ADD COLUMN IF NOT EXISTS http2_enabled BOOLEAN,
    ADD COLUMN IF NOT EXISTS tlog_enabled BOOLEAN,
    ADD COLUMN IF NOT EXISTS monitor_mode_enabled BOOLEAN,
    ADD COLUMN IF NOT EXISTS traffic_mirror_profile TEXT,
    ADD COLUMN IF NOT EXISTS traffic_mirror_type TEXT,
    ADD COLUMN IF NOT EXISTS allow_hosts_policy_name TEXT,
    ADD COLUMN IF NOT EXISTS replacemsg_name TEXT,
    ADD COLUMN IF NOT EXISTS half_open_threshold INTEGER,
    ADD COLUMN IF NOT EXISTS client_timeout INTEGER,
    ADD COLUMN IF NOT EXISTS tcp_conn_timeout INTEGER,
    ADD COLUMN IF NOT EXISTS comment_text TEXT;

CREATE INDEX IF NOT EXISTS idx_server_policies_device_policy_id
    ON server_policies(device_id, policy_id);

-- Re-define ingest function to map the full sample response keys.
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
            fortiweb_id,
            policy_id,
            deployment_mode,
            protocol,
            v_zone,
            status,
            ssl_enabled,
            http2_enabled,
            tlog_enabled,
            monitor_mode_enabled,
            traffic_mirror_profile,
            traffic_mirror_type,
            allow_hosts_policy_name,
            replacemsg_name,
            half_open_threshold,
            client_timeout,
            tcp_conn_timeout,
            comment_text,
            raw_json,
            updated_at
        ) VALUES (
            p_device_id,
            v_server_policy_name,
            COALESCE(item ->> 'web_protection_profile_name', item ->> 'web-protection-profile-name', item ->> 'web-protection-profile'),
            COALESCE(item ->> 'server_pool_name', item ->> 'server-pool-name', item ->> 'server-pool'),
            fortiweb_text_to_bool(COALESCE(item ->> 'traffic_mirror', item ->> 'traffic-mirror')),
            NULLIF(item ->> 'id', '')::BIGINT,
            NULLIF(item ->> 'policy-id', ''),
            NULLIF(item ->> 'deployment-mode', ''),
            NULLIF(item ->> 'protocol', ''),
            NULLIF(item ->> 'v-zone', ''),
            fortiweb_text_to_bool(item ->> 'status'),
            fortiweb_text_to_bool(item ->> 'ssl'),
            fortiweb_text_to_bool(item ->> 'http2'),
            fortiweb_text_to_bool(item ->> 'tlog'),
            fortiweb_text_to_bool(item ->> 'monitor-mode'),
            NULLIF(item ->> 'traffic-mirror-profile', ''),
            NULLIF(item ->> 'traffic-mirror-type', ''),
            NULLIF(item ->> 'allow-hosts', ''),
            NULLIF(item ->> 'replacemsg', ''),
            NULLIF(item ->> 'half-open-threshold', '')::INTEGER,
            NULLIF(item ->> 'client-timeout', '')::INTEGER,
            NULLIF(item ->> 'tcp-conn-timeout', '')::INTEGER,
            NULLIF(item ->> 'comment', ''),
            item,
            NOW()
        )
        ON CONFLICT (device_id, server_policy_name)
        DO UPDATE SET
            web_protection_profile_name = EXCLUDED.web_protection_profile_name,
            server_pool_name = EXCLUDED.server_pool_name,
            traffic_mirror = EXCLUDED.traffic_mirror,
            fortiweb_id = EXCLUDED.fortiweb_id,
            policy_id = EXCLUDED.policy_id,
            deployment_mode = EXCLUDED.deployment_mode,
            protocol = EXCLUDED.protocol,
            v_zone = EXCLUDED.v_zone,
            status = EXCLUDED.status,
            ssl_enabled = EXCLUDED.ssl_enabled,
            http2_enabled = EXCLUDED.http2_enabled,
            tlog_enabled = EXCLUDED.tlog_enabled,
            monitor_mode_enabled = EXCLUDED.monitor_mode_enabled,
            traffic_mirror_profile = EXCLUDED.traffic_mirror_profile,
            traffic_mirror_type = EXCLUDED.traffic_mirror_type,
            allow_hosts_policy_name = EXCLUDED.allow_hosts_policy_name,
            replacemsg_name = EXCLUDED.replacemsg_name,
            half_open_threshold = EXCLUDED.half_open_threshold,
            client_timeout = EXCLUDED.client_timeout,
            tcp_conn_timeout = EXCLUDED.tcp_conn_timeout,
            comment_text = EXCLUDED.comment_text,
            raw_json = EXCLUDED.raw_json,
            updated_at = NOW();

        v_count := v_count + 1;
    END LOOP;

    RETURN v_count;
END;
$$ LANGUAGE plpgsql;

COMMIT;
