BEGIN;

CREATE TABLE IF NOT EXISTS devices (
    id BIGSERIAL PRIMARY KEY,
    device_name TEXT NOT NULL,
    hostname TEXT,
    mgmt_ip INET,
    serial_number TEXT,
    adom TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    raw_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (device_name)
);

CREATE TABLE IF NOT EXISTS sync_runs (
    id BIGSERIAL PRIMARY KEY,
    device_id BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'running',
    source_endpoint TEXT,
    error_message TEXT,
    raw_json JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS signature_sets (
    id BIGSERIAL PRIMARY KEY,
    device_id BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    signature_set_name TEXT NOT NULL,
    cross_site_scripting BOOLEAN,
    sql_injection BOOLEAN,
    command_injection BOOLEAN,
    raw_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (device_id, signature_set_name)
);

CREATE TABLE IF NOT EXISTS custom_access_policies (
    id BIGSERIAL PRIMARY KEY,
    device_id BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    custom_access_policy_name TEXT NOT NULL,
    rules_content JSONB NOT NULL DEFAULT '{}'::jsonb,
    raw_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (device_id, custom_access_policy_name)
);

CREATE TABLE IF NOT EXISTS http_protocol_parameter_restrictions (
    id BIGSERIAL PRIMARY KEY,
    device_id BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    restriction_name TEXT NOT NULL,
    max_url_length INTEGER,
    max_header_length INTEGER,
    malformed_request_action TEXT,
    raw_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (device_id, restriction_name)
);

CREATE TABLE IF NOT EXISTS syntax_based_attack_detections (
    id BIGSERIAL PRIMARY KEY,
    device_id BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    syntax_based_attack_detection_name TEXT NOT NULL,
    xss_status TEXT,
    sql_status TEXT,
    command_injection_status TEXT,
    raw_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (device_id, syntax_based_attack_detection_name)
);

CREATE TABLE IF NOT EXISTS file_upload_security_profiles (
    id BIGSERIAL PRIMARY KEY,
    device_id BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    file_security_name TEXT NOT NULL,
    action TEXT,
    file_type_name TEXT,
    raw_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (device_id, file_security_name)
);

CREATE TABLE IF NOT EXISTS web_shell_detections (
    id BIGSERIAL PRIMARY KEY,
    device_id BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    web_shell_detection_name TEXT NOT NULL,
    action TEXT,
    raw_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (device_id, web_shell_detection_name)
);

CREATE TABLE IF NOT EXISTS allow_method_policies (
    id BIGSERIAL PRIMARY KEY,
    device_id BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    allow_method_policy_name TEXT NOT NULL,
    allowed_methods TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    raw_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (device_id, allow_method_policy_name)
);

CREATE TABLE IF NOT EXISTS bot_mitigation_policies (
    id BIGSERIAL PRIMARY KEY,
    device_id BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    bot_mitigation_policy_name TEXT NOT NULL,
    action TEXT,
    raw_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (device_id, bot_mitigation_policy_name)
);

CREATE TABLE IF NOT EXISTS known_bots (
    id BIGSERIAL PRIMARY KEY,
    device_id BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    known_bots_name TEXT NOT NULL,
    dos_status TEXT,
    spam_status TEXT,
    scanner_status TEXT,
    raw_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (device_id, known_bots_name)
);

CREATE TABLE IF NOT EXISTS threshold_based_detections (
    id BIGSERIAL PRIMARY KEY,
    device_id BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    threshold_based_detection_name TEXT NOT NULL,
    color TEXT,
    slow_attack_action TEXT,
    raw_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (device_id, threshold_based_detection_name)
);

CREATE TABLE IF NOT EXISTS biometric_based_detections (
    id BIGSERIAL PRIMARY KEY,
    device_id BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    biometric_based_detection_rule_name TEXT NOT NULL,
    action TEXT,
    url TEXT,
    raw_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (device_id, biometric_based_detection_rule_name)
);

CREATE TABLE IF NOT EXISTS certificate_locals (
    id BIGSERIAL PRIMARY KEY,
    device_id BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    certificate_name TEXT NOT NULL,
    valid_from TIMESTAMPTZ,
    valid_to TIMESTAMPTZ,
    serial_number TEXT,
    raw_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (device_id, certificate_name)
);

CREATE TABLE IF NOT EXISTS certificate_snis (
    id BIGSERIAL PRIMARY KEY,
    device_id BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    sni_name TEXT NOT NULL,
    domain TEXT,
    local_cert TEXT,
    raw_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (device_id, sni_name)
);

CREATE TABLE IF NOT EXISTS intermediate_certificate_groups (
    id BIGSERIAL PRIMARY KEY,
    device_id BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    intermediate_certificate_group_name TEXT NOT NULL,
    valid_from TIMESTAMPTZ,
    valid_to TIMESTAMPTZ,
    serial_number TEXT,
    raw_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (device_id, intermediate_certificate_group_name)
);

CREATE TABLE IF NOT EXISTS web_protection_profiles (
    id BIGSERIAL PRIMARY KEY,
    device_id BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    web_protection_profile_name TEXT NOT NULL,
    signature_set_name TEXT,
    custom_access_policy_name TEXT,
    http_protocol_parameter_restriction_name TEXT,
    syntax_based_attack_detection_name TEXT,
    file_security_name TEXT,
    web_shell_detection_name TEXT,
    allow_method_policy_name TEXT,
    bot_mitigation_policy_name TEXT,
    raw_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (device_id, web_protection_profile_name),
    FOREIGN KEY (device_id, signature_set_name)
        REFERENCES signature_sets(device_id, signature_set_name)
        ON DELETE SET NULL,
    FOREIGN KEY (device_id, custom_access_policy_name)
        REFERENCES custom_access_policies(device_id, custom_access_policy_name)
        ON DELETE SET NULL,
    FOREIGN KEY (device_id, http_protocol_parameter_restriction_name)
        REFERENCES http_protocol_parameter_restrictions(device_id, restriction_name)
        ON DELETE SET NULL,
    FOREIGN KEY (device_id, syntax_based_attack_detection_name)
        REFERENCES syntax_based_attack_detections(device_id, syntax_based_attack_detection_name)
        ON DELETE SET NULL,
    FOREIGN KEY (device_id, file_security_name)
        REFERENCES file_upload_security_profiles(device_id, file_security_name)
        ON DELETE SET NULL,
    FOREIGN KEY (device_id, web_shell_detection_name)
        REFERENCES web_shell_detections(device_id, web_shell_detection_name)
        ON DELETE SET NULL,
    FOREIGN KEY (device_id, allow_method_policy_name)
        REFERENCES allow_method_policies(device_id, allow_method_policy_name)
        ON DELETE SET NULL,
    FOREIGN KEY (device_id, bot_mitigation_policy_name)
        REFERENCES bot_mitigation_policies(device_id, bot_mitigation_policy_name)
        ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS server_pools (
    id BIGSERIAL PRIMARY KEY,
    device_id BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    server_pool_name TEXT NOT NULL,
    ssl BOOLEAN,
    tls_v10 BOOLEAN,
    tls_v11 BOOLEAN,
    tls_v12 BOOLEAN,
    tls_v13 BOOLEAN,
    http2 BOOLEAN,
    certificate_name TEXT,
    sni_name TEXT,
    intermediate_certificate_group_name TEXT,
    raw_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (device_id, server_pool_name),
    FOREIGN KEY (device_id, certificate_name)
        REFERENCES certificate_locals(device_id, certificate_name)
        ON DELETE SET NULL,
    FOREIGN KEY (device_id, sni_name)
        REFERENCES certificate_snis(device_id, sni_name)
        ON DELETE SET NULL,
    FOREIGN KEY (device_id, intermediate_certificate_group_name)
        REFERENCES intermediate_certificate_groups(device_id, intermediate_certificate_group_name)
        ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS server_policies (
    id BIGSERIAL PRIMARY KEY,
    device_id BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    server_policy_name TEXT NOT NULL,
    web_protection_profile_name TEXT,
    server_pool_name TEXT,
    traffic_mirror BOOLEAN,
    raw_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (device_id, server_policy_name),
    FOREIGN KEY (device_id, web_protection_profile_name)
        REFERENCES web_protection_profiles(device_id, web_protection_profile_name)
        ON DELETE SET NULL,
    FOREIGN KEY (device_id, server_pool_name)
        REFERENCES server_pools(device_id, server_pool_name)
        ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_sync_runs_device_id ON sync_runs(device_id);
CREATE INDEX IF NOT EXISTS idx_server_policies_device_pool ON server_policies(device_id, server_pool_name);
CREATE INDEX IF NOT EXISTS idx_server_policies_device_wpp ON server_policies(device_id, web_protection_profile_name);
CREATE INDEX IF NOT EXISTS idx_wpp_device_sig ON web_protection_profiles(device_id, signature_set_name);
CREATE INDEX IF NOT EXISTS idx_wpp_device_cap ON web_protection_profiles(device_id, custom_access_policy_name);
CREATE INDEX IF NOT EXISTS idx_server_pools_device_cert ON server_pools(device_id, certificate_name);
CREATE INDEX IF NOT EXISTS idx_server_pools_device_sni ON server_pools(device_id, sni_name);
CREATE INDEX IF NOT EXISTS idx_server_pools_device_icg ON server_pools(device_id, intermediate_certificate_group_name);

COMMIT;
