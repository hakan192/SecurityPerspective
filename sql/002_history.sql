BEGIN;

-- Generic audit/history table for all FortiWeb config entities.
CREATE TABLE IF NOT EXISTS config_change_log (
    id BIGSERIAL PRIMARY KEY,
    device_id BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    sync_run_id BIGINT REFERENCES sync_runs(id) ON DELETE SET NULL,
    table_name TEXT NOT NULL,
    object_name TEXT,
    operation TEXT NOT NULL CHECK (operation IN ('INSERT', 'UPDATE', 'DELETE')),
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    row_data JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_config_change_log_device_time
    ON config_change_log(device_id, changed_at DESC);
CREATE INDEX IF NOT EXISTS idx_config_change_log_table_name
    ON config_change_log(table_name);
CREATE INDEX IF NOT EXISTS idx_config_change_log_sync_run
    ON config_change_log(sync_run_id);

-- Optional rollup table for executive reporting snapshots per sync run.
CREATE TABLE IF NOT EXISTS executive_sync_summary (
    id BIGSERIAL PRIMARY KEY,
    sync_run_id BIGINT NOT NULL UNIQUE REFERENCES sync_runs(id) ON DELETE CASCADE,
    device_id BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    server_policy_count INTEGER NOT NULL DEFAULT 0,
    server_pool_count INTEGER NOT NULL DEFAULT 0,
    web_protection_profile_count INTEGER NOT NULL DEFAULT 0,
    signature_set_count INTEGER NOT NULL DEFAULT 0,
    certificate_local_count INTEGER NOT NULL DEFAULT 0,
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    raw_json JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_exec_summary_device_collected_at
    ON executive_sync_summary(device_id, collected_at DESC);

CREATE OR REPLACE FUNCTION log_config_change() RETURNS trigger AS $$
DECLARE
    payload JSONB;
    object_name_value TEXT;
BEGIN
    IF TG_OP = 'DELETE' THEN
        payload := to_jsonb(OLD);
    ELSE
        payload := to_jsonb(NEW);
    END IF;

    object_name_value := COALESCE(
        payload ->> 'server_policy_name',
        payload ->> 'server_pool_name',
        payload ->> 'web_protection_profile_name',
        payload ->> 'signature_set_name',
        payload ->> 'custom_access_policy_name',
        payload ->> 'restriction_name',
        payload ->> 'syntax_based_attack_detection_name',
        payload ->> 'file_security_name',
        payload ->> 'web_shell_detection_name',
        payload ->> 'allow_method_policy_name',
        payload ->> 'bot_mitigation_policy_name',
        payload ->> 'known_bots_name',
        payload ->> 'threshold_based_detection_name',
        payload ->> 'biometric_based_detection_rule_name',
        payload ->> 'certificate_name',
        payload ->> 'sni_name',
        payload ->> 'intermediate_certificate_group_name'
    );

    INSERT INTO config_change_log (
        device_id,
        table_name,
        object_name,
        operation,
        row_data
    ) VALUES (
        COALESCE((payload ->> 'device_id')::BIGINT, NULL),
        TG_TABLE_NAME,
        object_name_value,
        TG_OP,
        payload
    );

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS tr_log_signature_sets ON signature_sets;
CREATE TRIGGER tr_log_signature_sets
AFTER INSERT OR UPDATE OR DELETE ON signature_sets
FOR EACH ROW EXECUTE FUNCTION log_config_change();

DROP TRIGGER IF EXISTS tr_log_custom_access_policies ON custom_access_policies;
CREATE TRIGGER tr_log_custom_access_policies
AFTER INSERT OR UPDATE OR DELETE ON custom_access_policies
FOR EACH ROW EXECUTE FUNCTION log_config_change();

DROP TRIGGER IF EXISTS tr_log_http_protocol_parameter_restrictions ON http_protocol_parameter_restrictions;
CREATE TRIGGER tr_log_http_protocol_parameter_restrictions
AFTER INSERT OR UPDATE OR DELETE ON http_protocol_parameter_restrictions
FOR EACH ROW EXECUTE FUNCTION log_config_change();

DROP TRIGGER IF EXISTS tr_log_syntax_based_attack_detections ON syntax_based_attack_detections;
CREATE TRIGGER tr_log_syntax_based_attack_detections
AFTER INSERT OR UPDATE OR DELETE ON syntax_based_attack_detections
FOR EACH ROW EXECUTE FUNCTION log_config_change();

DROP TRIGGER IF EXISTS tr_log_file_upload_security_profiles ON file_upload_security_profiles;
CREATE TRIGGER tr_log_file_upload_security_profiles
AFTER INSERT OR UPDATE OR DELETE ON file_upload_security_profiles
FOR EACH ROW EXECUTE FUNCTION log_config_change();

DROP TRIGGER IF EXISTS tr_log_web_shell_detections ON web_shell_detections;
CREATE TRIGGER tr_log_web_shell_detections
AFTER INSERT OR UPDATE OR DELETE ON web_shell_detections
FOR EACH ROW EXECUTE FUNCTION log_config_change();

DROP TRIGGER IF EXISTS tr_log_allow_method_policies ON allow_method_policies;
CREATE TRIGGER tr_log_allow_method_policies
AFTER INSERT OR UPDATE OR DELETE ON allow_method_policies
FOR EACH ROW EXECUTE FUNCTION log_config_change();

DROP TRIGGER IF EXISTS tr_log_bot_mitigation_policies ON bot_mitigation_policies;
CREATE TRIGGER tr_log_bot_mitigation_policies
AFTER INSERT OR UPDATE OR DELETE ON bot_mitigation_policies
FOR EACH ROW EXECUTE FUNCTION log_config_change();

DROP TRIGGER IF EXISTS tr_log_known_bots ON known_bots;
CREATE TRIGGER tr_log_known_bots
AFTER INSERT OR UPDATE OR DELETE ON known_bots
FOR EACH ROW EXECUTE FUNCTION log_config_change();

DROP TRIGGER IF EXISTS tr_log_threshold_based_detections ON threshold_based_detections;
CREATE TRIGGER tr_log_threshold_based_detections
AFTER INSERT OR UPDATE OR DELETE ON threshold_based_detections
FOR EACH ROW EXECUTE FUNCTION log_config_change();

DROP TRIGGER IF EXISTS tr_log_biometric_based_detections ON biometric_based_detections;
CREATE TRIGGER tr_log_biometric_based_detections
AFTER INSERT OR UPDATE OR DELETE ON biometric_based_detections
FOR EACH ROW EXECUTE FUNCTION log_config_change();

DROP TRIGGER IF EXISTS tr_log_certificate_locals ON certificate_locals;
CREATE TRIGGER tr_log_certificate_locals
AFTER INSERT OR UPDATE OR DELETE ON certificate_locals
FOR EACH ROW EXECUTE FUNCTION log_config_change();

DROP TRIGGER IF EXISTS tr_log_certificate_snis ON certificate_snis;
CREATE TRIGGER tr_log_certificate_snis
AFTER INSERT OR UPDATE OR DELETE ON certificate_snis
FOR EACH ROW EXECUTE FUNCTION log_config_change();

DROP TRIGGER IF EXISTS tr_log_intermediate_certificate_groups ON intermediate_certificate_groups;
CREATE TRIGGER tr_log_intermediate_certificate_groups
AFTER INSERT OR UPDATE OR DELETE ON intermediate_certificate_groups
FOR EACH ROW EXECUTE FUNCTION log_config_change();

DROP TRIGGER IF EXISTS tr_log_web_protection_profiles ON web_protection_profiles;
CREATE TRIGGER tr_log_web_protection_profiles
AFTER INSERT OR UPDATE OR DELETE ON web_protection_profiles
FOR EACH ROW EXECUTE FUNCTION log_config_change();

DROP TRIGGER IF EXISTS tr_log_server_pools ON server_pools;
CREATE TRIGGER tr_log_server_pools
AFTER INSERT OR UPDATE OR DELETE ON server_pools
FOR EACH ROW EXECUTE FUNCTION log_config_change();

DROP TRIGGER IF EXISTS tr_log_server_policies ON server_policies;
CREATE TRIGGER tr_log_server_policies
AFTER INSERT OR UPDATE OR DELETE ON server_policies
FOR EACH ROW EXECUTE FUNCTION log_config_change();

COMMIT;
