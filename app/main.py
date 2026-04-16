import logging
import time
from typing import Annotated

import redis
from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.config import settings
from app.database import Base, SessionLocal, engine, get_db
from app.models import ManagedDevice
from app.schemas import LoginRequest, LoginResponse, ManagedDeviceCreate, ManagedDeviceOut
from app.security import require_analyst_or_admin, require_role, verify_local_admin
from app.services import fetch_and_store_server_policies_by_device, load_server_policies_from_db

app = FastAPI(title=settings.app_name)
scheduler = BackgroundScheduler()
redis_client = redis.from_url(settings.redis_url)
logger = logging.getLogger(__name__)
cors_origins = [origin.strip() for origin in settings.cors_allow_origins.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_origin_regex=settings.cors_allow_origin_regex,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def run_collection_job():
    db = SessionLocal()
    try:
        devices = db.query(ManagedDevice).order_by(ManagedDevice.id.desc()).all()
        fetch_and_store_server_policies_by_device(db, devices)
    finally:
        db.close()


@app.on_event("startup")
def startup_event():
    for attempt in range(1, 16):
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            redis_client.ping()
            break
        except Exception as exc:
            logger.warning("Startup dependency check failed (attempt %s/15): %s", attempt, exc)
            if attempt == 15:
                raise
            time.sleep(2)

    Base.metadata.create_all(bind=engine)
    with engine.begin() as connection:
        connection.execute(text("ALTER TABLE managed_devices ADD COLUMN IF NOT EXISTS apikey VARCHAR(255)"))
        connection.execute(text("UPDATE managed_devices SET apikey = '' WHERE apikey IS NULL"))
        connection.execute(text("DROP TABLE IF EXISTS baseline_controls CASCADE"))
        connection.execute(text("DROP TABLE IF EXISTS exchange_rate_snapshots CASCADE"))
        connection.execute(text("DROP TABLE IF EXISTS fortiweb_snapshots CASCADE"))
        connection.execute(text("DROP TABLE IF EXISTS maturity_assessments CASCADE"))
        connection.execute(text("DROP TABLE IF EXISTS parsed_configs CASCADE"))
        connection.execute(text('DROP TABLE IF EXISTS "Server_Policy" CASCADE'))
        connection.execute(text("DROP TABLE IF EXISTS server_policy CASCADE"))
        connection.execute(text("DROP TABLE IF EXISTS server_pool CASCADE"))
        connection.execute(text("DROP SEQUENCE IF EXISTS baseline_controls_id_seq CASCADE"))
        connection.execute(text("DROP SEQUENCE IF EXISTS exchange_rate_snapshots_id_seq CASCADE"))
        connection.execute(text("DROP SEQUENCE IF EXISTS fortiweb_snapshots_id_seq CASCADE"))
        connection.execute(text("DROP SEQUENCE IF EXISTS maturity_assessments_id_seq CASCADE"))
        connection.execute(text("DROP SEQUENCE IF EXISTS parsed_configs_id_seq CASCADE"))
        connection.execute(text('DROP SEQUENCE IF EXISTS "Server_Policy_id_seq" CASCADE'))
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS web_protection_profiles (
                    device_id bigint NOT NULL REFERENCES managed_devices(id) ON DELETE CASCADE,
                    web_protection_profile_name text NOT NULL,
                    signature_rule text,
                    http_protocol_parameter_restriction text,
                    cookie_security_policy text,
                    custom_access_policy text,
                    csrf_protection text,
                    syntax_based_attack_detection text,
                    parameter_validation_rule text,
                    hidden_fields_protection text,
                    file_upload_policy text,
                    webshell_detection_policy text,
                    allow_method_policy text,
                    bot_mitigate_policy text,
                    xml_validation_policy text,
                    json_validation_policy text,
                    graphql_validation_policy text,
                    openapi_validation_policy text,
                    application_layer_dos_prevention text,
                    ip_list_policy text,
                    ip_intelligence text,
                    geo_block_list_policy text,
                    waiting_room_policy text,
                    user_tracking_policy text,
                    websocket_security_policy text,
                    cors_protection_policy text,
                    created_at timestamptz NOT NULL DEFAULT now(),
                    updated_at timestamptz NOT NULL DEFAULT now(),
                    PRIMARY KEY (device_id, web_protection_profile_name)
                )
                """
            )
        )
        connection.execute(text("ALTER TABLE web_protection_profiles ADD COLUMN IF NOT EXISTS signature_rule text"))
        connection.execute(text("ALTER TABLE web_protection_profiles ADD COLUMN IF NOT EXISTS http_protocol_parameter_restriction text"))
        connection.execute(text("ALTER TABLE web_protection_profiles ADD COLUMN IF NOT EXISTS cookie_security_policy text"))
        connection.execute(text("ALTER TABLE web_protection_profiles ADD COLUMN IF NOT EXISTS custom_access_policy text"))
        connection.execute(text("ALTER TABLE web_protection_profiles ADD COLUMN IF NOT EXISTS csrf_protection text"))
        connection.execute(text("ALTER TABLE web_protection_profiles ADD COLUMN IF NOT EXISTS syntax_based_attack_detection text"))
        connection.execute(text("ALTER TABLE web_protection_profiles ADD COLUMN IF NOT EXISTS parameter_validation_rule text"))
        connection.execute(text("ALTER TABLE web_protection_profiles ADD COLUMN IF NOT EXISTS hidden_fields_protection text"))
        connection.execute(text("ALTER TABLE web_protection_profiles ADD COLUMN IF NOT EXISTS file_upload_policy text"))
        connection.execute(text("ALTER TABLE web_protection_profiles ADD COLUMN IF NOT EXISTS webshell_detection_policy text"))
        connection.execute(text("ALTER TABLE web_protection_profiles ADD COLUMN IF NOT EXISTS allow_method_policy text"))
        connection.execute(text("ALTER TABLE web_protection_profiles ADD COLUMN IF NOT EXISTS bot_mitigate_policy text"))
        connection.execute(text("ALTER TABLE web_protection_profiles ADD COLUMN IF NOT EXISTS xml_validation_policy text"))
        connection.execute(text("ALTER TABLE web_protection_profiles ADD COLUMN IF NOT EXISTS json_validation_policy text"))
        connection.execute(text("ALTER TABLE web_protection_profiles ADD COLUMN IF NOT EXISTS graphql_validation_policy text"))
        connection.execute(text("ALTER TABLE web_protection_profiles ADD COLUMN IF NOT EXISTS openapi_validation_policy text"))
        connection.execute(text("ALTER TABLE web_protection_profiles ADD COLUMN IF NOT EXISTS application_layer_dos_prevention text"))
        connection.execute(text("ALTER TABLE web_protection_profiles ADD COLUMN IF NOT EXISTS ip_list_policy text"))
        connection.execute(text("ALTER TABLE web_protection_profiles ADD COLUMN IF NOT EXISTS ip_intelligence text"))
        connection.execute(text("ALTER TABLE web_protection_profiles ADD COLUMN IF NOT EXISTS geo_block_list_policy text"))
        connection.execute(text("ALTER TABLE web_protection_profiles ADD COLUMN IF NOT EXISTS waiting_room_policy text"))
        connection.execute(text("ALTER TABLE web_protection_profiles ADD COLUMN IF NOT EXISTS user_tracking_policy text"))
        connection.execute(text("ALTER TABLE web_protection_profiles ADD COLUMN IF NOT EXISTS websocket_security_policy text"))
        connection.execute(text("ALTER TABLE web_protection_profiles ADD COLUMN IF NOT EXISTS cors_protection_policy text"))
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS certificate_local (
                    device_id bigint NOT NULL REFERENCES managed_devices(id) ON DELETE CASCADE,
                    certificate_name text NOT NULL,
                    PRIMARY KEY (device_id, certificate_name)
                )
                """
            )
        )
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS signature (
                    device_id bigint NOT NULL REFERENCES managed_devices(id) ON DELETE CASCADE,
                    signature_set_name text NOT NULL,
                    cross_site_scripting text,
                    cross_site_scripting_action text,
                    cross_site_scripting_extended text,
                    cross_site_scripting_extended_action text,
                    sql_injection text,
                    sql_injection_action text,
                    sql_injection_extended text,
                    sql_injection_extended_action text,
                    generic_attacks text,
                    generic_attacks_action text,
                    generic_attacks_extended text,
                    generic_attacks_extended_action text,
                    known_exploits text,
                    known_exploits_action text,
                    trojans text,
                    trojans_action text,
                    information_disclosure text,
                    information_disclosure_action text,
                    personally_identifiable_information text,
                    personally_identifiable_information_action text,
                    raw_json jsonb NOT NULL,
                    created_at timestamptz NOT NULL DEFAULT now(),
                    updated_at timestamptz NOT NULL DEFAULT now(),
                    PRIMARY KEY (device_id, signature_set_name)
                )
                """
            )
        )
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS http_protocol_parameter_restriction (
                    device_id bigint NOT NULL REFERENCES managed_devices(id) ON DELETE CASCADE,
                    name text NOT NULL,
                    max_http_header_length_check text,
                    max_http_header_length_check_action text,
                    max_http_content_length_check text,
                    max_http_content_length_check_action text,
                    max_http_body_length_check text,
                    max_http_body_length_check_action text,
                    max_http_request_length_check text,
                    max_http_request_length_check_action text,
                    max_url_parameter_length_check text,
                    max_url_parameter_length_check_action text,
                    illegal_http_version_check text,
                    illegal_http_version_check_action text,
                    max_cookie_in_request_check text,
                    max_cookie_in_request_check_action text,
                    max_header_line_request_check text,
                    max_header_line_request_check_action text,
                    illegal_http_request_method_check text,
                    illegal_http_request_method_check_action text,
                    max_url_parameter_check text,
                    max_url_parameter_check_action text,
                    illegal_host_name_check text,
                    illegal_host_name_check_action text,
                    number_of_ranges_in_range_header_check text,
                    number_of_ranges_in_range_header_check_action text,
                    http2_max_requests_check text,
                    http2_max_requests_check_action text,
                    block_malformed_request_check text,
                    block_malformed_request_check_action text,
                    illegal_content_length_check text,
                    illegal_content_length_check_action text,
                    illegal_content_type_check text,
                    illegal_content_type_check_action text,
                    illegal_response_code_check text,
                    illegal_response_code_check_action text,
                    post_request_ctype_check text,
                    post_request_ctype_check_action text,
                    max_http_header_name_length_check text,
                    max_http_header_name_length_check_action text,
                    max_http_header_value_length_check text,
                    max_http_header_value_length_check_action text,
                    parameter_name_check text,
                    parameter_name_check_action text,
                    parameter_value_check text,
                    parameter_value_check_action text,
                    illegal_header_name_check text,
                    illegal_header_name_check_action text,
                    illegal_header_value_check text,
                    illegal_header_value_check_action text,
                    max_http_body_parameter_length_check text,
                    max_http_body_parameter_length_check_action text,
                    max_http_request_filename_length_check text,
                    max_http_request_filename_length_check_action text,
                    web_socket_protocol_check text,
                    web_socket_protocol_check_action text,
                    max_setting_header_table_size_check text,
                    max_setting_header_table_size_check_action text,
                    max_setting_current_streams_num_check text,
                    max_setting_current_streams_num_check_action text,
                    max_setting_initial_window_size_check text,
                    max_setting_initial_window_size_check_action text,
                    max_setting_frame_size_check text,
                    max_setting_frame_size_check_action text,
                    max_setting_header_list_size_check text,
                    max_setting_header_list_size_check_action text,
                    max_url_param_name_len_check text,
                    max_url_param_name_len_check_action text,
                    url_param_name_check text,
                    url_param_name_check_action text,
                    url_param_value_check text,
                    url_param_value_check_action text,
                    null_byte_in_url_check text,
                    null_byte_in_url_check_action text,
                    illegal_byte_in_url_check text,
                    illegal_byte_in_url_check_action text,
                    malformed_url_check text,
                    malformed_url_check_action text,
                    redundant_header_check text,
                    redundant_header_check_action text,
                    chunk_size_check text,
                    chunk_size_check_action text,
                    internal_resource_limits_check text,
                    internal_resource_limits_check_action text,
                    rpc_protocol_check text,
                    rpc_protocol_check_action text,
                    duplicate_paramname_check text,
                    duplicate_paramname_check_action text,
                    odd_and_even_space_attack_check text,
                    odd_and_even_space_attack_check_action text,
                    cl_te_coexist_check text,
                    cl_te_coexist_check_action text,
                    inconsistent_cl_check text,
                    inconsistent_cl_check_action text,
                    missing_host_check text,
                    missing_host_check_action text,
                    range_overlapping_check text,
                    range_overlapping_check_action text,
                    multipart_formdata_bad_request_check text,
                    multipart_formdata_bad_request_check_action text,
                    h2_rst_stream_check text,
                    h2_rst_stream_check_action text,
                    raw_json jsonb,
                    created_at timestamptz NOT NULL DEFAULT now(),
                    updated_at timestamptz NOT NULL DEFAULT now(),
                    PRIMARY KEY (device_id, name)
                )
                """
            )
        )
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS "cookie-security-policy" (
                    device_id bigint NOT NULL REFERENCES managed_devices(id) ON DELETE CASCADE,
                    cookie_security_name text NOT NULL,
                    action text,
                    raw_json jsonb,
                    created_at timestamptz NOT NULL DEFAULT now(),
                    updated_at timestamptz NOT NULL DEFAULT now(),
                    PRIMARY KEY (device_id, cookie_security_name)
                )
                """
            )
        )
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS "syntax-based-attack-detection" (
                    device_id bigint NOT NULL REFERENCES managed_devices(id) ON DELETE CASCADE,
                    name text NOT NULL,
                    xss_html_tag_based_status text,
                    xss_html_tag_based_action text,
                    xss_html_attribute_based_status text,
                    xss_html_attribute_based_action text,
                    xss_javascript_function_based_status text,
                    xss_javascript_function_based_action text,
                    xss_javascript_variable_based_status text,
                    xss_javascript_variable_based_action text,
                    sql_stacked_queries_status text,
                    sql_stacked_queries_action text,
                    sql_embeded_queries_status text,
                    sql_embeded_queries_action text,
                    sql_condition_based_status text,
                    sql_condition_based_action text,
                    sql_arithmetic_operation_status text,
                    sql_arithmetic_operation_action text,
                    sql_line_comments_status text,
                    sql_line_comments_action text,
                    sql_function_based_status text,
                    sql_function_based_action text,
                    raw_json jsonb,
                    created_at timestamptz NOT NULL DEFAULT now(),
                    updated_at timestamptz NOT NULL DEFAULT now(),
                    PRIMARY KEY (device_id, name)
                )
                """
            )
        )
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS "custom-access-policy" (
                    device_id bigint NOT NULL REFERENCES managed_devices(id) ON DELETE CASCADE,
                    custom_access_policy_name text NOT NULL,
                    custom_access_rules text NOT NULL,
                    visfilterType text,
                    visvalue text,
                    raw_json jsonb,
                    created_at timestamptz NOT NULL DEFAULT now(),
                    updated_at timestamptz NOT NULL DEFAULT now(),
                    PRIMARY KEY (device_id, custom_access_policy_name, custom_access_rules)
                )
                """
            )
        )
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS "allow-method-policy" (
                    device_id bigint NOT NULL REFERENCES managed_devices(id) ON DELETE CASCADE,
                    allow_method_policy_name text NOT NULL,
                    allow_method text,
                    raw_json jsonb,
                    created_at timestamptz NOT NULL DEFAULT now(),
                    updated_at timestamptz NOT NULL DEFAULT now(),
                    PRIMARY KEY (device_id, allow_method_policy_name)
                )
                """
            )
        )
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS "xml-validation-policy" (
                    device_id bigint NOT NULL REFERENCES managed_devices(id) ON DELETE CASCADE,
                    xml_validation_name text NOT NULL,
                    enable_signature_detection text,
                    raw_json jsonb,
                    created_at timestamptz NOT NULL DEFAULT now(),
                    updated_at timestamptz NOT NULL DEFAULT now(),
                    PRIMARY KEY (device_id, xml_validation_name)
                )
                """
            )
        )
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS "json-validation-policy" (
                    device_id bigint NOT NULL REFERENCES managed_devices(id) ON DELETE CASCADE,
                    json_validation_name text NOT NULL,
                    enable_signature_detection text,
                    raw_json jsonb,
                    created_at timestamptz NOT NULL DEFAULT now(),
                    updated_at timestamptz NOT NULL DEFAULT now(),
                    PRIMARY KEY (device_id, json_validation_name)
                )
                """
            )
        )
        connection.execute(text("ALTER TABLE signature ADD COLUMN IF NOT EXISTS raw_json jsonb"))
        connection.execute(text('ALTER TABLE "cookie-security-policy" ADD COLUMN IF NOT EXISTS action text'))
        connection.execute(text('ALTER TABLE "cookie-security-policy" ADD COLUMN IF NOT EXISTS raw_json jsonb'))
        connection.execute(text('ALTER TABLE "syntax-based-attack-detection" ADD COLUMN IF NOT EXISTS raw_json jsonb'))
        connection.execute(text('ALTER TABLE "custom-access-policy" ADD COLUMN IF NOT EXISTS visfilterType text'))
        connection.execute(text('ALTER TABLE "custom-access-policy" ADD COLUMN IF NOT EXISTS visvalue text'))
        connection.execute(text('ALTER TABLE "custom-access-policy" ADD COLUMN IF NOT EXISTS raw_json jsonb'))
        connection.execute(text('ALTER TABLE "allow-method-policy" ADD COLUMN IF NOT EXISTS allow_method text'))
        connection.execute(text('ALTER TABLE "allow-method-policy" ADD COLUMN IF NOT EXISTS raw_json jsonb'))
        connection.execute(text('ALTER TABLE "xml-validation-policy" ADD COLUMN IF NOT EXISTS enable_signature_detection text'))
        connection.execute(text('ALTER TABLE "xml-validation-policy" ADD COLUMN IF NOT EXISTS raw_json jsonb'))
        connection.execute(text('ALTER TABLE "json-validation-policy" ADD COLUMN IF NOT EXISTS enable_signature_detection text'))
        connection.execute(text('ALTER TABLE "json-validation-policy" ADD COLUMN IF NOT EXISTS raw_json jsonb'))
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS "application-layer-dos-prevention" (
                    device_id bigint NOT NULL REFERENCES managed_devices(id) ON DELETE CASCADE,
                    name text NOT NULL,
                    http_request_flood_prevention_rule text,
                    enable_layer4_dos_prevention text,
                    layer4_access_limit_rule text,
                    layer4_connection_flood_check_rule text,
                    raw_json jsonb,
                    created_at timestamptz NOT NULL DEFAULT now(),
                    updated_at timestamptz NOT NULL DEFAULT now(),
                    PRIMARY KEY (device_id, name)
                )
                """
            )
        )
        connection.execute(text('ALTER TABLE "application-layer-dos-prevention" ADD COLUMN IF NOT EXISTS http_request_flood_prevention_rule text'))
        connection.execute(text('ALTER TABLE "application-layer-dos-prevention" ADD COLUMN IF NOT EXISTS enable_layer4_dos_prevention text'))
        connection.execute(text('ALTER TABLE "application-layer-dos-prevention" ADD COLUMN IF NOT EXISTS layer4_access_limit_rule text'))
        connection.execute(text('ALTER TABLE "application-layer-dos-prevention" ADD COLUMN IF NOT EXISTS layer4_connection_flood_check_rule text'))
        connection.execute(text('ALTER TABLE "application-layer-dos-prevention" ADD COLUMN IF NOT EXISTS raw_json jsonb'))
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS "http-request-flood-prevention-rule" (
                    device_id bigint NOT NULL REFERENCES managed_devices(id) ON DELETE CASCADE,
                    name text NOT NULL,
                    http_connection_name text,
                    action text,
                    bot_confirmation text,
                    bot_recognition text,
                    raw_json_http_connection jsonb,
                    created_at timestamptz NOT NULL DEFAULT now(),
                    updated_at timestamptz NOT NULL DEFAULT now(),
                    PRIMARY KEY (device_id, name)
                )
                """
            )
        )
        connection.execute(text('ALTER TABLE "http-request-flood-prevention-rule" ADD COLUMN IF NOT EXISTS http_connection_name text'))
        connection.execute(text('ALTER TABLE "http-request-flood-prevention-rule" ADD COLUMN IF NOT EXISTS action text'))
        connection.execute(text('ALTER TABLE "http-request-flood-prevention-rule" ADD COLUMN IF NOT EXISTS bot_confirmation text'))
        connection.execute(text('ALTER TABLE "http-request-flood-prevention-rule" ADD COLUMN IF NOT EXISTS bot_recognition text'))
        connection.execute(text('ALTER TABLE "http-request-flood-prevention-rule" ADD COLUMN IF NOT EXISTS raw_json_http_connection jsonb'))
        connection.execute(text("ALTER TABLE signature ADD COLUMN IF NOT EXISTS cross_site_scripting_action text"))
        connection.execute(text("ALTER TABLE signature ADD COLUMN IF NOT EXISTS cross_site_scripting_extended_action text"))
        connection.execute(text("ALTER TABLE signature ADD COLUMN IF NOT EXISTS sql_injection_action text"))
        connection.execute(text("ALTER TABLE signature ADD COLUMN IF NOT EXISTS sql_injection_extended_action text"))
        connection.execute(text("ALTER TABLE signature ADD COLUMN IF NOT EXISTS generic_attacks_action text"))
        connection.execute(text("ALTER TABLE signature ADD COLUMN IF NOT EXISTS generic_attacks_extended_action text"))
        connection.execute(text("ALTER TABLE signature ADD COLUMN IF NOT EXISTS known_exploits_action text"))
        connection.execute(text("ALTER TABLE signature ADD COLUMN IF NOT EXISTS trojans_action text"))
        connection.execute(text("ALTER TABLE signature ADD COLUMN IF NOT EXISTS information_disclosure_action text"))
        connection.execute(text("ALTER TABLE signature ADD COLUMN IF NOT EXISTS personally_identifiable_information_action text"))
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS certificate_sni (
                    device_id bigint NOT NULL REFERENCES managed_devices(id) ON DELETE CASCADE,
                    sni_name text NOT NULL,
                    PRIMARY KEY (device_id, sni_name)
                )
                """
            )
        )
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS intermediate_certificate_groups (
                    device_id bigint NOT NULL REFERENCES managed_devices(id) ON DELETE CASCADE,
                    intermediate_certificate_group_name text NOT NULL,
                    PRIMARY KEY (device_id, intermediate_certificate_group_name)
                )
                """
            )
        )
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS server_pool (
                    id bigserial PRIMARY KEY,
                    device_id bigint NOT NULL,
                    server_pool_name text NOT NULL,
                    ip inet,
                    certificate_name text,
                    sni_certificate_name text,
                    intermediate_certificate_group_name text,
                    ssl_custom_cipher text,
                    tls13_custom_cipher text,
                    tls_v10 boolean,
                    tls_v11 boolean,
                    tls_v12 boolean,
                    tls_v13 boolean,
                    http2 boolean,
                    raw_json jsonb NOT NULL,
                    created_at timestamptz NOT NULL DEFAULT now(),
                    updated_at timestamptz NOT NULL DEFAULT now(),

                    CONSTRAINT fk_server_pool_device
                        FOREIGN KEY (device_id)
                        REFERENCES managed_devices(id)
                        ON DELETE CASCADE,

                    CONSTRAINT uq_server_pool_device_name
                        UNIQUE (device_id, server_pool_name),

                    CONSTRAINT fk_server_pool_certificate
                        FOREIGN KEY (device_id, certificate_name)
                        REFERENCES certificate_local(device_id, certificate_name)
                        ON DELETE SET NULL,

                    CONSTRAINT fk_server_pool_sni_certificate
                        FOREIGN KEY (device_id, sni_certificate_name)
                        REFERENCES certificate_sni(device_id, sni_name)
                        ON DELETE SET NULL,

                    CONSTRAINT fk_server_pool_intermediate_group
                        FOREIGN KEY (device_id, intermediate_certificate_group_name)
                        REFERENCES intermediate_certificate_groups(device_id, intermediate_certificate_group_name)
                        ON DELETE SET NULL
                )
                """
            )
        )
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS server_policy (
                    id bigserial PRIMARY KEY,
                    device_id bigint NOT NULL,
                    server_policy_name text NOT NULL,
                    web_protection_profile_name text,
                    server_pool_name text,
                    allow_hosts text,
                    traffic_mirror boolean,
                    raw_json jsonb NOT NULL,
                    created_at timestamptz NOT NULL DEFAULT now(),
                    updated_at timestamptz NOT NULL DEFAULT now(),

                    CONSTRAINT fk_server_policy_device
                        FOREIGN KEY (device_id)
                        REFERENCES managed_devices(id)
                        ON DELETE CASCADE,

                    CONSTRAINT uq_server_policy_device_name
                        UNIQUE (device_id, server_policy_name),

                    CONSTRAINT fk_server_policy_web_protection_profile
                        FOREIGN KEY (device_id, web_protection_profile_name)
                        REFERENCES web_protection_profiles(device_id, web_protection_profile_name)
                        ON DELETE SET NULL,

                    CONSTRAINT fk_server_policy_server_pool
                        FOREIGN KEY (device_id, server_pool_name)
                        REFERENCES server_pool(device_id, server_pool_name)
                        ON DELETE SET NULL
                )
                """
            )
        )
        connection.execute(text("ALTER TABLE server_policy ADD COLUMN IF NOT EXISTS allow_hosts text"))
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS allow_hosts (
                    id bigserial PRIMARY KEY,
                    device_id bigint NOT NULL REFERENCES managed_devices(id) ON DELETE CASCADE,
                    allow_hosts text NOT NULL,
                    host text,
                    raw_json jsonb NOT NULL,
                    created_at timestamptz NOT NULL DEFAULT now(),
                    updated_at timestamptz NOT NULL DEFAULT now(),
                    UNIQUE (device_id, allow_hosts, host)
                )
                """
            )
        )

    db = SessionLocal()
    try:
        if db.query(ManagedDevice).count() == 0:
            db.add_all(
                [
                    ManagedDevice(name="FortiWeb-Prod-TR-01", ip="10.10.1.15", model="FortiWeb VM", environment="Production", region="Istanbul", firmware="7.4.2", apikey="prod-tr-apikey", status="Online", last_sync="5 min ago"),
                    ManagedDevice(name="FortiWeb-DR-01", ip="10.20.1.22", model="FortiWeb 4000E", environment="Disaster Recovery", region="Ankara", firmware="7.2.6", apikey="dr-apikey", status="Warning", last_sync="42 min ago"),
                    ManagedDevice(name="FortiWeb-Test-01", ip="10.30.8.9", model="FortiWeb VM", environment="Test", region="Izmir", firmware="7.4.1", apikey="test-apikey", status="Offline", last_sync="3 hours ago"),
                ]
            )
            db.commit()
    finally:
        db.close()

    if settings.scheduler_enabled:
        scheduler.add_job(run_collection_job, "interval", minutes=settings.scheduler_minutes)
        scheduler.start()


@app.on_event("shutdown")
def shutdown_event():
    if scheduler.running:
        scheduler.shutdown(wait=False)


@app.get("/health/live")
def health_live():
    return {"status": "ok", "service": settings.app_name}


@app.get("/health/ready")
def health_ready():
    checks = {"database": False, "redis": False}

    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        checks["database"] = True
    except Exception:
        checks["database"] = False

    try:
        checks["redis"] = bool(redis_client.ping())
    except Exception:
        checks["redis"] = False

    status = "ready" if all(checks.values()) else "degraded"
    return {"status": status, "checks": checks}


@app.post("/auth/login", response_model=LoginResponse)
def login(payload: LoginRequest):
    if not verify_local_admin(payload.username, payload.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return LoginResponse(access_token="local-admin-token", username=payload.username)


@app.post("/fortiweb/server-policy/collect")
def collect_fortiweb_server_policy(
    db: Session = Depends(get_db),
    _: Annotated[str, Depends(require_analyst_or_admin)] = "analyst",
):
    devices = db.query(ManagedDevice).order_by(ManagedDevice.id.desc()).all()
    fetch_and_store_server_policies_by_device(db, devices)
    return {"payload": load_server_policies_from_db(db)}


@app.get("/fortiweb/server-policy/latest")
def latest_fortiweb_server_policy(
    db: Session = Depends(get_db),
    _: Annotated[str, Depends(require_role)] = "viewer",
):
    return {"payload": load_server_policies_from_db(db)}


@app.get("/devices", response_model=list[ManagedDeviceOut])
def list_devices(
    db: Session = Depends(get_db),
    _: Annotated[str, Depends(require_role)] = "viewer",
):
    return db.query(ManagedDevice).order_by(ManagedDevice.id.desc()).all()


@app.get("/devices/{device_id}", response_model=ManagedDeviceOut)
def get_device(
    device_id: int,
    db: Session = Depends(get_db),
    _: Annotated[str, Depends(require_role)] = "viewer",
):
    device = db.query(ManagedDevice).filter(ManagedDevice.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


@app.post("/devices", response_model=ManagedDeviceOut)
def create_device(
    payload: ManagedDeviceCreate,
    db: Session = Depends(get_db),
    _: Annotated[str, Depends(require_analyst_or_admin)] = "analyst",
):
    device = ManagedDevice(**payload.model_dump())
    db.add(device)
    db.commit()
    db.refresh(device)
    return device


@app.delete("/devices/{device_id}")
def delete_device(
    device_id: int,
    db: Session = Depends(get_db),
    _: Annotated[str, Depends(require_analyst_or_admin)] = "analyst",
):
    device = db.query(ManagedDevice).filter(ManagedDevice.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    db.delete(device)
    db.commit()
    return {"status": "deleted", "id": device_id}
