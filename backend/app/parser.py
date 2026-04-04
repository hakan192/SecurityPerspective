def extract_controls(raw: dict) -> dict[str, bool]:
    protection = raw.get("protection", {})
    updates = raw.get("updates", {})
    transport = raw.get("transport", {})
    monitoring = raw.get("monitoring", {})
    return {
        "waf_policy_enabled": bool(protection.get("waf_policy_enabled", False)),
        "signature_update_auto": bool(updates.get("signature_update_auto", False)),
        "bot_protection_enabled": bool(protection.get("bot_protection_enabled", False)),
        "https_redirect_enabled": bool(transport.get("https_redirect_enabled", False)),
        "logging_enabled": bool(monitoring.get("logging_enabled", False)),
    }
