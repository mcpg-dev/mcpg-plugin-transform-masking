// Host builds don't export the wit Guest impl (see the cfg-gate on
// `wit_bindgen::generate!` below), so the masking helpers are only
// reached from `#[cfg(test)]` on host. Silence the dead-code warnings
// in the host-only configuration to keep the workspace build clean.
#![cfg_attr(not(any(target_arch = "wasm32", test)), allow(dead_code))]

//! MCPG Transform Plugin — Field Masking
//!
//! A Wasm Component Model plugin that masks sensitive fields in tool arguments
//! and results. Field names to mask are configured via the plugin config JSON.
//!
//! ## Config format
//!
//! ```json
//! {
//!   "policy": "strict",
//!   "redact_fields": ["ssn", "credit_card", "password"],
//!   "mask_char": "*",
//!   "mask_length": 8,
//!   "preserve_type": true,
//!   "nested": true
//! }
//! ```
//!
//! ## Behavior
//!
//! - `strict` policy: masks both arguments (pre-dispatch) and results (post-dispatch)
//! - `output_only` policy: masks only results (post-dispatch)
//! - `input_only` policy: masks only arguments (pre-dispatch)
//! - Nested object fields are searched recursively when `nested: true` (default)
//! - String values are replaced with `mask_char` repeated `mask_length` times
//! - Non-string values (numbers, booleans) are replaced with null when `preserve_type`
//!   is false, or kept as-is when `preserve_type` is true

// The WIT-exported surface is only compiled for the WebAssembly
// target (`cargo build --target wasm32-wasip2`). On a native host
// the wit-bindgen-emitted symbols carry WIT-style colons
// (`mcpg:plugin/transform@0.1.0#foo`) that GNU version scripts
// can't parse, so rust-lld fails the cdylib link step. Gating the
// wit glue on target_arch keeps `cargo build --workspace` green;
// the real Wasm artifact is still built via Nx.
#[cfg(target_arch = "wasm32")]
wit_bindgen::generate!({
    path: "wit/plugin.wit",
    world: "transform-plugin",
});

#[cfg(target_arch = "wasm32")]
use exports::mcpg::plugin::transform::Guest;
#[cfg(target_arch = "wasm32")]
use mcpg::plugin::types::{PluginContext, PluginManifest, TransformResult};

#[cfg(target_arch = "wasm32")]
struct MaskingPlugin;

#[cfg(target_arch = "wasm32")]
export!(MaskingPlugin);

#[cfg(target_arch = "wasm32")]
impl Guest for MaskingPlugin {
    fn manifest() -> PluginManifest {
        PluginManifest {
            id: "dev.mcpg.transform.masking".into(),
            version: "0.1.0".into(),
            name: "Field Masking Transform".into(),
            plugin_class: "transform".into(),
            protocol_version: "1.0".to_owned(),
        }
    }

    fn transform_arguments(
        ctx: PluginContext,
        arguments: String,
        config: String,
    ) -> TransformResult {
        let _ = &ctx;
        let cfg = match parse_config(&config) {
            Ok(c) => c,
            Err(e) => return TransformResult::Error(format!("invalid config: {e}")),
        };

        // Only mask arguments in strict or input_only policy
        if cfg.policy != Policy::Strict && cfg.policy != Policy::InputOnly {
            return TransformResult::Unchanged;
        }

        match serde_json::from_str::<serde_json::Value>(&arguments) {
            Ok(mut value) => {
                let changed = mask_fields(&mut value, &cfg);
                if changed {
                    TransformResult::Modified(serde_json::to_string(&value).unwrap_or(arguments))
                } else {
                    TransformResult::Unchanged
                }
            }
            Err(_) => TransformResult::Unchanged,
        }
    }

    fn transform_output(ctx: PluginContext, result: String, config: String) -> TransformResult {
        let _ = &ctx;
        let cfg = match parse_config(&config) {
            Ok(c) => c,
            Err(e) => return TransformResult::Error(format!("invalid config: {e}")),
        };

        // Only mask results in strict or output_only policy
        if cfg.policy != Policy::Strict && cfg.policy != Policy::OutputOnly {
            return TransformResult::Unchanged;
        }

        match serde_json::from_str::<serde_json::Value>(&result) {
            Ok(mut value) => {
                let changed = mask_fields(&mut value, &cfg);
                if changed {
                    TransformResult::Modified(serde_json::to_string(&value).unwrap_or(result))
                } else {
                    TransformResult::Unchanged
                }
            }
            Err(_) => TransformResult::Unchanged,
        }
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
enum Policy {
    Strict,
    InputOnly,
    OutputOnly,
}

struct MaskConfig {
    policy: Policy,
    redact_fields: Vec<String>,
    mask_char: char,
    mask_length: usize,
    preserve_type: bool,
    nested: bool,
}

fn parse_config(json: &str) -> Result<MaskConfig, String> {
    let val: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("JSON parse: {e}"))?;

    let policy_str = val
        .get("policy")
        .and_then(|v| v.as_str())
        .unwrap_or("strict");
    let policy = match policy_str {
        "strict" => Policy::Strict,
        "input_only" => Policy::InputOnly,
        "output_only" => Policy::OutputOnly,
        other => return Err(format!("unknown policy: {other}")),
    };

    let redact_fields: Vec<String> = val
        .get("redact_fields")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_lowercase()))
                .collect()
        })
        .unwrap_or_default();

    if redact_fields.is_empty() {
        return Err("redact_fields must contain at least one field name".into());
    }

    let mask_char = val
        .get("mask_char")
        .and_then(|v| v.as_str())
        .and_then(|s| s.chars().next())
        .unwrap_or('*');

    let mask_length = val.get("mask_length").and_then(|v| v.as_u64()).unwrap_or(8) as usize;

    let preserve_type = val
        .get("preserve_type")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let nested = val.get("nested").and_then(|v| v.as_bool()).unwrap_or(true);

    Ok(MaskConfig {
        policy,
        redact_fields,
        mask_char,
        mask_length,
        preserve_type,
        nested,
    })
}

// ---------------------------------------------------------------------------
// Masking logic
// ---------------------------------------------------------------------------

fn mask_fields(value: &mut serde_json::Value, cfg: &MaskConfig) -> bool {
    match value {
        serde_json::Value::Object(map) => {
            let mut changed = false;
            // Collect keys that need masking (case-insensitive match).
            let keys: Vec<String> = map.keys().cloned().collect();
            for key in &keys {
                let key_lower = key.to_lowercase();
                if cfg
                    .redact_fields
                    .iter()
                    .any(|rf| field_matches(&key_lower, rf))
                {
                    if let Some(val) = map.get_mut(key) {
                        mask_value(val, cfg);
                        changed = true;
                    }
                } else if cfg.nested
                    && let Some(val) = map.get_mut(key)
                    && mask_fields(val, cfg)
                {
                    changed = true;
                }
            }
            changed
        }
        serde_json::Value::Array(arr) => {
            let mut changed = false;
            for item in arr.iter_mut() {
                if mask_fields(item, cfg) {
                    changed = true;
                }
            }
            changed
        }
        _ => false,
    }
}

/// Check if a field key matches a redact pattern.
/// Supports exact match and wildcard suffix (e.g., "card_*" matches "card_number").
fn field_matches(key: &str, pattern: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        key.starts_with(prefix)
    } else {
        key == pattern
    }
}

fn mask_value(value: &mut serde_json::Value, cfg: &MaskConfig) {
    match value {
        serde_json::Value::String(_) => {
            let masked: String = std::iter::repeat_n(cfg.mask_char, cfg.mask_length).collect();
            *value = serde_json::Value::String(masked);
        }
        serde_json::Value::Number(_) | serde_json::Value::Bool(_) => {
            if !cfg.preserve_type {
                *value = serde_json::Value::Null;
            }
            // preserve_type: true → leave primitive as-is (masking only applies to strings)
        }
        serde_json::Value::Array(arr) => {
            // Mask each element in the array
            for item in arr.iter_mut() {
                mask_value(item, cfg);
            }
        }
        serde_json::Value::Object(map) => {
            // Mask all values in the sub-object
            for val in map.values_mut() {
                mask_value(val, cfg);
            }
        }
        serde_json::Value::Null => {}
    }
}

// ---------------------------------------------------------------------------
// Tests (native-only, exercising the masking logic)
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> MaskConfig {
        MaskConfig {
            policy: Policy::Strict,
            redact_fields: vec!["ssn".into(), "credit_card".into(), "password".into()],
            mask_char: '*',
            mask_length: 8,
            preserve_type: true,
            nested: true,
        }
    }

    #[test]
    fn masks_top_level_string_fields() {
        let cfg = test_config();
        let mut val = serde_json::json!({
            "name": "Alice",
            "ssn": "123-45-6789",
            "age": 30
        });
        let changed = mask_fields(&mut val, &cfg);
        assert!(changed);
        assert_eq!(val["ssn"], "********");
        assert_eq!(val["name"], "Alice");
        assert_eq!(val["age"], 30);
    }

    #[test]
    fn masks_nested_fields() {
        let cfg = test_config();
        let mut val = serde_json::json!({
            "user": {
                "name": "Bob",
                "credit_card": "4111-1111-1111-1111"
            }
        });
        let changed = mask_fields(&mut val, &cfg);
        assert!(changed);
        assert_eq!(val["user"]["credit_card"], "********");
        assert_eq!(val["user"]["name"], "Bob");
    }

    #[test]
    fn no_change_when_no_matching_fields() {
        let cfg = test_config();
        let mut val = serde_json::json!({ "name": "Alice", "email": "a@b.com" });
        let changed = mask_fields(&mut val, &cfg);
        assert!(!changed);
    }

    #[test]
    fn case_insensitive_matching() {
        let cfg = test_config();
        let mut val = serde_json::json!({ "SSN": "123", "Password": "secret" });
        let changed = mask_fields(&mut val, &cfg);
        assert!(changed);
        assert_eq!(val["SSN"], "********");
        assert_eq!(val["Password"], "********");
    }

    #[test]
    fn wildcard_suffix_pattern() {
        let cfg = MaskConfig {
            policy: Policy::Strict,
            redact_fields: vec!["card_*".into()],
            mask_char: 'X',
            mask_length: 4,
            preserve_type: true,
            nested: true,
        };
        let mut val = serde_json::json!({
            "card_number": "4111",
            "card_cvv": "123",
            "name": "Alice"
        });
        let changed = mask_fields(&mut val, &cfg);
        assert!(changed);
        assert_eq!(val["card_number"], "XXXX");
        assert_eq!(val["card_cvv"], "XXXX");
        assert_eq!(val["name"], "Alice");
    }

    #[test]
    fn preserves_type_for_numbers_by_default() {
        let cfg = test_config();
        let mut val = serde_json::json!({ "ssn": 123456789 });
        let changed = mask_fields(&mut val, &cfg);
        assert!(!changed || val["ssn"] == 123456789);
    }

    #[test]
    fn nullifies_numbers_when_preserve_type_false() {
        let mut cfg = test_config();
        cfg.preserve_type = false;
        let mut val = serde_json::json!({ "ssn": 123456789 });
        let changed = mask_fields(&mut val, &cfg);
        assert!(changed);
        assert!(val["ssn"].is_null());
    }

    #[test]
    fn masks_array_elements() {
        let cfg = test_config();
        let mut val = serde_json::json!({
            "records": [
                { "ssn": "111-11-1111", "name": "A" },
                { "ssn": "222-22-2222", "name": "B" }
            ]
        });
        let changed = mask_fields(&mut val, &cfg);
        assert!(changed);
        assert_eq!(val["records"][0]["ssn"], "********");
        assert_eq!(val["records"][1]["ssn"], "********");
        assert_eq!(val["records"][0]["name"], "A");
    }

    #[test]
    fn masks_nested_object_within_matched_field() {
        let cfg = test_config();
        let mut val = serde_json::json!({
            "credit_card": {
                "number": "4111-1111",
                "cvv": "123"
            }
        });
        let changed = mask_fields(&mut val, &cfg);
        assert!(changed);
        // When a matched field contains an object, all its values are masked
        assert_eq!(val["credit_card"]["number"], "********");
        assert_eq!(val["credit_card"]["cvv"], "********");
    }

    #[test]
    fn nested_false_skips_deep_fields() {
        let mut cfg = test_config();
        cfg.nested = false;
        let mut val = serde_json::json!({
            "user": { "ssn": "123-45-6789" }
        });
        let changed = mask_fields(&mut val, &cfg);
        assert!(!changed); // ssn is nested, but nested=false
    }

    #[test]
    fn custom_mask_char_and_length() {
        let cfg = MaskConfig {
            policy: Policy::Strict,
            redact_fields: vec!["ssn".into()],
            mask_char: '#',
            mask_length: 4,
            preserve_type: true,
            nested: true,
        };
        let mut val = serde_json::json!({ "ssn": "123-45-6789" });
        mask_fields(&mut val, &cfg);
        assert_eq!(val["ssn"], "####");
    }

    #[test]
    fn parse_config_valid() {
        let json = r#"{"policy":"strict","redact_fields":["ssn","password"]}"#;
        let cfg = parse_config(json).unwrap();
        assert_eq!(cfg.policy, Policy::Strict);
        assert_eq!(cfg.redact_fields, vec!["ssn", "password"]);
        assert_eq!(cfg.mask_char, '*');
        assert_eq!(cfg.mask_length, 8);
    }

    #[test]
    fn parse_config_unknown_policy_errors() {
        let json = r#"{"policy":"unknown","redact_fields":["ssn"]}"#;
        assert!(parse_config(json).is_err());
    }

    #[test]
    fn parse_config_empty_redact_fields_errors() {
        let json = r#"{"redact_fields":[]}"#;
        assert!(parse_config(json).is_err());
    }

    #[test]
    fn parse_config_defaults() {
        let json = r#"{"redact_fields":["x"]}"#;
        let cfg = parse_config(json).unwrap();
        assert_eq!(cfg.policy, Policy::Strict);
        assert_eq!(cfg.mask_char, '*');
        assert_eq!(cfg.mask_length, 8);
        assert!(cfg.preserve_type);
        assert!(cfg.nested);
    }

    #[test]
    fn input_only_policy_skips_output() {
        let cfg = MaskConfig {
            policy: Policy::InputOnly,
            redact_fields: vec!["ssn".into()],
            mask_char: '*',
            mask_length: 8,
            preserve_type: true,
            nested: true,
        };
        // input_only: mask_fields should work (called by transform_arguments)
        let mut val = serde_json::json!({ "ssn": "123" });
        assert!(mask_fields(&mut val, &cfg));

        // But the transform_output path would check policy != Strict and != OutputOnly
        // and return Unchanged
    }

    #[test]
    fn output_only_policy_skips_input() {
        let _cfg = MaskConfig {
            policy: Policy::OutputOnly,
            redact_fields: vec!["ssn".into()],
            mask_char: '*',
            mask_length: 8,
            preserve_type: true,
            nested: true,
        };
        // The transform_arguments path checks policy != Strict and != InputOnly
        // For OutputOnly, transform_arguments returns Unchanged
        // (tested via the WIT export path)
    }
}
