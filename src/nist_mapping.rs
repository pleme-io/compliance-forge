//! Maps resource categories to NIST 800-53 control identifiers.

/// Return NIST 800-53 control IDs for a resource category.
///
/// Categories align with typical cloud/vault resource groupings.
/// Unknown categories get a baseline set of configuration management controls.
#[must_use]
pub fn nist_controls_for_category(category: &str) -> Vec<&'static str> {
    match category {
        "auth_method" | "auth" => vec!["AC-2", "AC-3", "IA-2", "IA-5"],
        "secret" | "secrets" => vec!["SC-12", "SC-28", "MP-4"],
        "target" | "targets" => vec!["SC-7", "AC-17", "CA-3"],
        "role" | "roles" => vec!["AC-2", "AC-3", "AC-5", "AC-6"],
        "key" | "keys" | "encryption" => vec!["SC-12", "SC-13"],
        "event_forwarder" | "logging" | "audit" => vec!["AU-2", "AU-3", "AU-6"],
        "gateway" | "gateways" => vec!["SC-7", "AC-17"],
        "certificate" | "certificates" | "pki" => vec!["SC-12", "SC-17", "IA-5"],
        "policy" | "policies" => vec!["AC-1", "CM-1", "SI-1"],
        "network" | "firewall" => vec!["SC-7", "AC-4", "SC-8"],
        _ => vec!["CM-2", "CM-6"],
    }
}

/// NIST controls that apply to all existence checks.
#[must_use]
pub fn existence_controls() -> Vec<&'static str> {
    vec!["CM-2", "CM-8"]
}

/// NIST controls for required attribute enforcement.
#[must_use]
pub fn required_attr_controls() -> Vec<&'static str> {
    vec!["CM-6"]
}

/// NIST controls for sensitive data protection.
#[must_use]
pub fn sensitive_controls() -> Vec<&'static str> {
    vec!["SC-28", "AC-3"]
}

/// NIST controls for immutable enforcement.
#[must_use]
pub fn immutable_controls() -> Vec<&'static str> {
    vec!["CM-3"]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_method_category() {
        let controls = nist_controls_for_category("auth_method");
        assert!(controls.contains(&"AC-2"));
        assert!(controls.contains(&"IA-2"));
        assert!(controls.contains(&"IA-5"));
    }

    #[test]
    fn auth_alias() {
        assert_eq!(
            nist_controls_for_category("auth"),
            nist_controls_for_category("auth_method")
        );
    }

    #[test]
    fn secret_category() {
        let controls = nist_controls_for_category("secret");
        assert!(controls.contains(&"SC-12"));
        assert!(controls.contains(&"SC-28"));
        assert!(controls.contains(&"MP-4"));
    }

    #[test]
    fn target_category() {
        let controls = nist_controls_for_category("target");
        assert!(controls.contains(&"SC-7"));
        assert!(controls.contains(&"AC-17"));
    }

    #[test]
    fn role_category() {
        let controls = nist_controls_for_category("role");
        assert!(controls.contains(&"AC-5"));
        assert!(controls.contains(&"AC-6"));
    }

    #[test]
    fn key_category() {
        let controls = nist_controls_for_category("key");
        assert!(controls.contains(&"SC-12"));
        assert!(controls.contains(&"SC-13"));
    }

    #[test]
    fn event_forwarder_category() {
        let controls = nist_controls_for_category("event_forwarder");
        assert!(controls.contains(&"AU-2"));
        assert!(controls.contains(&"AU-3"));
    }

    #[test]
    fn gateway_category() {
        let controls = nist_controls_for_category("gateway");
        assert!(controls.contains(&"SC-7"));
    }

    #[test]
    fn certificate_category() {
        let controls = nist_controls_for_category("certificate");
        assert!(controls.contains(&"SC-17"));
    }

    #[test]
    fn policy_category() {
        let controls = nist_controls_for_category("policy");
        assert!(controls.contains(&"AC-1"));
    }

    #[test]
    fn network_category() {
        let controls = nist_controls_for_category("network");
        assert!(controls.contains(&"SC-7"));
        assert!(controls.contains(&"AC-4"));
    }

    #[test]
    fn unknown_category_fallback() {
        let controls = nist_controls_for_category("unknown_thing");
        assert_eq!(controls, vec!["CM-2", "CM-6"]);
    }

    #[test]
    fn existence_controls_include_cm8() {
        assert!(existence_controls().contains(&"CM-8"));
    }

    #[test]
    fn required_attr_controls_include_cm6() {
        assert!(required_attr_controls().contains(&"CM-6"));
    }

    #[test]
    fn sensitive_controls_include_sc28() {
        assert!(sensitive_controls().contains(&"SC-28"));
    }

    #[test]
    fn immutable_controls_include_cm3() {
        assert!(immutable_controls().contains(&"CM-3"));
    }
}
