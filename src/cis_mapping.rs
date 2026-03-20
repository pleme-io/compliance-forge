//! Maps resource categories to CIS benchmark identifiers.

/// Return CIS benchmark IDs for a resource category.
///
/// These align with CIS Controls v8 safeguards.
#[must_use]
pub fn cis_controls_for_category(category: &str) -> Vec<&'static str> {
    match category {
        "auth_method" | "auth" => vec!["CIS-5.2", "CIS-6.3", "CIS-6.5"],
        "secret" | "secrets" => vec!["CIS-3.7", "CIS-3.10", "CIS-3.11"],
        "target" | "targets" => vec!["CIS-12.2", "CIS-12.4"],
        "role" | "roles" => vec!["CIS-5.4", "CIS-6.1", "CIS-6.8"],
        "key" | "keys" | "encryption" => vec!["CIS-3.6", "CIS-3.7"],
        "event_forwarder" | "logging" | "audit" => vec!["CIS-8.2", "CIS-8.5", "CIS-8.9"],
        "gateway" | "gateways" => vec!["CIS-12.2", "CIS-13.4"],
        "certificate" | "certificates" | "pki" => vec!["CIS-3.10", "CIS-3.11"],
        "policy" | "policies" => vec!["CIS-4.1", "CIS-4.8"],
        "network" | "firewall" => vec!["CIS-4.4", "CIS-12.2", "CIS-13.4"],
        _ => vec!["CIS-4.1"],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_method_category() {
        let controls = cis_controls_for_category("auth_method");
        assert!(controls.contains(&"CIS-5.2"));
        assert!(controls.contains(&"CIS-6.3"));
    }

    #[test]
    fn auth_alias() {
        assert_eq!(
            cis_controls_for_category("auth"),
            cis_controls_for_category("auth_method")
        );
    }

    #[test]
    fn secret_category() {
        let controls = cis_controls_for_category("secret");
        assert!(controls.contains(&"CIS-3.7"));
        assert!(controls.contains(&"CIS-3.11"));
    }

    #[test]
    fn target_category() {
        let controls = cis_controls_for_category("target");
        assert!(controls.contains(&"CIS-12.2"));
    }

    #[test]
    fn role_category() {
        let controls = cis_controls_for_category("role");
        assert!(controls.contains(&"CIS-5.4"));
        assert!(controls.contains(&"CIS-6.1"));
    }

    #[test]
    fn key_category() {
        let controls = cis_controls_for_category("key");
        assert!(controls.contains(&"CIS-3.6"));
    }

    #[test]
    fn event_forwarder_category() {
        let controls = cis_controls_for_category("event_forwarder");
        assert!(controls.contains(&"CIS-8.2"));
        assert!(controls.contains(&"CIS-8.5"));
    }

    #[test]
    fn gateway_category() {
        let controls = cis_controls_for_category("gateway");
        assert!(controls.contains(&"CIS-12.2"));
    }

    #[test]
    fn certificate_category() {
        let controls = cis_controls_for_category("certificate");
        assert!(controls.contains(&"CIS-3.10"));
    }

    #[test]
    fn unknown_category_fallback() {
        let controls = cis_controls_for_category("unknown_thing");
        assert_eq!(controls, vec!["CIS-4.1"]);
    }

    #[test]
    fn policy_category() {
        let controls = cis_controls_for_category("policy");
        assert!(controls.contains(&"CIS-4.1"));
    }

    #[test]
    fn network_category() {
        let controls = cis_controls_for_category("network");
        assert!(controls.contains(&"CIS-4.4"));
        assert!(controls.contains(&"CIS-12.2"));
    }
}
