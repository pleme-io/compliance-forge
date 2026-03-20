//! Configuration for compliance control generation.

use serde::{Deserialize, Serialize};

/// Impact levels for each control type.
///
/// InSpec uses impact values from 0.0 (informational) to 1.0 (critical).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactLevels {
    pub existence: f64,
    pub required_attrs: f64,
    pub type_validation: f64,
    pub sensitive_protection: f64,
    pub immutable_enforcement: f64,
    pub enum_validation: f64,
    pub default_verification: f64,
}

impl Default for ImpactLevels {
    fn default() -> Self {
        Self {
            existence: 1.0,
            required_attrs: 1.0,
            type_validation: 0.7,
            sensitive_protection: 1.0,
            immutable_enforcement: 0.7,
            enum_validation: 0.5,
            default_verification: 0.3,
        }
    }
}

/// Top-level configuration for compliance code generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceConfig {
    /// Impact scores per control type.
    pub impact: ImpactLevels,
    /// Compliance baseline name (e.g., "default", "strict", "minimal").
    pub baseline: String,
}

impl Default for ComplianceConfig {
    fn default() -> Self {
        Self {
            impact: ImpactLevels::default(),
            baseline: "default".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_baseline() {
        let config = ComplianceConfig::default();
        assert_eq!(config.baseline, "default");
    }

    #[test]
    fn default_impact_existence() {
        let config = ComplianceConfig::default();
        assert!((config.impact.existence - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn default_impact_type_validation() {
        let config = ComplianceConfig::default();
        assert!((config.impact.type_validation - 0.7).abs() < f64::EPSILON);
    }

    #[test]
    fn default_impact_default_verification() {
        let config = ComplianceConfig::default();
        assert!((config.impact.default_verification - 0.3).abs() < f64::EPSILON);
    }

    #[test]
    fn custom_config() {
        let config = ComplianceConfig {
            impact: ImpactLevels {
                existence: 0.9,
                required_attrs: 0.9,
                type_validation: 0.5,
                sensitive_protection: 1.0,
                immutable_enforcement: 0.5,
                enum_validation: 0.3,
                default_verification: 0.1,
            },
            baseline: "strict".to_string(),
        };
        assert_eq!(config.baseline, "strict");
        assert!((config.impact.existence - 0.9).abs() < f64::EPSILON);
        assert!((config.impact.enum_validation - 0.3).abs() < f64::EPSILON);
    }
}
