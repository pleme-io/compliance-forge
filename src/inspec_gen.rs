//! InSpec control generation from `IacResource`.
//!
//! Generates Ruby InSpec control blocks for the 7 control types:
//! existence, required attributes, type validation, sensitive protection,
//! immutable enforcement, enum validation, and default verification.

use iac_forge::ir::{IacAttribute, IacResource, IacType};

use crate::cis_mapping;
use crate::config::ComplianceConfig;
use crate::nist_mapping;
use crate::type_map;

/// Format a list of NIST control IDs as a Ruby array literal.
fn nist_tag(controls: &[&str]) -> String {
    let items: Vec<String> = controls.iter().map(|c| format!("'{c}'")).collect();
    format!("[{}]", items.join(", "))
}

/// Format a list of CIS control IDs as a Ruby array literal.
fn cis_tag(controls: &[&str]) -> String {
    let items: Vec<String> = controls.iter().map(|c| format!("'{c}'")).collect();
    format!("[{}]", items.join(", "))
}

/// Generate the existence control block.
#[must_use]
pub fn generate_existence_control(resource: &IacResource, config: &ComplianceConfig) -> String {
    let nist = nist_mapping::existence_controls();
    let cis = cis_mapping::cis_controls_for_category(&resource.category);
    format!(
        r#"control '{name}-existence' do
  impact {impact}
  title '{name} must exist'
  desc 'Verify that the {name} resource exists and is properly configured.'
  tag nist: {nist}
  tag cis: {cis}

  describe {name}(name: resource_name) do
    it {{ should exist }}
  end
end
"#,
        name = resource.name,
        impact = config.impact.existence,
        nist = nist_tag(&nist),
        cis = cis_tag(&cis),
    )
}

/// Generate the required attributes control block.
#[must_use]
pub fn generate_required_attrs_control(
    resource: &IacResource,
    config: &ComplianceConfig,
) -> String {
    let required_attrs: Vec<&IacAttribute> =
        resource.attributes.iter().filter(|a| a.required).collect();

    if required_attrs.is_empty() {
        return String::new();
    }

    let nist = nist_mapping::required_attr_controls();
    let cis = cis_mapping::cis_controls_for_category(&resource.category);

    let mut checks = String::new();
    for attr in &required_attrs {
        checks.push_str(&format!(
            "    its('{}') {{ should_not be_nil }}\n",
            attr.canonical_name
        ));
    }

    format!(
        r#"control '{name}-required-attrs' do
  impact {impact}
  title '{name} required attributes must be present'
  desc 'Verify that all required attributes of {name} are set.'
  tag nist: {nist}
  tag cis: {cis}

  describe {name}(name: resource_name) do
{checks}  end
end
"#,
        name = resource.name,
        impact = config.impact.required_attrs,
        nist = nist_tag(&nist),
        cis = cis_tag(&cis),
    )
}

/// Generate the type validation control block.
#[must_use]
pub fn generate_type_validation_control(
    resource: &IacResource,
    config: &ComplianceConfig,
) -> String {
    let typed_attrs: Vec<&IacAttribute> = resource
        .attributes
        .iter()
        .filter(|a| !matches!(a.iac_type, IacType::Any))
        .collect();

    if typed_attrs.is_empty() {
        return String::new();
    }

    let nist = nist_mapping::nist_controls_for_category(&resource.category);
    let cis = cis_mapping::cis_controls_for_category(&resource.category);

    let mut checks = String::new();
    for attr in &typed_attrs {
        let assertion = type_map::ruby_type_assertion(&attr.iac_type);
        let type_name = type_map::ruby_type_name(&attr.iac_type);
        checks.push_str(&format!(
            "    its('{}') {{ should {assertion} }} # expected: {type_name}\n",
            attr.canonical_name
        ));
    }

    format!(
        r#"control '{name}-type-validation' do
  impact {impact}
  title '{name} attributes must have correct types'
  desc 'Verify that attributes of {name} conform to their expected types.'
  tag nist: {nist}
  tag cis: {cis}

  describe {name}(name: resource_name) do
{checks}  end
end
"#,
        name = resource.name,
        impact = config.impact.type_validation,
        nist = nist_tag(&nist),
        cis = cis_tag(&cis),
    )
}

/// Generate the sensitive protection control block.
#[must_use]
pub fn generate_sensitive_control(resource: &IacResource, config: &ComplianceConfig) -> String {
    let sensitive_attrs: Vec<&IacAttribute> =
        resource.attributes.iter().filter(|a| a.sensitive).collect();

    if sensitive_attrs.is_empty() {
        return String::new();
    }

    let nist = nist_mapping::sensitive_controls();
    let cis = cis_mapping::cis_controls_for_category(&resource.category);

    let mut checks = String::new();
    for attr in &sensitive_attrs {
        checks.push_str(&format!(
            r#"  describe 'sensitive field {}' do
    it 'should not appear in logs' do
      expect(subject.to_s).not_to include('{}')
    end
  end
"#,
            attr.canonical_name, attr.canonical_name
        ));
    }

    format!(
        r#"control '{name}-sensitive-protection' do
  impact {impact}
  title '{name} sensitive attributes must be protected'
  desc 'Verify that sensitive attributes of {name} are not exposed in logs or output.'
  tag nist: {nist}
  tag cis: {cis}

{checks}end
"#,
        name = resource.name,
        impact = config.impact.sensitive_protection,
        nist = nist_tag(&nist),
        cis = cis_tag(&cis),
    )
}

/// Generate the immutable enforcement control block.
#[must_use]
pub fn generate_immutable_control(resource: &IacResource, config: &ComplianceConfig) -> String {
    let immutable_attrs: Vec<&IacAttribute> = resource
        .attributes
        .iter()
        .filter(|a| a.immutable)
        .collect();

    if immutable_attrs.is_empty() {
        return String::new();
    }

    let nist = nist_mapping::immutable_controls();
    let cis = cis_mapping::cis_controls_for_category(&resource.category);

    let mut checks = String::new();
    for attr in &immutable_attrs {
        checks.push_str(&format!(
            r#"  describe 'immutable field {}' do
    it 'should not be changed after creation' do
      expect({name}(name: resource_name).{field}).to eq(original_{field})
    end
  end
"#,
            attr.canonical_name,
            name = resource.name,
            field = attr.canonical_name
        ));
    }

    format!(
        r#"control '{name}-immutable-enforcement' do
  impact {impact}
  title '{name} immutable attributes must not change'
  desc 'Verify that immutable attributes of {name} cannot be modified after creation.'
  tag nist: {nist}
  tag cis: {cis}

{checks}end
"#,
        name = resource.name,
        impact = config.impact.immutable_enforcement,
        nist = nist_tag(&nist),
        cis = cis_tag(&cis),
    )
}

/// Generate the enum validation control block.
#[must_use]
pub fn generate_enum_control(resource: &IacResource, config: &ComplianceConfig) -> String {
    let enum_attrs: Vec<&IacAttribute> = resource
        .attributes
        .iter()
        .filter(|a| a.enum_values.is_some())
        .collect();

    if enum_attrs.is_empty() {
        return String::new();
    }

    let nist = nist_mapping::nist_controls_for_category(&resource.category);
    let cis = cis_mapping::cis_controls_for_category(&resource.category);

    let mut checks = String::new();
    for attr in &enum_attrs {
        if let Some(values) = &attr.enum_values {
            let items: Vec<String> = values.iter().map(|v| format!("'{v}'")).collect();
            let values_str = items.join(", ");
            checks.push_str(&format!(
                "    its('{}') {{ should be_in [{}] }}\n",
                attr.canonical_name, values_str
            ));
        }
    }

    format!(
        r#"control '{name}-enum-validation' do
  impact {impact}
  title '{name} enum attributes must have valid values'
  desc 'Verify that enum-constrained attributes of {name} contain only allowed values.'
  tag nist: {nist}
  tag cis: {cis}

  describe {name}(name: resource_name) do
{checks}  end
end
"#,
        name = resource.name,
        impact = config.impact.enum_validation,
        nist = nist_tag(&nist),
        cis = cis_tag(&cis),
    )
}

/// Generate the default verification control block.
#[must_use]
pub fn generate_default_control(resource: &IacResource, config: &ComplianceConfig) -> String {
    let default_attrs: Vec<&IacAttribute> = resource
        .attributes
        .iter()
        .filter(|a| a.default_value.is_some())
        .collect();

    if default_attrs.is_empty() {
        return String::new();
    }

    let nist = nist_mapping::nist_controls_for_category(&resource.category);
    let cis = cis_mapping::cis_controls_for_category(&resource.category);

    let mut checks = String::new();
    for attr in &default_attrs {
        if let Some(default) = &attr.default_value {
            let default_str = match default {
                serde_json::Value::String(s) => format!("'{s}'"),
                serde_json::Value::Bool(b) => b.to_string(),
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::Null => "nil".to_string(),
                other => other.to_string(),
            };
            checks.push_str(&format!(
                "    its('{}') {{ should eq {} }}\n",
                attr.canonical_name, default_str
            ));
        }
    }

    format!(
        r#"control '{name}-default-verification' do
  impact {impact}
  title '{name} default attribute values must be correct'
  desc 'Verify that attributes with defaults in {name} have their expected default values.'
  tag nist: {nist}
  tag cis: {cis}

  describe {name}(name: resource_name) do
{checks}  end
end
"#,
        name = resource.name,
        impact = config.impact.default_verification,
        nist = nist_tag(&nist),
        cis = cis_tag(&cis),
    )
}

/// Generate all InSpec controls for a resource as a single file.
#[must_use]
pub fn generate_resource_controls(resource: &IacResource, config: &ComplianceConfig) -> String {
    let mut output = String::from(
        "# frozen_string_literal: true\n# Code generated by compliance-forge. DO NOT EDIT.\n\n",
    );

    output.push_str(&generate_existence_control(resource, config));
    output.push('\n');

    let required = generate_required_attrs_control(resource, config);
    if !required.is_empty() {
        output.push_str(&required);
        output.push('\n');
    }

    let type_val = generate_type_validation_control(resource, config);
    if !type_val.is_empty() {
        output.push_str(&type_val);
        output.push('\n');
    }

    let sensitive = generate_sensitive_control(resource, config);
    if !sensitive.is_empty() {
        output.push_str(&sensitive);
        output.push('\n');
    }

    let immutable = generate_immutable_control(resource, config);
    if !immutable.is_empty() {
        output.push_str(&immutable);
        output.push('\n');
    }

    let enum_ctrl = generate_enum_control(resource, config);
    if !enum_ctrl.is_empty() {
        output.push_str(&enum_ctrl);
        output.push('\n');
    }

    let default_ctrl = generate_default_control(resource, config);
    if !default_ctrl.is_empty() {
        output.push_str(&default_ctrl);
        output.push('\n');
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use iac_forge::testing::{TestAttributeBuilder, test_resource, test_resource_with_type};

    fn default_config() -> ComplianceConfig {
        ComplianceConfig::default()
    }

    // ---- existence control ----

    #[test]
    fn existence_control_format() {
        let r = test_resource("my_secret");
        let config = default_config();
        let output = generate_existence_control(&r, &config);
        assert!(output.contains("control 'my_secret-existence'"));
        assert!(output.contains("should exist"));
        assert!(output.contains("impact 1"));
    }

    #[test]
    fn existence_control_has_nist_tags() {
        let r = test_resource("my_secret");
        let config = default_config();
        let output = generate_existence_control(&r, &config);
        assert!(output.contains("tag nist:"));
        assert!(output.contains("CM-8"));
    }

    #[test]
    fn existence_control_has_cis_tags() {
        let r = test_resource("my_secret");
        let config = default_config();
        let output = generate_existence_control(&r, &config);
        assert!(output.contains("tag cis:"));
    }

    // ---- required attrs control ----

    #[test]
    fn required_attrs_control_format() {
        let r = test_resource("my_secret");
        let config = default_config();
        let output = generate_required_attrs_control(&r, &config);
        assert!(output.contains("control 'my_secret-required-attrs'"));
        assert!(output.contains("should_not be_nil"));
        assert!(output.contains("its('name')"));
        assert!(output.contains("its('value')"));
    }

    #[test]
    fn required_attrs_control_empty_when_no_required() {
        let mut r = test_resource("my_secret");
        for attr in &mut r.attributes {
            attr.required = false;
        }
        let config = default_config();
        let output = generate_required_attrs_control(&r, &config);
        assert!(output.is_empty());
    }

    #[test]
    fn required_attrs_control_has_nist_cm6() {
        let r = test_resource("my_secret");
        let config = default_config();
        let output = generate_required_attrs_control(&r, &config);
        assert!(output.contains("CM-6"));
    }

    // ---- type validation control ----

    #[test]
    fn type_validation_control_string() {
        let r = test_resource("my_secret");
        let config = default_config();
        let output = generate_type_validation_control(&r, &config);
        assert!(output.contains("control 'my_secret-type-validation'"));
        assert!(output.contains("be_a(String)"));
    }

    #[test]
    fn type_validation_control_integer() {
        let r = test_resource_with_type("counter", "count", IacType::Integer);
        let config = default_config();
        let output = generate_type_validation_control(&r, &config);
        assert!(output.contains("be_a(Integer)"));
    }

    #[test]
    fn type_validation_control_boolean() {
        let r = test_resource_with_type("flag", "enabled", IacType::Boolean);
        let config = default_config();
        let output = generate_type_validation_control(&r, &config);
        assert!(output.contains("satisfy { |v| [true, false].include?(v) }"));
    }

    #[test]
    fn type_validation_control_list() {
        let r = test_resource_with_type(
            "tagged",
            "tags",
            IacType::List(Box::new(IacType::String)),
        );
        let config = default_config();
        let output = generate_type_validation_control(&r, &config);
        assert!(output.contains("be_an(Array)"));
    }

    #[test]
    fn type_validation_control_impact() {
        let r = test_resource("my_secret");
        let config = default_config();
        let output = generate_type_validation_control(&r, &config);
        assert!(output.contains("impact 0.7"));
    }

    #[test]
    fn type_validation_control_empty_for_any_only() {
        let r = test_resource_with_type("dynamic", "data", IacType::Any);
        let config = default_config();
        let output = generate_type_validation_control(&r, &config);
        assert!(output.is_empty());
    }

    // ---- sensitive control ----

    #[test]
    fn sensitive_control_format() {
        let r = test_resource("my_secret");
        let config = default_config();
        let output = generate_sensitive_control(&r, &config);
        assert!(output.contains("control 'my_secret-sensitive-protection'"));
        assert!(output.contains("should not appear in logs"));
        assert!(output.contains("value")); // "value" is the sensitive attr in test_resource
    }

    #[test]
    fn sensitive_control_empty_when_no_sensitive() {
        let r = test_resource_with_type("safe", "name", IacType::String);
        let config = default_config();
        let output = generate_sensitive_control(&r, &config);
        assert!(output.is_empty());
    }

    #[test]
    fn sensitive_control_has_sc28_tag() {
        let r = test_resource("my_secret");
        let config = default_config();
        let output = generate_sensitive_control(&r, &config);
        assert!(output.contains("SC-28"));
    }

    // ---- immutable control ----

    #[test]
    fn immutable_control_format() {
        let r = test_resource("my_secret");
        let config = default_config();
        let output = generate_immutable_control(&r, &config);
        assert!(output.contains("control 'my_secret-immutable-enforcement'"));
        assert!(output.contains("should not be changed after creation"));
        assert!(output.contains("name")); // "name" is immutable in test_resource
    }

    #[test]
    fn immutable_control_empty_when_no_immutable() {
        let r = test_resource_with_type("mutable", "data", IacType::String);
        let config = default_config();
        let output = generate_immutable_control(&r, &config);
        assert!(output.is_empty());
    }

    #[test]
    fn immutable_control_has_cm3_tag() {
        let r = test_resource("my_secret");
        let config = default_config();
        let output = generate_immutable_control(&r, &config);
        assert!(output.contains("CM-3"));
    }

    // ---- enum control ----

    #[test]
    fn enum_control_format() {
        let mut r = test_resource("my_secret");
        r.attributes.push(
            TestAttributeBuilder::new("status", IacType::String)
                .enum_values(vec!["active".into(), "inactive".into()])
                .build(),
        );
        let config = default_config();
        let output = generate_enum_control(&r, &config);
        assert!(output.contains("control 'my_secret-enum-validation'"));
        assert!(output.contains("should be_in ['active', 'inactive']"));
    }

    #[test]
    fn enum_control_impact() {
        let mut r = test_resource("my_secret");
        r.attributes.push(
            TestAttributeBuilder::new("status", IacType::String)
                .enum_values(vec!["a".into()])
                .build(),
        );
        let config = default_config();
        let output = generate_enum_control(&r, &config);
        assert!(output.contains("impact 0.5"));
    }

    #[test]
    fn enum_control_empty_when_no_enums() {
        let r = test_resource("my_secret");
        let config = default_config();
        let output = generate_enum_control(&r, &config);
        assert!(output.is_empty());
    }

    // ---- default control ----

    #[test]
    fn default_control_string_value() {
        let mut r = test_resource("my_secret");
        r.attributes.push(
            TestAttributeBuilder::new("format", IacType::String)
                .default_value(serde_json::json!("json"))
                .build(),
        );
        let config = default_config();
        let output = generate_default_control(&r, &config);
        assert!(output.contains("control 'my_secret-default-verification'"));
        assert!(output.contains("should eq 'json'"));
    }

    #[test]
    fn default_control_boolean_value() {
        let mut r = test_resource("my_secret");
        r.attributes.push(
            TestAttributeBuilder::new("enabled", IacType::Boolean)
                .default_value(serde_json::json!(true))
                .build(),
        );
        let config = default_config();
        let output = generate_default_control(&r, &config);
        assert!(output.contains("should eq true"));
    }

    #[test]
    fn default_control_number_value() {
        let mut r = test_resource("my_secret");
        r.attributes.push(
            TestAttributeBuilder::new("ttl", IacType::Integer)
                .default_value(serde_json::json!(3600))
                .build(),
        );
        let config = default_config();
        let output = generate_default_control(&r, &config);
        assert!(output.contains("should eq 3600"));
    }

    #[test]
    fn default_control_impact() {
        let mut r = test_resource("my_secret");
        r.attributes.push(
            TestAttributeBuilder::new("x", IacType::String)
                .default_value(serde_json::json!("y"))
                .build(),
        );
        let config = default_config();
        let output = generate_default_control(&r, &config);
        assert!(output.contains("impact 0.3"));
    }

    #[test]
    fn default_control_empty_when_no_defaults() {
        let r = test_resource("my_secret");
        let config = default_config();
        let output = generate_default_control(&r, &config);
        assert!(output.is_empty());
    }

    // ---- generate_resource_controls (combined) ----

    #[test]
    fn resource_controls_includes_header() {
        let r = test_resource("my_secret");
        let config = default_config();
        let output = generate_resource_controls(&r, &config);
        assert!(output.contains("# frozen_string_literal: true"));
        assert!(output.contains("DO NOT EDIT"));
    }

    #[test]
    fn resource_controls_includes_all_applicable() {
        let r = test_resource("my_secret");
        let config = default_config();
        let output = generate_resource_controls(&r, &config);
        assert!(output.contains("-existence'"));
        assert!(output.contains("-required-attrs'"));
        assert!(output.contains("-type-validation'"));
        assert!(output.contains("-sensitive-protection'"));
        assert!(output.contains("-immutable-enforcement'"));
        // test_resource has no enum or default attrs
        assert!(!output.contains("-enum-validation'"));
        assert!(!output.contains("-default-verification'"));
    }

    #[test]
    fn resource_controls_deterministic() {
        let r = test_resource("my_secret");
        let config = default_config();
        let output1 = generate_resource_controls(&r, &config);
        let output2 = generate_resource_controls(&r, &config);
        assert_eq!(output1, output2);
    }

    #[test]
    fn resource_controls_all_seven_types() {
        let mut r = test_resource("full_resource");
        r.attributes.push(
            TestAttributeBuilder::new("status", IacType::String)
                .enum_values(vec!["on".into(), "off".into()])
                .build(),
        );
        r.attributes.push(
            TestAttributeBuilder::new("ttl", IacType::Integer)
                .default_value(serde_json::json!(60))
                .build(),
        );
        let config = default_config();
        let output = generate_resource_controls(&r, &config);
        assert!(output.contains("-existence'"));
        assert!(output.contains("-required-attrs'"));
        assert!(output.contains("-type-validation'"));
        assert!(output.contains("-sensitive-protection'"));
        assert!(output.contains("-immutable-enforcement'"));
        assert!(output.contains("-enum-validation'"));
        assert!(output.contains("-default-verification'"));
    }
}
