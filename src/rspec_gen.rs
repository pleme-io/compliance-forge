//! RSpec synthesis test generation from `IacResource`.
//!
//! Generates Ruby RSpec tests that verify synthesized resource data,
//! mirroring the 7 InSpec control types but operating on synthesized hashes.

use iac_forge::ir::{IacAttribute, IacResource, IacType};

use crate::config::ComplianceConfig;
use crate::type_map;

/// Generate the existence test block.
fn generate_existence_test(resource: &IacResource) -> String {
    format!(
        r#"  describe 'existence' do
    it 'resource {name} should be present in synthesized output' do
      expect(synthesized_resource).not_to be_nil
      expect(synthesized_resource).to be_a(Hash)
    end
  end
"#,
        name = resource.name,
    )
}

/// Generate the required attributes test block.
fn generate_required_attrs_test(resource: &IacResource) -> String {
    let required_attrs: Vec<&IacAttribute> =
        resource.attributes.iter().filter(|a| a.required).collect();

    if required_attrs.is_empty() {
        return String::new();
    }

    let mut checks = String::new();
    for attr in &required_attrs {
        checks.push_str(&format!(
            "    it 'has required attribute {}' do\n      expect(synthesized_resource).to have_key('{}')\n      expect(synthesized_resource['{}']).not_to be_nil\n    end\n",
            attr.canonical_name, attr.canonical_name, attr.canonical_name
        ));
    }

    format!(
        r#"  describe 'required attributes' do
{checks}  end
"#,
    )
}

/// Generate the type validation test block.
fn generate_type_validation_test(resource: &IacResource) -> String {
    let typed_attrs: Vec<&IacAttribute> = resource
        .attributes
        .iter()
        .filter(|a| !matches!(a.iac_type, IacType::Any))
        .collect();

    if typed_attrs.is_empty() {
        return String::new();
    }

    let mut checks = String::new();
    for attr in &typed_attrs {
        let assertion = type_map::ruby_type_assertion(&attr.iac_type);
        let type_name = type_map::ruby_type_name(&attr.iac_type);
        checks.push_str(&format!(
            "    it '{} should be {type_name}' do\n      expect(synthesized_resource['{}']).to {assertion}\n    end\n",
            attr.canonical_name, attr.canonical_name
        ));
    }

    format!(
        r#"  describe 'type validation' do
{checks}  end
"#,
    )
}

/// Generate the sensitive protection test block.
fn generate_sensitive_test(resource: &IacResource) -> String {
    let sensitive_attrs: Vec<&IacAttribute> =
        resource.attributes.iter().filter(|a| a.sensitive).collect();

    if sensitive_attrs.is_empty() {
        return String::new();
    }

    let mut checks = String::new();
    for attr in &sensitive_attrs {
        checks.push_str(&format!(
            "    it 'sensitive field {} should not appear in string output' do\n      expect(synthesized_resource.to_s).not_to include(synthesized_resource['{}'].to_s)\n    end\n",
            attr.canonical_name, attr.canonical_name
        ));
    }

    format!(
        r#"  describe 'sensitive protection' do
{checks}  end
"#,
    )
}

/// Generate the immutable enforcement test block.
fn generate_immutable_test(resource: &IacResource) -> String {
    let immutable_attrs: Vec<&IacAttribute> = resource
        .attributes
        .iter()
        .filter(|a| a.immutable)
        .collect();

    if immutable_attrs.is_empty() {
        return String::new();
    }

    let mut checks = String::new();
    for attr in &immutable_attrs {
        checks.push_str(&format!(
            "    it 'immutable field {} should match original value' do\n      expect(synthesized_resource['{}']).to eq(original_values['{}'])\n    end\n",
            attr.canonical_name, attr.canonical_name, attr.canonical_name
        ));
    }

    format!(
        r#"  describe 'immutable enforcement' do
{checks}  end
"#,
    )
}

/// Generate the enum validation test block.
fn generate_enum_test(resource: &IacResource) -> String {
    let enum_attrs: Vec<&IacAttribute> = resource
        .attributes
        .iter()
        .filter(|a| a.enum_values.is_some())
        .collect();

    if enum_attrs.is_empty() {
        return String::new();
    }

    let mut checks = String::new();
    for attr in &enum_attrs {
        if let Some(values) = &attr.enum_values {
            let items: Vec<String> = values.iter().map(|v| format!("'{v}'")).collect();
            let values_str = items.join(", ");
            checks.push_str(&format!(
                "    it '{} should be one of the allowed values' do\n      expect([{}]).to include(synthesized_resource['{}'])\n    end\n",
                attr.canonical_name, values_str, attr.canonical_name
            ));
        }
    }

    format!(
        r#"  describe 'enum validation' do
{checks}  end
"#,
    )
}

/// Generate the default verification test block.
fn generate_default_test(resource: &IacResource) -> String {
    let default_attrs: Vec<&IacAttribute> = resource
        .attributes
        .iter()
        .filter(|a| a.default_value.is_some())
        .collect();

    if default_attrs.is_empty() {
        return String::new();
    }

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
                "    it '{} should have default value {default_str}' do\n      expect(synthesized_resource['{}']).to eq({default_str})\n    end\n",
                attr.canonical_name, attr.canonical_name
            ));
        }
    }

    format!(
        r#"  describe 'default verification' do
{checks}  end
"#,
    )
}

/// Generate all RSpec tests for a resource as a single file.
#[must_use]
#[allow(clippy::needless_pass_by_value)]
pub fn generate_resource_tests(
    resource: &IacResource,
    _config: &ComplianceConfig,
) -> String {
    let mut output = String::from(
        "# frozen_string_literal: true\n# Code generated by compliance-forge. DO NOT EDIT.\n\n",
    );

    output.push_str(&format!(
        "RSpec.describe '{}' do\n",
        resource.name
    ));

    output.push_str("  let(:synthesized_resource) { subject }\n");
    output.push_str("  let(:original_values) { {} }\n\n");

    output.push_str(&generate_existence_test(resource));
    output.push('\n');

    let required = generate_required_attrs_test(resource);
    if !required.is_empty() {
        output.push_str(&required);
        output.push('\n');
    }

    let type_val = generate_type_validation_test(resource);
    if !type_val.is_empty() {
        output.push_str(&type_val);
        output.push('\n');
    }

    let sensitive = generate_sensitive_test(resource);
    if !sensitive.is_empty() {
        output.push_str(&sensitive);
        output.push('\n');
    }

    let immutable = generate_immutable_test(resource);
    if !immutable.is_empty() {
        output.push_str(&immutable);
        output.push('\n');
    }

    let enum_test = generate_enum_test(resource);
    if !enum_test.is_empty() {
        output.push_str(&enum_test);
        output.push('\n');
    }

    let default_test = generate_default_test(resource);
    if !default_test.is_empty() {
        output.push_str(&default_test);
        output.push('\n');
    }

    output.push_str("end\n");
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use iac_forge::testing::{TestAttributeBuilder, test_resource, test_resource_with_type};

    fn default_config() -> ComplianceConfig {
        ComplianceConfig::default()
    }

    // ---- existence test ----

    #[test]
    fn existence_test_format() {
        let r = test_resource("my_secret");
        let output = generate_existence_test(&r);
        assert!(output.contains("describe 'existence'"));
        assert!(output.contains("not_to be_nil"));
        assert!(output.contains("be_a(Hash)"));
    }

    // ---- required attrs test ----

    #[test]
    fn required_attrs_test_format() {
        let r = test_resource("my_secret");
        let output = generate_required_attrs_test(&r);
        assert!(output.contains("describe 'required attributes'"));
        assert!(output.contains("have_key('name')"));
        assert!(output.contains("have_key('value')"));
    }

    #[test]
    fn required_attrs_test_empty_when_none() {
        let mut r = test_resource("my_secret");
        for attr in &mut r.attributes {
            attr.required = false;
        }
        let output = generate_required_attrs_test(&r);
        assert!(output.is_empty());
    }

    // ---- type validation test ----

    #[test]
    fn type_validation_test_string() {
        let r = test_resource("my_secret");
        let output = generate_type_validation_test(&r);
        assert!(output.contains("describe 'type validation'"));
        assert!(output.contains("be_a(String)"));
    }

    #[test]
    fn type_validation_test_integer() {
        let r = test_resource_with_type("counter", "count", IacType::Integer);
        let output = generate_type_validation_test(&r);
        assert!(output.contains("be_a(Integer)"));
    }

    #[test]
    fn type_validation_test_boolean() {
        let r = test_resource_with_type("flag", "enabled", IacType::Boolean);
        let output = generate_type_validation_test(&r);
        assert!(output.contains("satisfy { |v| [true, false].include?(v) }"));
    }

    #[test]
    fn type_validation_test_list() {
        let r = test_resource_with_type(
            "tagged",
            "tags",
            IacType::List(Box::new(IacType::String)),
        );
        let output = generate_type_validation_test(&r);
        assert!(output.contains("be_an(Array)"));
    }

    #[test]
    fn type_validation_test_empty_for_any_only() {
        let r = test_resource_with_type("dynamic", "data", IacType::Any);
        let output = generate_type_validation_test(&r);
        assert!(output.is_empty());
    }

    // ---- sensitive test ----

    #[test]
    fn sensitive_test_format() {
        let r = test_resource("my_secret");
        let output = generate_sensitive_test(&r);
        assert!(output.contains("describe 'sensitive protection'"));
        assert!(output.contains("not_to include"));
    }

    #[test]
    fn sensitive_test_empty_when_none() {
        let r = test_resource_with_type("safe", "name", IacType::String);
        let output = generate_sensitive_test(&r);
        assert!(output.is_empty());
    }

    // ---- immutable test ----

    #[test]
    fn immutable_test_format() {
        let r = test_resource("my_secret");
        let output = generate_immutable_test(&r);
        assert!(output.contains("describe 'immutable enforcement'"));
        assert!(output.contains("eq(original_values['name'])"));
    }

    #[test]
    fn immutable_test_empty_when_none() {
        let r = test_resource_with_type("mutable", "data", IacType::String);
        let output = generate_immutable_test(&r);
        assert!(output.is_empty());
    }

    // ---- enum test ----

    #[test]
    fn enum_test_format() {
        let mut r = test_resource("my_secret");
        r.attributes.push(
            TestAttributeBuilder::new("status", IacType::String)
                .enum_values(vec!["active".into(), "inactive".into()])
                .build(),
        );
        let output = generate_enum_test(&r);
        assert!(output.contains("describe 'enum validation'"));
        assert!(output.contains("'active', 'inactive'"));
    }

    #[test]
    fn enum_test_empty_when_none() {
        let r = test_resource("my_secret");
        let output = generate_enum_test(&r);
        assert!(output.is_empty());
    }

    // ---- default test ----

    #[test]
    fn default_test_string_value() {
        let mut r = test_resource("my_secret");
        r.attributes.push(
            TestAttributeBuilder::new("format", IacType::String)
                .default_value(serde_json::json!("json"))
                .build(),
        );
        let output = generate_default_test(&r);
        assert!(output.contains("describe 'default verification'"));
        assert!(output.contains("eq('json')"));
    }

    #[test]
    fn default_test_boolean_value() {
        let mut r = test_resource("my_secret");
        r.attributes.push(
            TestAttributeBuilder::new("enabled", IacType::Boolean)
                .default_value(serde_json::json!(false))
                .build(),
        );
        let output = generate_default_test(&r);
        assert!(output.contains("eq(false)"));
    }

    #[test]
    fn default_test_empty_when_none() {
        let r = test_resource("my_secret");
        let output = generate_default_test(&r);
        assert!(output.is_empty());
    }

    // ---- generate_resource_tests (combined) ----

    #[test]
    fn resource_tests_includes_header() {
        let r = test_resource("my_secret");
        let config = default_config();
        let output = generate_resource_tests(&r, &config);
        assert!(output.contains("# frozen_string_literal: true"));
        assert!(output.contains("DO NOT EDIT"));
    }

    #[test]
    fn resource_tests_has_describe_block() {
        let r = test_resource("my_secret");
        let config = default_config();
        let output = generate_resource_tests(&r, &config);
        assert!(output.contains("RSpec.describe 'my_secret'"));
        assert!(output.contains("end\n"));
    }

    #[test]
    fn resource_tests_includes_let_blocks() {
        let r = test_resource("my_secret");
        let config = default_config();
        let output = generate_resource_tests(&r, &config);
        assert!(output.contains("let(:synthesized_resource)"));
        assert!(output.contains("let(:original_values)"));
    }

    #[test]
    fn resource_tests_includes_all_applicable() {
        let r = test_resource("my_secret");
        let config = default_config();
        let output = generate_resource_tests(&r, &config);
        assert!(output.contains("existence"));
        assert!(output.contains("required attributes"));
        assert!(output.contains("type validation"));
        assert!(output.contains("sensitive protection"));
        assert!(output.contains("immutable enforcement"));
    }

    #[test]
    fn resource_tests_deterministic() {
        let r = test_resource("my_secret");
        let config = default_config();
        let output1 = generate_resource_tests(&r, &config);
        let output2 = generate_resource_tests(&r, &config);
        assert_eq!(output1, output2);
    }

    #[test]
    fn resource_tests_all_seven_types() {
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
        let output = generate_resource_tests(&r, &config);
        assert!(output.contains("existence"));
        assert!(output.contains("required attributes"));
        assert!(output.contains("type validation"));
        assert!(output.contains("sensitive protection"));
        assert!(output.contains("immutable enforcement"));
        assert!(output.contains("enum validation"));
        assert!(output.contains("default verification"));
    }
}
