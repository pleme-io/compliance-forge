//! Maps `IacType` variants to Ruby type assertion strings for InSpec/RSpec.

use iac_forge::ir::IacType;

/// Return the Ruby RSpec type assertion string for an `IacType`.
///
/// These are used inside `its('field') { should ... }` matchers.
#[must_use]
pub fn ruby_type_assertion(iac_type: &IacType) -> &'static str {
    match iac_type {
        IacType::String => "be_a(String)",
        IacType::Integer => "be_a(Integer)",
        IacType::Float => "be_a(Float)",
        IacType::Boolean => "satisfy { |v| [true, false].include?(v) }",
        IacType::List(_) => "be_an(Array)",
        IacType::Set(_) => "be_an(Array)",
        IacType::Map(_) => "be_a(Hash)",
        IacType::Object { .. } => "be_a(Hash)",
        IacType::Enum { .. } => "be_a(String)",
        IacType::Any => "not_be_nil",
    }
}

/// Return a human-readable Ruby type name (for control descriptions).
#[must_use]
pub fn ruby_type_name(iac_type: &IacType) -> &'static str {
    match iac_type {
        IacType::String => "String",
        IacType::Integer => "Integer",
        IacType::Float => "Float",
        IacType::Boolean => "Boolean",
        IacType::List(_) => "Array",
        IacType::Set(_) => "Array",
        IacType::Map(_) => "Hash",
        IacType::Object { .. } => "Hash",
        IacType::Enum { .. } => "String",
        IacType::Any => "Object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_assertion() {
        assert_eq!(ruby_type_assertion(&IacType::String), "be_a(String)");
    }

    #[test]
    fn integer_assertion() {
        assert_eq!(ruby_type_assertion(&IacType::Integer), "be_a(Integer)");
    }

    #[test]
    fn float_assertion() {
        assert_eq!(ruby_type_assertion(&IacType::Float), "be_a(Float)");
    }

    #[test]
    fn boolean_assertion() {
        assert_eq!(
            ruby_type_assertion(&IacType::Boolean),
            "satisfy { |v| [true, false].include?(v) }"
        );
    }

    #[test]
    fn list_assertion() {
        assert_eq!(
            ruby_type_assertion(&IacType::List(Box::new(IacType::String))),
            "be_an(Array)"
        );
    }

    #[test]
    fn set_assertion() {
        assert_eq!(
            ruby_type_assertion(&IacType::Set(Box::new(IacType::Integer))),
            "be_an(Array)"
        );
    }

    #[test]
    fn map_assertion() {
        assert_eq!(
            ruby_type_assertion(&IacType::Map(Box::new(IacType::String))),
            "be_a(Hash)"
        );
    }

    #[test]
    fn object_assertion() {
        assert_eq!(
            ruby_type_assertion(&IacType::Object {
                name: "Foo".to_string(),
                fields: vec![],
            }),
            "be_a(Hash)"
        );
    }

    #[test]
    fn enum_assertion() {
        assert_eq!(
            ruby_type_assertion(&IacType::Enum {
                values: vec!["a".into()],
                underlying: Box::new(IacType::String),
            }),
            "be_a(String)"
        );
    }

    #[test]
    fn any_assertion() {
        assert_eq!(ruby_type_assertion(&IacType::Any), "not_be_nil");
    }

    #[test]
    fn string_type_name() {
        assert_eq!(ruby_type_name(&IacType::String), "String");
    }

    #[test]
    fn boolean_type_name() {
        assert_eq!(ruby_type_name(&IacType::Boolean), "Boolean");
    }
}
