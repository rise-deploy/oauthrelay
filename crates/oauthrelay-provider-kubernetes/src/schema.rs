//! Structural schemas retain the validation of Serde object alternatives.

use schemars::{generate::SchemaSettings, JsonSchema, Schema};
use serde_json::{json, Map, Value};

pub(crate) fn structural<T: JsonSchema>() -> Schema {
    let mut settings = SchemaSettings::openapi3();
    settings.inline_subschemas = true;
    let mut value = settings
        .into_generator()
        .into_root_schema_for::<T>()
        .to_value();
    adapt(&mut value);
    value.as_object_mut().unwrap().remove("$schema");
    Schema::try_from(value).expect("generated schema is an object")
}

/// Hoists object properties out of schemars unions to satisfy Kubernetes structural
/// schema rules while preserving each alternative's validation constraints. The
/// `allOf` wrappers keep kube's schema rewriter from hoisting those constraints too.
fn adapt(value: &mut Value) {
    match value {
        Value::Array(values) => {
            for value in values {
                adapt(value);
            }
        }
        Value::Object(object) => {
            for value in object.values_mut() {
                adapt(value);
            }
            for union in ["oneOf", "anyOf"] {
                let Some(Value::Array(branches)) = object.remove(union) else {
                    continue;
                };
                // OpenAPI represents nullable scalar alternatives without object properties.
                if !branches.iter().any(|b| b.get("properties").is_some()) {
                    object.insert(union.into(), Value::Array(branches));
                    continue;
                }
                let mut properties = object
                    .get("properties")
                    .and_then(Value::as_object)
                    .cloned()
                    .unwrap_or_default();
                for branch in &branches {
                    if let Some(fields) = branch.get("properties").and_then(Value::as_object) {
                        for (name, schema) in fields {
                            match properties.get_mut(name) {
                                None => {
                                    properties.insert(name.clone(), schema.clone());
                                }
                                Some(existing) => merge_property(existing, schema),
                            }
                        }
                    }
                }
                let names: Vec<_> = properties.keys().cloned().collect();
                let validations: Vec<_> = branches
                    .into_iter()
                    .map(|mut branch| {
                        if branch.get("additionalProperties") == Some(&Value::Bool(false)) {
                            let fields = branch
                                .get("properties")
                                .and_then(Value::as_object)
                                .cloned()
                                .unwrap_or_default();
                            let forbidden: Vec<_> = names
                                .iter()
                                .filter(|name| !fields.contains_key(*name))
                                .map(|name| json!({"not":{"required":[name]}}))
                                .collect();
                            if !forbidden.is_empty() {
                                branch
                                    .as_object_mut()
                                    .unwrap()
                                    .entry("allOf")
                                    .or_insert_with(|| json!([]))
                                    .as_array_mut()
                                    .unwrap()
                                    .extend(forbidden);
                            }
                        }
                        validation_only(&mut branch);
                        branch
                    })
                    .collect();
                // An allOf wrapper keeps branch constraints below the structural fields;
                // kube's union rewriter only hoists direct branch properties.
                let rules: Vec<_> = validations
                    .into_iter()
                    .map(|v| json!({"allOf":[v]}))
                    .collect();
                object.insert("type".into(), json!("object"));
                object.insert("properties".into(), Value::Object(properties));
                object.insert(union.into(), Value::Array(rules));
            }
        }
        _ => {}
    }
}

fn merge_property(existing: &mut Value, other: &Value) {
    if existing == other {
        return;
    }
    let a = existing.as_object_mut().expect("property schema");
    let b = other.as_object().expect("property schema");
    match (a.get("type"), b.get("type")) {
        (None, Some(kind)) => {
            a.insert("type".into(), kind.clone());
        }
        (Some(left), Some(right)) => assert_eq!(left, right, "union property types must agree"),
        _ => {}
    }
    // Structural properties describe the union; each branch retains its constraints.
    for key in [
        "enum",
        "const",
        "allOf",
        "not",
        "minLength",
        "maxLength",
        "pattern",
        "required",
    ] {
        if a.get(key) != b.get(key) {
            a.remove(key);
        }
    }
    if let Some(fields) = b.get("properties").and_then(Value::as_object) {
        let target = a
            .entry("properties")
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .unwrap();
        for (name, field) in fields {
            if let Some(existing) = target.get_mut(name) {
                merge_property(existing, field);
            } else {
                target.insert(name.clone(), field.clone());
            }
        }
    }
}

/// Validation branches may refer to structural fields but cannot declare their types.
fn validation_only(value: &mut Value) {
    if let Some(object) = value.as_object_mut() {
        for key in [
            "type",
            "title",
            "description",
            "default",
            "nullable",
            "additionalProperties",
            "$schema",
        ] {
            object.remove(key);
        }
        for key in ["properties", "$defs"] {
            if let Some(fields) = object.get_mut(key).and_then(Value::as_object_mut) {
                for field in fields.values_mut() {
                    validation_only(field);
                }
            }
        }
        for key in ["items", "not"] {
            if let Some(schema) = object.get_mut(key) {
                validation_only(schema);
            }
        }
        for key in ["allOf", "oneOf", "anyOf"] {
            if let Some(schemas) = object.get_mut(key).and_then(Value::as_array_mut) {
                for schema in schemas {
                    validation_only(schema);
                }
            }
        }
    }
}
