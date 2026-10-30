use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Claim names and matchers that must all pass within one policy section.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(transparent)]
#[schemars(transform = non_empty_claim_set)]
pub struct IdTokenClaimSet(pub BTreeMap<String, IdTokenClaimMatcher>);

/// Admission rules evaluated against a verified upstream ID token.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[schemars(transform = require_policy_section)]
pub struct IdTokenPolicy {
    /// Every matcher must pass when this section is present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1))]
    pub required: Option<IdTokenClaimSet>,
    /// At least one branch must pass; matchers within each branch are ANDed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1))]
    pub any_of: Option<Vec<IdTokenClaimSet>>,
}

/// Exactly one typed comparison of a top-level ID-token claim.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(untagged, deny_unknown_fields)]
pub enum IdTokenClaimMatcher {
    /// Case-sensitive equality with a string claim.
    StringEquals {
        #[serde(rename = "stringEquals")]
        value: String,
    },
    /// Case-sensitive membership in a non-empty list of strings.
    StringIn {
        #[serde(rename = "stringIn")]
        #[schemars(length(min = 1))]
        values: Vec<String>,
    },
    /// Full-string, case-sensitive glob: `*` matches any sequence; `?` matches one character.
    StringLike {
        #[serde(rename = "stringLike")]
        pattern: String,
    },
    /// Equality with a JSON boolean, without string coercion.
    BooleanEquals {
        #[serde(rename = "booleanEquals")]
        value: bool,
    },
    /// The claim is an array of strings and at least one listed value is an element
    /// (case-sensitive).
    ArrayContainsAny {
        #[serde(rename = "arrayContainsAny")]
        #[schemars(length(min = 1))]
        values: Vec<String>,
    },
    /// The claim is an array of strings and every listed value is an element
    /// (case-sensitive).
    ArrayContainsAll {
        #[serde(rename = "arrayContainsAll")]
        #[schemars(length(min = 1))]
        values: Vec<String>,
    },
    /// The claim is an array of strings and at least one element matches the `stringLike` glob.
    ArrayLikeAny {
        #[serde(rename = "arrayLikeAny")]
        pattern: String,
    },
}

impl IdTokenPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if self.required.is_none() && self.any_of.is_none() {
            return Err("idTokenPolicy must contain required or anyOf".into());
        }
        if let Some(required) = &self.required {
            validate_set(required)?;
        }
        if let Some(branches) = &self.any_of {
            if branches.is_empty() {
                return Err("idTokenPolicy.anyOf must not be empty".into());
            }
            for branch in branches {
                validate_set(branch)?;
            }
        }
        Ok(())
    }

    pub(crate) fn evaluate(&self, claims: &Value, relay: &str, upstream: &str) -> bool {
        let required = self
            .required
            .as_ref()
            .is_none_or(|rules| evaluate_set(rules, claims, relay, upstream, "required", None));
        let any_of = self.any_of.as_ref().is_none_or(|branches| {
            let mut accepted = false;
            for (index, rules) in branches.iter().enumerate() {
                let matched = evaluate_set(rules, claims, relay, upstream, "anyOf", Some(index));
                tracing::debug!(
                    target: "oauthrelay::id_token_policy",
                    relay, upstream, branch = index, matched,
                    "ID-token policy branch evaluated"
                );
                accepted |= matched;
            }
            accepted
        });
        required && any_of
    }
}

fn validate_set(rules: &IdTokenClaimSet) -> Result<(), String> {
    if rules.0.is_empty() {
        return Err("idTokenPolicy claim sets must not be empty".into());
    }
    for (claim, matcher) in &rules.0 {
        if claim.is_empty() {
            return Err("idTokenPolicy must not contain an empty claim name".into());
        }
        if let Some(values) = matcher.value_list() {
            if values.is_empty() {
                return Err(format!(
                    "idTokenPolicy.{} must not be empty",
                    matcher.operator()
                ));
            }
        }
    }
    Ok(())
}

fn evaluate_set(
    rules: &IdTokenClaimSet,
    claims: &Value,
    relay: &str,
    upstream: &str,
    section: &str,
    branch: Option<usize>,
) -> bool {
    let mut accepted = true;
    // Evaluate every rule so debug output describes all predicates, including after a mismatch.
    for (claim, matcher) in &rules.0 {
        let (matched, reason) = matcher.evaluate(claims.get(claim));
        tracing::debug!(
            target: "oauthrelay::id_token_policy",
            relay, upstream, section, branch, claim,
            operator = matcher.operator(), matched, reason,
            "ID-token policy matcher evaluated"
        );
        accepted &= matched;
    }
    accepted
}

impl IdTokenClaimMatcher {
    fn operator(&self) -> &'static str {
        match self {
            Self::StringEquals { .. } => "stringEquals",
            Self::StringIn { .. } => "stringIn",
            Self::StringLike { .. } => "stringLike",
            Self::BooleanEquals { .. } => "booleanEquals",
            Self::ArrayContainsAny { .. } => "arrayContainsAny",
            Self::ArrayContainsAll { .. } => "arrayContainsAll",
            Self::ArrayLikeAny { .. } => "arrayLikeAny",
        }
    }

    /// The configured list of a list-valued operator.
    fn value_list(&self) -> Option<&[String]> {
        match self {
            Self::StringIn { values }
            | Self::ArrayContainsAny { values }
            | Self::ArrayContainsAll { values } => Some(values),
            _ => None,
        }
    }

    fn evaluate(&self, actual: Option<&Value>) -> (bool, &'static str) {
        let Some(actual) = actual else {
            return (false, "missing_claim");
        };
        let matched = match self {
            Self::BooleanEquals { value } => match actual.as_bool() {
                Some(actual) => actual == *value,
                None => return (false, "wrong_type"),
            },
            Self::ArrayContainsAny { .. }
            | Self::ArrayContainsAll { .. }
            | Self::ArrayLikeAny { .. } => {
                let Some(elements) = string_array(actual) else {
                    return (false, "wrong_type");
                };
                // An empty array never satisfies an array operator.
                !elements.is_empty()
                    && match self {
                        Self::ArrayContainsAny { values } => elements
                            .iter()
                            .any(|element| values.iter().any(|value| value == element)),
                        Self::ArrayContainsAll { values } => values
                            .iter()
                            .all(|value| elements.iter().any(|element| element == value)),
                        Self::ArrayLikeAny { pattern } => {
                            elements.iter().any(|element| string_like(pattern, element))
                        }
                        _ => unreachable!(),
                    }
            }
            _ => {
                let Some(actual) = actual.as_str() else {
                    return (false, "wrong_type");
                };
                match self {
                    Self::StringEquals { value } => actual == value,
                    Self::StringIn { values } => values.iter().any(|value| value == actual),
                    Self::StringLike { pattern } => string_like(pattern, actual),
                    _ => unreachable!(),
                }
            }
        };
        (matched, if matched { "matched" } else { "value_mismatch" })
    }
}

/// The elements of a JSON array whose elements are all strings.
fn string_array(value: &Value) -> Option<Vec<&str>> {
    value
        .as_array()?
        .iter()
        .map(Value::as_str)
        .collect::<Option<Vec<_>>>()
}

fn string_like(pattern: &str, value: &str) -> bool {
    let pattern: Vec<_> = pattern.chars().collect();
    let value: Vec<_> = value.chars().collect();
    let (mut p, mut v, mut star, mut retry) = (0, 0, None, 0);
    while v < value.len() {
        if p < pattern.len() && (pattern[p] == '?' || (pattern[p] != '*' && pattern[p] == value[v]))
        {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            p += 1;
            retry = v;
        } else if let Some(index) = star {
            retry += 1;
            v = retry;
            p = index + 1;
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|character| *character == '*')
}

fn require_policy_section(schema: &mut schemars::Schema) {
    schema.insert(
        "anyOf".into(),
        serde_json::json!([
            {"required": ["required"], "properties": {"required": {"not": {"enum": [null]}}}},
            {"required": ["anyOf"], "properties": {"anyOf": {"not": {"enum": [null]}}}}
        ]),
    );
}

fn non_empty_claim_set(schema: &mut schemars::Schema) {
    schema.insert("minProperties".into(), serde_json::json!(1));
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn admission() -> IdTokenPolicy {
        serde_json::from_value(json!({
            "required": {"email_verified": {"booleanEquals": true}},
            "anyOf": [
                {"hd": {"stringEquals": "example.com"}},
                {"email": {"stringIn": ["guest@gmail.com", "second@gmail.com"]}}
            ]
        }))
        .unwrap()
    }

    #[test]
    fn admission_requires_verification_and_either_domain_or_exact_email() {
        let policy = admission();
        policy.validate().unwrap();
        for (claims, accepted) in [
            (json!({"email_verified": true, "hd": "example.com"}), true),
            (
                json!({"email_verified": true, "email": "guest@gmail.com"}),
                true,
            ),
            (
                json!({"email_verified": false, "email": "guest@gmail.com"}),
                false,
            ),
            (
                json!({"email_verified": "true", "email": "guest@gmail.com"}),
                false,
            ),
            (json!({"email": "guest@gmail.com"}), false),
            (
                json!({"email_verified": true, "email": "other@gmail.com"}),
                false,
            ),
            (
                json!({"email_verified": true, "email": "GUEST@gmail.com"}),
                false,
            ),
            (
                json!({"email_verified": true, "email": ["guest@gmail.com"]}),
                false,
            ),
            (json!({"email_verified": true, "hd": null}), false),
        ] {
            assert_eq!(
                policy.evaluate(&claims, "app", "google"),
                accepted,
                "{claims}"
            );
        }
    }

    #[test]
    fn empty_and_malformed_policies_are_configuration_errors() {
        for value in [
            json!({}),
            json!({"required": {}}),
            json!({"anyOf": []}),
            json!({"anyOf": [{}]}),
            json!({"required": null}),
            json!({"anyOf": null}),
            json!({"required": {"": {"stringEquals": "x"}}}),
            json!({"required": {"email": {"stringIn": []}}}),
            json!({"required": {"groups": {"arrayContainsAny": []}}}),
            json!({"required": {"groups": {"arrayContainsAll": []}}}),
        ] {
            let policy: IdTokenPolicy = serde_json::from_value(value).unwrap();
            assert!(policy.validate().is_err());
        }
        for value in [
            json!({"required": {"email": {"stringEquals": "x", "stringLike": "*"}}}),
            json!({"required": {"email": {"stringRegex": ".*"}}}),
            json!({"required": {"email": {"stringIn": ["x", true]}}}),
            json!({"required": {"groups": {"arrayContainsAny": ["x", 1]}}}),
            json!({"required": {"groups": {"arrayContainsAll": "x"}}}),
            json!({"required": {"groups": {"arrayLikeAny": ["x"]}}}),
            json!({"required": {"groups": {"arrayContainsAny": ["x"], "arrayContainsAll": ["x"]}}}),
            json!({"required": {"groups": {"arrayContainsAny": ["x"], "stringIn": ["x"]}}}),
            json!({"required": {"email_verified": {"booleanEquals": "true"}}}),
            json!({"required": {"email": {"stringEquals": "x"}}, "unknown": true}),
        ] {
            assert!(serde_json::from_value::<IdTokenPolicy>(value).is_err());
        }
    }

    fn matcher(value: Value) -> IdTokenClaimMatcher {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn array_operators_match_string_array_claims() {
        let any = matcher(json!({"arrayContainsAny": ["admins", "ops"]}));
        let all = matcher(json!({"arrayContainsAll": ["admins", "ops"]}));
        let like = matcher(json!({"arrayLikeAny": "team-*"}));
        for (claim, any_result, all_result, like_result) in [
            (json!(["admins"]), true, false, false),
            (json!(["ops", "other"]), true, false, false),
            (json!(["ops", "admins"]), true, true, false),
            (json!(["admins", "ops", "team-a"]), true, true, true),
            (json!(["Admins"]), false, false, false),
            (json!(["other"]), false, false, false),
            (json!(["team-a"]), false, false, true),
            (json!(["x-team-a"]), false, false, false),
            (json!([]), false, false, false),
        ] {
            for (matcher, expected) in
                [(&any, any_result), (&all, all_result), (&like, like_result)]
            {
                assert_eq!(
                    matcher.evaluate(Some(&claim)),
                    (
                        expected,
                        if expected {
                            "matched"
                        } else {
                            "value_mismatch"
                        }
                    ),
                    "{} {claim}",
                    matcher.operator()
                );
            }
        }
    }

    #[test]
    fn array_operators_fail_closed_on_wrong_types() {
        for matcher in [
            matcher(json!({"arrayContainsAny": ["admins"]})),
            matcher(json!({"arrayContainsAll": ["admins"]})),
            matcher(json!({"arrayLikeAny": "*"})),
        ] {
            assert_eq!(matcher.evaluate(None), (false, "missing_claim"));
            for claim in [
                json!("admins"),
                json!(true),
                json!(1),
                json!(null),
                json!({"admins": true}),
                json!(["admins", 1]),
                json!(["admins", null]),
                json!(["admins", ["nested"]]),
                json!([true]),
            ] {
                assert_eq!(
                    matcher.evaluate(Some(&claim)),
                    (false, "wrong_type"),
                    "{} {claim}",
                    matcher.operator()
                );
            }
        }
        for matcher in [
            matcher(json!({"stringEquals": "admins"})),
            matcher(json!({"stringIn": ["admins"]})),
            matcher(json!({"stringLike": "*"})),
        ] {
            assert_eq!(
                matcher.evaluate(Some(&json!(["admins"]))),
                (false, "wrong_type")
            );
        }
    }

    #[test]
    fn groups_policy_composes_with_required_and_any_of() {
        let policy: IdTokenPolicy = serde_json::from_value(json!({
            "required": {
                "email_verified": {"booleanEquals": true},
                "groups": {"arrayContainsAny": ["admins", "ops"]}
            },
            "anyOf": [
                {"groups": {"arrayContainsAll": ["eng", "oncall"]}},
                {"groups": {"arrayLikeAny": "platform-*"}}
            ]
        }))
        .unwrap();
        policy.validate().unwrap();
        for (claims, accepted) in [
            (
                json!({"email_verified": true, "groups": ["ops", "eng", "oncall"]}),
                true,
            ),
            (
                json!({"email_verified": true, "groups": ["admins", "platform-sre"]}),
                true,
            ),
            (
                json!({"email_verified": true, "groups": ["admins", "eng"]}),
                false,
            ),
            (
                json!({"email_verified": false, "groups": ["ops", "platform-sre"]}),
                false,
            ),
            (json!({"email_verified": true, "groups": []}), false),
            (json!({"email_verified": true}), false),
            (json!({"email_verified": true, "groups": "ops"}), false),
        ] {
            assert_eq!(policy.evaluate(&claims, "app", "idp"), accepted, "{claims}");
        }
    }

    #[test]
    fn array_operators_round_trip_and_appear_in_the_schema() {
        let value = json!({
            "required": {
                "a": {"arrayContainsAny": ["x", "y"]},
                "b": {"arrayContainsAll": ["x"]},
                "c": {"arrayLikeAny": "team-*"}
            }
        });
        let policy: IdTokenPolicy = serde_json::from_value(value.clone()).unwrap();
        policy.validate().unwrap();
        assert_eq!(serde_json::to_value(&policy).unwrap(), value);
        let schema = serde_json::to_string(&schemars::schema_for!(IdTokenPolicy)).unwrap();
        for operator in ["arrayContainsAny", "arrayContainsAll", "arrayLikeAny"] {
            assert!(schema.contains(operator), "{operator}");
        }
    }

    #[test]
    fn null_optional_sections_are_omitted() {
        let policy: IdTokenPolicy = serde_json::from_value(json!({
            "required": null, "anyOf": [{"email": {"stringEquals": "guest@gmail.com"}}]
        }))
        .unwrap();
        policy.validate().unwrap();
        assert!(policy.evaluate(&json!({"email": "guest@gmail.com"}), "app", "google"));
    }

    #[test]
    fn glob_is_anchored_case_sensitive_and_unicode_aware() {
        for (pattern, value, matched) in [
            ("*@example.com", "a@example.com", true),
            ("*@example.com", "a@example.com.evil", false),
            ("*@example.com", "a@EXAMPLE.com", false),
            ("a?c", "aéc", true),
            ("a?c", "a👋c", true),
            ("a?c", "ac", false),
            ("a?c", "abcc", false),
            ("*a*b", "aaaxxb", true),
            ("*a*b", "aaaxxbc", false),
            ("a**?c", "abc", true),
            ("*", "", true),
            ("", "", true),
            ("", "a", false),
            ("?", "", false),
            ("[ab]", "a", false),
            ("[ab]", "[ab]", true),
            (r"a\*", r"a\b", true),
            ("*", "a/b", true),
        ] {
            assert_eq!(
                string_like(pattern, value),
                matched,
                "{pattern:?} {value:?}"
            );
        }
        let matcher = IdTokenClaimMatcher::StringLike {
            pattern: "*".into(),
        };
        assert_eq!(matcher.evaluate(None), (false, "missing_claim"));
        assert_eq!(matcher.evaluate(Some(&json!(false))), (false, "wrong_type"));
    }

    #[test]
    fn glob_matches_the_wildcard_language_for_short_inputs() {
        fn words(alphabet: &[char], length: usize) -> Vec<String> {
            if length == 0 {
                return vec![String::new()];
            }
            let shorter = words(alphabet, length - 1);
            let mut result = shorter.clone();
            for prefix in shorter
                .iter()
                .filter(|word| word.chars().count() == length - 1)
            {
                result.extend(
                    alphabet
                        .iter()
                        .map(|character| format!("{prefix}{character}")),
                );
            }
            result
        }
        fn reference(pattern: &[char], value: &[char]) -> bool {
            match pattern.split_first() {
                None => value.is_empty(),
                Some(('*', rest)) => {
                    reference(rest, value) || (!value.is_empty() && reference(pattern, &value[1..]))
                }
                Some((character, rest)) => {
                    !value.is_empty()
                        && (*character == '?' || *character == value[0])
                        && reference(rest, &value[1..])
                }
            }
        }
        for pattern in words(&['a', 'b', '*', '?'], 3) {
            for value in words(&['a', 'b', '*', '?', 'é'], 3) {
                assert_eq!(
                    string_like(&pattern, &value),
                    reference(
                        &pattern.chars().collect::<Vec<_>>(),
                        &value.chars().collect::<Vec<_>>()
                    ),
                    "{pattern:?} {value:?}"
                );
            }
        }
    }

    #[test]
    fn debug_logs_report_all_results_without_claim_values_or_patterns() {
        use std::{
            io::Write,
            sync::{Arc, Mutex},
        };
        #[derive(Clone)]
        struct Writer(Arc<Mutex<Vec<u8>>>);
        impl Write for Writer {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let writer = Writer(bytes.clone());
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .without_time()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        let policy: IdTokenPolicy = serde_json::from_value(json!({
            "required": {"email_verified": {"booleanEquals": true}},
            "anyOf": [
                {"email": {"stringLike": "private-*@example.com"}},
                {"email": {"stringEquals": "private-expected@example.com"}},
                {"missing": {"stringIn": ["private-list-entry"]}},
                {"groups": {"arrayContainsAny": ["private-group"]}},
                {"groups": {"arrayContainsAll": ["private-group"]}},
                {"groups": {"arrayLikeAny": "private-*"}}
            ]
        }))
        .unwrap();
        tracing::subscriber::with_default(subscriber, || {
            assert!(policy.evaluate(
                &json!({
                    "email_verified": true,
                    "email": "private-user@example.com",
                    "groups": ["private-group"]
                }),
                "test-app",
                "test-google"
            ));
        });
        let output = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
        for expected in [
            "test-app",
            "test-google",
            "stringLike",
            "stringEquals",
            "stringIn",
            "booleanEquals",
            "arrayContainsAny",
            "arrayContainsAll",
            "arrayLikeAny",
            "matched=true",
            "matched=false",
            "missing_claim",
            "value_mismatch",
            "branch=2",
            "branch=5",
        ] {
            assert!(output.contains(expected), "missing {expected}: {output}");
        }
        assert!(
            !output.contains("private-"),
            "raw values or configured predicates leaked: {output}"
        );
    }
}
