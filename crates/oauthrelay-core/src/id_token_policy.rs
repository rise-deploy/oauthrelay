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
        if matches!(matcher, IdTokenClaimMatcher::StringIn { values } if values.is_empty()) {
            return Err("idTokenPolicy.stringIn must not be empty".into());
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
            _ => {
                let Some(actual) = actual.as_str() else {
                    return (false, "wrong_type");
                };
                match self {
                    Self::StringEquals { value } => actual == value,
                    Self::StringIn { values } => values.iter().any(|value| value == actual),
                    Self::StringLike { pattern } => string_like(pattern, actual),
                    Self::BooleanEquals { .. } => unreachable!(),
                }
            }
        };
        (matched, if matched { "matched" } else { "value_mismatch" })
    }
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
        ] {
            let policy: IdTokenPolicy = serde_json::from_value(value).unwrap();
            assert!(policy.validate().is_err());
        }
        for value in [
            json!({"required": {"email": {"stringEquals": "x", "stringLike": "*"}}}),
            json!({"required": {"email": {"stringRegex": ".*"}}}),
            json!({"required": {"email": {"stringIn": ["x", true]}}}),
            json!({"required": {"email_verified": {"booleanEquals": "true"}}}),
            json!({"required": {"email": {"stringEquals": "x"}}, "unknown": true}),
        ] {
            assert!(serde_json::from_value::<IdTokenPolicy>(value).is_err());
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
                {"missing": {"stringIn": ["private-list-entry"]}}
            ]
        }))
        .unwrap();
        tracing::subscriber::with_default(subscriber, || {
            assert!(policy.evaluate(
                &json!({"email_verified": true, "email": "private-user@example.com"}),
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
            "matched=true",
            "matched=false",
            "missing_claim",
            "value_mismatch",
            "branch=2",
        ] {
            assert!(output.contains(expected), "missing {expected}: {output}");
        }
        assert!(
            !output.contains("private-"),
            "raw values or configured predicates leaked: {output}"
        );
    }
}
