use serde::Serialize;
use serde_json::Value;

use crate::state::State;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DetectorKind {
    /// A hand-maintained (resource_type, attribute_path) pair known,
    /// from the provider's own documented schema, to store real
    /// plaintext secret material in state.
    Known,
    /// The attribute name matched a generic secret-shaped keyword and
    /// didn't hit any of the known-safe exclusions.
    Heuristic,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub resource_type: String,
    pub resource_name: String,
    pub instance_index: usize,
    pub attribute_path: String,
    pub detector: DetectorKind,
    pub redacted_value: String,
}

/// Shows the first and last 4 characters with the middle blotted out —
/// enough to confirm a real value was found without ever putting the
/// actual secret in a report that itself might get pasted somewhere.
/// Anything 8 characters or shorter is fully masked, since 4-and-4 would
/// otherwise show the whole thing (or overlap).
pub fn redact(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let n = chars.len();
    if n == 0 {
        return String::new(); // nothing to redact, and no length to leak either
    }
    if n <= 8 {
        return "*".repeat(n.max(4));
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[n - 4..].iter().collect();
    format!("{head}{}{tail}", "*".repeat(n - 8))
}

/// (resource_type, attribute_path) pairs where the named attribute is
/// documented, by the provider's own schema, to hold real plaintext
/// secret material in state — not a reference or an identifier pointing
/// at a secret stored elsewhere, but the material itself. `data.*`
/// entries are prefix rules (see [`KnownRule`]) since a Kubernetes
/// Secret's `data` map has caller-defined keys.
enum KnownRule {
    Exact(&'static str, &'static str),
    Prefix(&'static str, &'static str),
}

const KNOWN_RULES: &[KnownRule] = &[
    KnownRule::Exact("aws_db_instance", "password"),
    KnownRule::Exact("aws_rds_cluster", "master_password"),
    KnownRule::Exact("aws_redshift_cluster", "master_password"),
    KnownRule::Exact("aws_elasticache_replication_group", "auth_token"),
    KnownRule::Exact("aws_elasticache_user", "passwords"),
    KnownRule::Exact("aws_iam_access_key", "secret"),
    KnownRule::Exact("aws_iam_access_key", "ses_smtp_password_v4"),
    KnownRule::Exact("aws_secretsmanager_secret_version", "secret_string"),
    KnownRule::Exact("aws_secretsmanager_secret_version", "secret_binary"),
    KnownRule::Exact("aws_ssm_parameter", "value"),
    KnownRule::Exact("random_password", "result"),
    KnownRule::Exact("random_password", "bcrypt_hash"),
    KnownRule::Exact("tls_private_key", "private_key_pem"),
    KnownRule::Exact("tls_private_key", "private_key_openssh"),
    KnownRule::Exact("tls_private_key", "private_key_pem_pkcs8"),
    KnownRule::Exact("azurerm_key_vault_secret", "value"),
    KnownRule::Exact("azurerm_mssql_server", "administrator_login_password"),
    KnownRule::Exact("azurerm_sql_server", "administrator_login_password"),
    KnownRule::Exact("google_sql_user", "password"),
    KnownRule::Exact("github_actions_secret", "plaintext_value"),
    KnownRule::Exact("rabbitmq_user", "password"),
    KnownRule::Exact("postgresql_role", "password"),
    KnownRule::Exact("mysql_user", "plaintext_password"),
    KnownRule::Prefix("kubernetes_secret", "data."),
    KnownRule::Prefix("kubernetes_secret_v1", "data."),
];

fn known_match(resource_type: &str, path: &str) -> bool {
    KNOWN_RULES.iter().any(|rule| match rule {
        KnownRule::Exact(t, p) => *t == resource_type && *p == path,
        KnownRule::Prefix(t, prefix) => *t == resource_type && path.starts_with(prefix),
    })
}

/// Substrings that make an attribute *name* look secret-shaped. Checked
/// against the final path segment only (e.g. `data.password` -> checks
/// `password`), case-insensitively.
const HEURISTIC_KEYWORDS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "private_key",
    "privatekey",
    "access_key",
    "accesskey",
    "api_key",
    "apikey",
    "credential",
];

/// Name suffixes that mean an attribute is a reference, a count, or
/// metadata *about* a secret rather than the secret itself — checked
/// before the keyword match so `secret_id`/`secret_arn`/`token_endpoint`
/// don't get flagged just because they contain a keyword substring.
const SAFE_NAME_SUFFIXES: &[&str] = &[
    "_id",
    "_arn",
    "_length",
    "_count",
    "_version",
    "_enabled",
    "_required",
    "_hash",
    "_endpoint",
    "_url",
    "_wo",
    "_wo_version",
];

/// Extracts the last path segment (after the final `.`, with any
/// trailing `[N]` array-index stripped) — the actual attribute/map-key
/// name a heuristic should judge, not the full dotted path.
fn leaf_name(path: &str) -> &str {
    let without_index = match path.rfind('[') {
        Some(i) if path.ends_with(']') => &path[..i],
        _ => path,
    };
    without_index.rsplit('.').next().unwrap_or(without_index)
}

fn looks_like_arn(value: &str) -> bool {
    value.starts_with("arn:aws:") || value.starts_with("arn:aws-")
}

fn heuristic_match(path: &str, value: &str) -> bool {
    let name = leaf_name(path).to_lowercase();
    if SAFE_NAME_SUFFIXES.iter().any(|suf| name.ends_with(suf)) {
        return false;
    }
    if looks_like_arn(value) {
        return false;
    }
    HEURISTIC_KEYWORDS.iter().any(|kw| name.contains(kw))
}

/// Walks a (possibly nested) attributes value depth-first, calling
/// `visit` on every scalar leaf with its dotted/indexed path
/// (`"data.password"`, `"tags[0].value"`).
fn walk(value: &Value, path: &str, visit: &mut impl FnMut(&str, &Value)) {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                let child_path = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                walk(v, &child_path, visit);
            }
        }
        Value::Array(items) => {
            for (i, v) in items.iter().enumerate() {
                let child_path = format!("{path}[{i}]");
                walk(v, &child_path, visit);
            }
        }
        scalar => visit(path, scalar),
    }
}

pub fn scan(state: &State) -> Vec<Finding> {
    let mut findings = Vec::new();

    for resource in &state.resources {
        for (instance_index, instance) in resource.instances.iter().enumerate() {
            walk(&instance.attributes, "", &mut |path, value| {
                let Value::String(s) = value else {
                    return;
                };
                if s.is_empty() {
                    return;
                }

                let detector = if known_match(&resource.resource_type, path) {
                    Some(DetectorKind::Known)
                } else if heuristic_match(path, s) {
                    Some(DetectorKind::Heuristic)
                } else {
                    None
                };

                if let Some(detector) = detector {
                    findings.push(Finding {
                        resource_type: resource.resource_type.clone(),
                        resource_name: resource.name.clone(),
                        instance_index,
                        attribute_path: path.to_string(),
                        detector,
                        redacted_value: redact(s),
                    });
                }
            });
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::parse_state;

    fn scan_str(content: &str) -> Vec<Finding> {
        scan(&parse_state(content).unwrap())
    }

    #[test]
    fn redact_shows_first_and_last_four_for_long_values() {
        assert_eq!(redact("Sup3rSecretDBPass!42"), "Sup3************s!42");
    }

    #[test]
    fn redact_fully_masks_short_values() {
        assert_eq!(redact("abc"), "****");
        assert_eq!(redact(""), "");
        assert!(redact("hunter2").chars().all(|c| c == '*'));
    }

    #[test]
    fn leaf_name_strips_array_index_and_takes_last_segment() {
        assert_eq!(leaf_name("password"), "password");
        assert_eq!(leaf_name("data.password"), "password");
        assert_eq!(leaf_name("tags[0].value"), "value");
        assert_eq!(leaf_name("secrets[2]"), "secrets");
    }

    #[test]
    fn known_aws_db_instance_password_is_flagged() {
        let content = r#"{"version":4,"resources":[{"mode":"managed","type":"aws_db_instance","name":"primary",
            "instances":[{"attributes":{"id":"db-1","username":"admin","password":"Sup3rSecretDBPass!42"}}]}]}"#;
        let findings = scan_str(content);
        let f = findings
            .iter()
            .find(|f| f.attribute_path == "password")
            .expect("expected a finding for password");
        assert_eq!(f.detector, DetectorKind::Known);
        assert!(!findings.iter().any(|f| f.attribute_path == "username"));
    }

    #[test]
    fn known_random_password_result_is_flagged() {
        let content = r#"{"version":4,"resources":[{"mode":"managed","type":"random_password","name":"app",
            "instances":[{"attributes":{"id":"none","length":24,"special":true,"result":"xK9$mP2vL7qR@nT4wZ8y"}}]}]}"#;
        let findings = scan_str(content);
        assert!(findings
            .iter()
            .any(|f| f.attribute_path == "result" && f.detector == DetectorKind::Known));
        assert!(!findings.iter().any(|f| f.attribute_path == "length"));
    }

    #[test]
    fn known_tls_private_key_pem_is_flagged_but_public_key_is_not() {
        let content = r#"{"version":4,"resources":[{"mode":"managed","type":"tls_private_key","name":"ca",
            "instances":[{"attributes":{"algorithm":"RSA","private_key_pem":"-----BEGIN RSA PRIVATE KEY-----\nMIIFAKE\n-----END RSA PRIVATE KEY-----\n","public_key_pem":"-----BEGIN PUBLIC KEY-----\nMIIFAKE\n-----END PUBLIC KEY-----\n"}}]}]}"#;
        let findings = scan_str(content);
        assert!(findings
            .iter()
            .any(|f| f.attribute_path == "private_key_pem"));
        assert!(!findings
            .iter()
            .any(|f| f.attribute_path == "public_key_pem"));
    }

    #[test]
    fn kubernetes_secret_data_map_flags_every_child_key() {
        let content = r#"{"version":4,"resources":[{"mode":"managed","type":"kubernetes_secret","name":"creds",
            "instances":[{"attributes":{"type":"Opaque","data":{"username":"svc-app","password":"hunter2-but-real"}}}]}]}"#;
        let findings = scan_str(content);
        assert!(findings.iter().any(|f| f.attribute_path == "data.username"));
        assert!(findings.iter().any(|f| f.attribute_path == "data.password"));
        assert!(findings.iter().all(|f| f.detector == DetectorKind::Known));
    }

    #[test]
    fn secretsmanager_secret_version_secret_string_is_flagged() {
        let content = r#"{"version":4,"resources":[{"mode":"managed","type":"aws_secretsmanager_secret_version","name":"example",
            "instances":[{"attributes":{"secret_id":"arn:aws:secretsmanager:us-east-1:123456789012:secret:example-AbCdEf","secret_string":"prod-api-key-9f8e7d6c5b"}}]}]}"#;
        let findings = scan_str(content);
        assert!(findings.iter().any(|f| f.attribute_path == "secret_string"));
        assert!(
            !findings.iter().any(|f| f.attribute_path == "secret_id"),
            "an ARN pointing at a secret is not the secret material itself"
        );
    }

    #[test]
    fn heuristic_catches_an_unlisted_resource_types_password_field() {
        // postgresql_role is in the known table, but a genuinely unknown
        // custom/community provider's "api_token" field is not — this
        // must still be caught by the generic keyword heuristic.
        let content = r#"{"version":4,"resources":[{"mode":"managed","type":"some_saas_provider_user","name":"svc",
            "instances":[{"attributes":{"id":"u-1","api_token":"tok_live_9f8e7d6c5b4a3c2d1e"}}]}]}"#;
        let findings = scan_str(content);
        let f = findings
            .iter()
            .find(|f| f.attribute_path == "api_token")
            .expect("expected a heuristic finding");
        assert_eq!(f.detector, DetectorKind::Heuristic);
    }

    #[test]
    fn manage_master_user_password_true_leaves_password_null_and_unflagged() {
        let content = r#"{"version":4,"resources":[{"mode":"managed","type":"aws_db_instance","name":"primary",
            "instances":[{"attributes":{"id":"db-1","username":"admin","password":null,"manage_master_user_password":true}}]}]}"#;
        let findings = scan_str(content);
        assert!(findings.is_empty());
    }

    #[test]
    fn write_only_attribute_is_never_flagged_even_with_a_secret_shaped_name() {
        // Terraform 1.11+ write-only arguments are never actually
        // persisted to state (always null in practice); this asserts the
        // exclusion holds even in the hypothetical case of a non-null
        // value under a *_wo name, since the exclusion is name-based.
        let content = r#"{"version":4,"resources":[{"mode":"managed","type":"some_provider_thing","name":"x",
            "instances":[{"attributes":{"password_wo":"should-not-be-flagged","password_wo_version":"1"}}]}]}"#;
        let findings = scan_str(content);
        assert!(findings.is_empty());
    }

    #[test]
    fn ordinary_non_secret_attributes_are_never_flagged() {
        let content = r#"{"version":4,"resources":[{"mode":"managed","type":"aws_instance","name":"web",
            "instances":[{"attributes":{"id":"i-0123456789abcdef0","ami":"ami-0abcdef1234567890",
            "instance_type":"t3.micro","tags":{"Name":"web-1","Environment":"prod"},
            "description":"rotate the database password every 90 days"}}]}]}"#;
        let findings = scan_str(content);
        assert!(
            findings.is_empty(),
            "value content mentioning \"password\" must not trigger a name-based heuristic: {findings:?}"
        );
    }

    #[test]
    fn random_id_hex_is_not_flagged() {
        let content = r#"{"version":4,"resources":[{"mode":"managed","type":"random_id","name":"suffix",
            "instances":[{"attributes":{"hex":"a1b2c3d4","byte_length":4}}]}]}"#;
        let findings = scan_str(content);
        assert!(findings.is_empty());
    }

    #[test]
    fn empty_string_secret_shaped_value_is_not_flagged() {
        let content = r#"{"version":4,"resources":[{"mode":"managed","type":"aws_db_instance","name":"primary",
            "instances":[{"attributes":{"password":""}}]}]}"#;
        let findings = scan_str(content);
        assert!(findings.is_empty());
    }

    #[test]
    fn no_resources_produces_no_findings() {
        let findings = scan_str(r#"{"version":4,"resources":[]}"#);
        assert!(findings.is_empty());
    }
}
