use serde::Deserialize;
use serde_json::Value;

/// The real shape of a Terraform state file since format version 4
/// (Terraform 0.12+): a top-level `resources` array, each with a `type`/
/// `name`/`instances`, and each instance's `attributes` as real nested
/// JSON (not the pre-0.12 dotted-key flatmap — see README). Fields this
/// crate doesn't care about (`serial`, `lineage`, `outputs`, `provider`,
/// `schema_version`, `dependencies`, ...) are simply never named, which
/// with `serde_json` means they're ignored rather than rejected.
#[derive(Debug, Deserialize)]
pub struct State {
    pub version: Option<u64>,
    pub terraform_version: Option<String>,
    #[serde(default)]
    pub resources: Vec<Resource>,
}

#[derive(Debug, Deserialize)]
pub struct Resource {
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(rename = "type")]
    pub resource_type: String,
    pub name: String,
    #[serde(default)]
    pub instances: Vec<Instance>,
}

#[derive(Debug, Deserialize)]
pub struct Instance {
    #[serde(default)]
    pub attributes: Value,
}

pub fn parse_state(content: &str) -> Result<State, String> {
    serde_json::from_str(content).map_err(|e| format!("not a valid Terraform state file: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_realistic_state_v4_document() {
        let content = r#"{
            "version": 4,
            "terraform_version": "1.9.5",
            "serial": 3,
            "lineage": "abc-123",
            "resources": [
                {
                    "mode": "managed",
                    "type": "aws_db_instance",
                    "name": "primary",
                    "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
                    "instances": [
                        {"schema_version": 2, "attributes": {"id": "db-1", "password": "hunter2hunter2"}}
                    ]
                }
            ]
        }"#;
        let state = parse_state(content).unwrap();
        assert_eq!(state.version, Some(4));
        assert_eq!(state.resources.len(), 1);
        assert_eq!(state.resources[0].resource_type, "aws_db_instance");
        assert_eq!(state.resources[0].instances.len(), 1);
        assert_eq!(
            state.resources[0].instances[0].attributes["password"],
            "hunter2hunter2"
        );
    }

    #[test]
    fn missing_resources_key_defaults_to_empty() {
        let content = r#"{"version": 4, "terraform_version": "1.9.5"}"#;
        let state = parse_state(content).unwrap();
        assert!(state.resources.is_empty());
    }

    #[test]
    fn malformed_json_is_a_clean_error() {
        assert!(parse_state("not json {{{").is_err());
    }

    #[test]
    fn resource_missing_required_type_field_is_a_clean_error() {
        let content = r#"{"version": 4, "resources": [{"name": "x", "instances": []}]}"#;
        assert!(parse_state(content).is_err());
    }
}
