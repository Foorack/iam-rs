use super::IAMStatement;
use crate::{
    core::IAMVersion,
    validation::{Validate, ValidationContext, ValidationError, ValidationResult, helpers},
};
use serde::{Deserialize, Serialize};
use serde_with::OneOrMany;
use serde_with::formats::PreferOne;
use serde_with::serde_as;
use std::collections::HashSet;

/// JSON policy documents are made up of elements.
/// The elements are listed here in the general order you use them in a policy.
/// The order of the elements doesn't matter—for example, the Resource element can come before the Action element.
/// You're not required to specify any Condition elements in the policy.
/// To learn more about the general structure and purpose of a JSON policy document, see Overview of JSON policies.
///
/// Some JSON policy elements are mutually exclusive.
/// This means that you cannot create a policy that uses both.
/// For example, you cannot use both Action and NotAction in the same policy statement.
/// Other pairs that are mutually exclusive include Principal/NotPrincipal and Resource/NotResource.
///
/// The details of what goes into a policy vary for each service, depending on what actions the service makes available, what types of resources it contains, and so on.
/// When you're writing policies for a specific service, it's helpful to see examples of policies for that service.
///
/// When you create or edit a JSON policy, `iam-rw` can perform policy validation to help you create an effective policy.
///
/// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct IAMPolicy {
    /// The `Version` policy element specifies the language syntax rules that are to be used to process a policy.
    ///
    /// To use all of the available policy features, include the following Version element outside the Statement element in all policies.
    /// `Version` is a required element in all IAM policies and must always be set to at least `2012-10-17`.
    ///
    /// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_version.html
    #[serde(rename = "Version")]
    pub version: IAMVersion,

    /// The `Id` element specifies an optional identifier for the policy.
    ///
    /// The ID is used differently in different services.
    /// ID is allowed in resource-based policies, but not in identity-based policies.
    ///
    /// Recommendation is to use a UUID (GUID) for the value, or incorporate a UUID as part of the ID to ensure uniqueness.
    ///
    /// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_id.html
    #[serde(rename = "Id", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// The Statement element is the main element for a policy.
    ///
    /// The Statement element can contain a single statement or an array of individual statements.
    /// Each individual statement block must be enclosed in curly braces { }.
    /// For multiple statements, the array must be enclosed in square brackets [ ].
    ///
    /// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_statement.html
    #[serde(rename = "Statement")]
    #[serde_as(as = "OneOrMany<_, PreferOne>")]
    #[cfg_attr(
        feature = "utoipa",
        schema(value_type = OneOrManyEnum<IAMStatement>)
    )]
    pub statement: Vec<IAMStatement>,
}

#[cfg(feature = "utoipa")]
#[derive(utoipa::ToSchema)]
#[allow(dead_code)]
enum OneOrManyEnum<T> {
    One(T),
    Many(Vec<T>),
}

impl IAMPolicy {
    /// Creates a new IAM policy with the default version
    #[must_use]
    pub fn new() -> Self {
        Self {
            version: IAMVersion::default(),
            id: None,
            statement: Vec::new(),
        }
    }

    /// Creates a new IAM policy with a specific version
    #[must_use]
    pub fn with_version(version: IAMVersion) -> Self {
        Self {
            version,
            id: None,
            statement: Vec::new(),
        }
    }

    /// Adds a statement to the policy
    #[must_use]
    pub fn add_statement(mut self, statement: IAMStatement) -> Self {
        self.statement.push(statement);
        self
    }

    /// Sets the policy ID
    #[must_use]
    pub fn with_id<S: Into<String>>(mut self, id: S) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Parses an IAM policy from a JSON string
    ///
    /// # Errors
    ///
    /// Returns a JSON parsing error if the input string is not valid JSON
    /// or does not match the expected IAM policy structure.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Serializes the IAM policy to a JSON string
    ///
    /// # Errors
    ///
    /// Returns a JSON serialization error if the policy cannot be converted to JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

impl Default for IAMPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl Validate for IAMPolicy {
    fn validate(&self, context: &mut ValidationContext) -> ValidationResult {
        context.with_segment("Policy", |ctx| {
            let mut results = Vec::new();

            // Check that policy has at least one statement
            if self.statement.is_empty() {
                results.push(Err(ValidationError::MissingField {
                    field: "Statement".to_string(),
                    context: ctx.current_path(),
                }));
                return helpers::collect_errors(results);
            }

            // Validate each statement
            for (i, statement) in self.statement.iter().enumerate() {
                ctx.with_segment(&format!("Statement[{i}]"), |stmt_ctx| {
                    results.push(statement.validate(stmt_ctx));
                });
            }

            // Check for duplicate statement IDs
            let mut seen_sids = HashSet::new();
            for (i, statement) in self.statement.iter().enumerate() {
                if let Some(ref sid) = statement.sid {
                    if seen_sids.contains(sid) {
                        results.push(Err(ValidationError::LogicalError {
                            message: format!(
                                "Duplicate statement ID '{sid}' found at position {i}"
                            ),
                        }));
                    } else {
                        seen_sids.insert(sid.clone());
                    }
                }
            }

            // Validate that policy version is supported
            match self.version {
                IAMVersion::V20121017 => {
                    // Supported version
                }
                #[allow(deprecated)]
                IAMVersion::V20081017 => {
                    results.push(Err(ValidationError::InvalidValue {
                        field: "Version".to_string(),
                        value: format!("{:?}", self.version),
                        reason: "Only IAM version 2012-10-17 is supported".to_string(),
                    }));
                }
            }

            // Validate policy ID format if present
            if let Some(ref id) = self.id {
                if id.is_empty() {
                    results.push(Err(ValidationError::InvalidValue {
                        field: "Id".to_string(),
                        value: id.clone(),
                        reason: "Policy ID cannot be empty".to_string(),
                    }));
                }
            }

            helpers::collect_errors(results)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Action, Effect, IAMVersion, Resource};

    #[test]
    fn test_policy_validation() {
        // Valid policy with UUID-format ID
        let valid_policy = IAMPolicy::new()
            .with_id("550e8400-e29b-41d4-a716-446655440000")
            .add_statement(
                IAMStatement::new(Effect::Allow)
                    .with_sid("AllowS3Read")
                    .with_action(Action::Single("s3:GetObject".to_string()))
                    .with_resource(Resource::Single("arn:aws:s3:::bucket/*".to_string())),
            );
        assert!(valid_policy.is_valid());

        // Empty policy (no statements)
        let empty_policy = IAMPolicy::new();
        assert!(!empty_policy.is_valid());

        // Policy with duplicate statement IDs and valid UUID
        let duplicate_sid_policy = IAMPolicy::new()
            .with_id("550e8400-e29b-41d4-a716-446655440001")
            .add_statement(
                IAMStatement::new(Effect::Allow)
                    .with_sid("DuplicateId")
                    .with_action(Action::Single("s3:GetObject".to_string()))
                    .with_resource(Resource::Single("*".to_string())),
            )
            .add_statement(
                IAMStatement::new(Effect::Deny)
                    .with_sid("DuplicateId")
                    .with_action(Action::Single("s3:DeleteObject".to_string()))
                    .with_resource(Resource::Single("*".to_string())),
            );
        assert!(!duplicate_sid_policy.is_valid());
    }

    #[test]
    fn test_policy_id_validation() {
        // Empty ID
        let mut empty_id_policy = IAMPolicy::new();
        empty_id_policy.id = Some("".to_string());
        empty_id_policy.statement.push(
            IAMStatement::new(Effect::Allow)
                .with_action(Action::Single("s3:GetObject".to_string()))
                .with_resource(Resource::Single("*".to_string())),
        );
        assert!(!empty_id_policy.is_valid());

        // Valid short ID
        let short_id_policy = IAMPolicy::new().with_id("short").add_statement(
            IAMStatement::new(Effect::Allow)
                .with_action(Action::Single("s3:GetObject".to_string()))
                .with_resource(Resource::Single("*".to_string())),
        );
        assert!(short_id_policy.is_valid());
    }

    #[test]
    fn test_iam_policy_creation() {
        let policy = IAMPolicy::new().with_id("test-policy").add_statement(
            IAMStatement::new(Effect::Allow)
                .with_sid("AllowS3Access")
                .with_action(Action::Single("s3:GetObject".to_string()))
                .with_resource(Resource::Single("arn:aws:s3:::mybucket/*".to_string())),
        );

        assert_eq!(policy.version, IAMVersion::V20121017);
        assert_eq!(policy.id, Some("test-policy".to_string()));
        assert_eq!(policy.statement.len(), 1);
        assert_eq!(policy.statement[0].effect, Effect::Allow);
    }

    #[test]
    fn test_policy_serialization() {
        let policy = IAMPolicy::new().add_statement(
            IAMStatement::new(Effect::Allow)
                .with_action(Action::Single("s3:GetObject".to_string()))
                .with_resource(Resource::Single("*".to_string())),
        );

        let json = policy.to_json().unwrap();
        let parsed_policy = IAMPolicy::from_json(&json).unwrap();

        assert_eq!(policy, parsed_policy);
    }

    #[test]
    fn test_policy_roundtrip_from_files() {
        // List filenames in the tests/policies directory
        let policies_dir = "tests/policies";

        let mut policy_files = std::fs::read_dir(policies_dir)
            .unwrap_or_else(|e| {
                panic!(
                    "Failed to read policies directory '{}': {}",
                    policies_dir, e
                )
            })
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let path = entry.path();
                if path.extension()? == "json" {
                    Some(path)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        // Verify we actually found policy files to test
        assert!(
            !policy_files.is_empty(),
            "No policy JSON files found in {}/",
            policies_dir
        );

        // Sort files by name for consistent test order
        // All files are called 1.json, 2.json, ..., 10.json, etc.
        policy_files.sort_by_key(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.split(".").next().unwrap().parse::<u32>().unwrap())
                .map(|n| format!("{:010}", n))
        });

        println!(
            "Testing {} policy files from {}/",
            policy_files.len(),
            policies_dir
        );

        for (index, policy_file) in policy_files.iter().enumerate() {
            let filename = policy_file
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown");

            println!("Testing policy #{}: {} ... ", index + 1, filename);

            // Read the JSON file
            let json_content = std::fs::read_to_string(&policy_file).unwrap_or_else(|e| {
                panic!("Failed to read file '{}': {}", policy_file.display(), e)
            });

            // Parse the policy from JSON
            let original_policy = IAMPolicy::from_json(&json_content)
                .unwrap_or_else(|e| panic!("Failed to parse JSON policy: {:?}", e));

            // Validate the parsed policy
            assert!(
                original_policy.is_valid(),
                "Policy {} is invalid: {:?}",
                filename,
                original_policy.validate(&mut ValidationContext::new())
            );

            // Serialize the policy back to JSON
            let serialized_json = original_policy
                .to_json()
                .unwrap_or_else(|e| panic!("Failed to serialize policy to JSON: {:?}", e));

            // Compare the serialized JSON with the prettified original
            assert_eq!(
                serialized_json,
                json_content.trim_end_matches("\n"),
                "Serialized JSON does not match original prettified JSON for file '{}'",
                filename
            );
        }
    }
}
