use super::{IAMStatement, IAMVersion};
use serde::{Deserialize, Serialize};
use serde_with::OneOrMany;
use serde_with::formats::PreferOne;
use serde_with::serde_as;

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
    pub statement: Vec<IAMStatement>,
}

impl IAMPolicy {
    /// Creates a new IAM policy with the default version
    pub fn new() -> Self {
        Self {
            version: IAMVersion::default(),
            id: None,
            statement: Vec::new(),
        }
    }

    /// Creates a new IAM policy with a specific version
    pub fn with_version(version: IAMVersion) -> Self {
        Self {
            version,
            id: None,
            statement: Vec::new(),
        }
    }

    /// Adds a statement to the policy
    pub fn add_statement(mut self, statement: IAMStatement) -> Self {
        self.statement.push(statement);
        self
    }

    /// Sets the policy ID
    pub fn with_id<S: Into<String>>(mut self, id: S) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Parses an IAM policy from a JSON string
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Serializes the IAM policy to a JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

impl Default for IAMPolicy {
    fn default() -> Self {
        Self::new()
    }
}
