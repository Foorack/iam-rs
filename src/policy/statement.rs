use serde::{Deserialize, Serialize};

use super::ConditionBlock;
use crate::{
    core::{IAMAction, IAMEffect, IAMOperator, Principal, IAMResource},
    policy::condition::ConditionValue,
    validation::{Validate, ValidationContext, ValidationError, ValidationResult, helpers},
};

/// Represents a single statement in an IAM policy
///
/// <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_statement.html>
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct IAMStatement {
    /// Optional statement ID
    ///
    /// You can provide a `Sid` (statement ID) as an optional identifier for the policy statement.
    /// You can assign a `Sid` value to each statement in a statement array.
    /// You can use the `Sid` value as a description for the policy statement.
    ///
    /// In services that let you specify an ID element, such as AWS SQS and AWS SNS, the `Sid` value is just a sub-ID of the policy document ID.
    /// In IAM, the `Sid` value must be unique within a JSON policy.
    ///
    /// The Sid element supports ASCII uppercase letters (A-Z), lowercase letters (a-z), and numbers (0-9).
    ///
    /// <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_sid.html>
    #[serde(rename = "Sid", skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,

    /// The effect of the statement (Allow or Deny)
    ///
    /// The `Effect` element is required and specifies whether the statement results in an allow or an explicit deny.
    /// Valid values for Effect are **Allow** and **Deny**.
    /// The Effect value is case sensitive.
    ///
    /// By default, access to resources is denied.
    /// To allow access to a resource, you must set the Effect element to Allow.
    /// To override an allow (for example, to override an allow that is otherwise in force), you set the Effect element to Deny.
    ///
    /// <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_effect.html>
    #[serde(rename = "Effect")]
    pub effect: IAMEffect,

    /// Optional principal(s) - who the statement applies to
    ///
    /// Use the `Principal` element in a resource-based JSON policy to specify the principal that is allowed or denied access to a resource.
    ///
    /// You must use the `Principal` element in resource-based policies.
    /// You cannot use the `Principal` element in an identity-based policy.
    ///
    /// Identity-based policies are permissions policies that you attach to IAM identities (users, groups, or roles).
    /// In those cases, the principal is implicitly the identity where the policy is attached.
    ///
    /// <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html>
    #[serde(rename = "Principal", skip_serializing_if = "Option::is_none")]
    pub principal: Option<Principal>,

    /// Optional not principal(s) - who the statement does not apply to
    ///
    /// The `NotPrincipal` element uses "Effect":"Deny" to deny access to all principals except the principal specified in the `NotPrincipal` element.
    /// A principal can usually be a user, federated user, role, assumed role, account, service, or other principal type.
    ///
    /// `NotPrincipal` must be used with `"Effect":"Deny"`. Using it with `"Effect":"Allow"` is not supported.
    ///
    /// <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notprincipal.html>
    #[serde(rename = "NotPrincipal", skip_serializing_if = "Option::is_none")]
    pub not_principal: Option<Principal>,

    /// Optional action(s) - what actions are allowed/denied
    ///
    /// The `Action` element describes the specific action or actions that will be allowed or denied.
    /// Statements must include either an `Action` or `NotAction` element.
    /// Each service has its own set of actions that describe tasks that you can perform with that service.
    ///
    /// For example:
    /// * the list of actions for Amazon S3 can be found at Specifying Permissions in a Policy in the *Amazon Simple Storage Service User Guide*
    /// * the list of actions for Amazon EC2 can be found in the [Amazon EC2 API Reference](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/query-apis.html)
    /// * the list of actions for AWS Identity and Access Management can be found in the [IAM API Reference](https://docs.aws.amazon.com/IAM/latest/APIReference/API_Operations.html)
    ///
    /// To find the list of actions for other AWS services, consult the [API reference](http://aws.amazon.com/documentation) documentation for the service.
    /// For non-AWS services, consult the service documentation for the actions that are supported by that service.
    ///
    /// You specify a value using a service namespace as an action prefix (`iam`, `ec2`, `sqs`, `sns`, `s3`, etc.) followed by the name of the action to allow or deny.
    /// The name must match an action that is supported by the service.
    /// The prefix and the action name are case insensitive.
    /// For example, `iam:ListAccessKeys` is the same as `IAM:listaccesskeys`.
    ///
    /// The following examples show Action elements for different services:
    /// * `Action: "sqs:SendMessage"` - allows the `SendMessage` action on SQS.
    /// * `Action: "ec2:StartInstances"` - allows the `StartInstances` action on EC2.
    /// * `Action: "iam:ChangePassword"` - allows the `ChangePassword` action on IAM.
    /// * `Action: "s3:GetObject"` - allows the `GetObject` action on S3.
    ///
    /// You can specify multiple values for the Action element:
    /// * `Action: [ "sqs:SendMessage", "sqs:ReceiveMessage", "ec2:StartInstances", "iam:ChangePassword", "s3:GetObject" ]`
    ///
    /// You can use wildcards to match multiple actions:
    /// * `Action: "s3:*"` - allows all actions on S3.
    ///
    /// You can also use wildcards (`*` or `?`) as part of the action name. For example, the following Action element applies to all IAM actions that include the string `AccessKey`, including `CreateAccessKey`, `DeleteAccessKey`, `ListAccessKeys`, and `UpdateAccessKey`:
    ///
    /// `"Action": "iam:*AccessKey*"`
    ///
    /// Some services let you limit the actions that are available.
    /// For example, Amazon SQS lets you make available just a subset of all the possible Amazon SQS actions.
    /// In that case, the `*` wildcard doesn't allow complete control of the queue; it allows only the subset of actions that you've shared.
    ///
    /// <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html>
    #[serde(rename = "Action", skip_serializing_if = "Option::is_none")]
    pub action: Option<IAMAction>,

    /// Optional not action(s) - what actions are not covered
    ///
    /// `NotAction` is an advanced policy element that explicitly matches everything except the specified list of actions.
    /// Using `NotAction` can result in a shorter policy by listing only a few actions that should not match, rather than including a long list of actions that will match.
    ///
    /// Actions specified in `NotAction` are not impacted by the Allow or Deny effect in a policy statement.
    /// This, in turn, means that all of the applicable actions or services that are not listed are allowed if you use the Allow effect.
    /// In addition, such unlisted actions or services are denied if you use the Deny effect.
    ///
    /// When you use `NotAction` with the Resource element, you provide scope for the policy.
    /// This is how AWS determines which actions or services are applicable.
    ///
    /// For more information, see the following example policy.
    ///
    /// # `NotAction` with Allow
    ///
    /// You can use the `NotAction` element in a statement with `"Effect": "Allow"` to provide access to all of the actions in an AWS service, except for the actions specified in `NotAction`.
    /// You can use it with the Resource element to provide scope for the policy, limiting the allowed actions to the actions that can be performed on the specified resource.
    ///
    /// Example: Allow all S3 actions except deleting a bucket:
    /// ```json
    /// "Effect": "Allow",
    /// "NotAction": "s3:DeleteBucket",
    /// "Resource": "arn:aws:s3:::*"
    /// ```
    ///
    /// Example: Allow all actions except IAM:
    /// ```json
    /// "Effect": "Allow",
    /// "NotAction": "iam:*",
    /// "Resource": "*"
    /// ```
    ///
    /// Be careful using `NotAction` with `"Effect": "Allow"` as it could grant more permissions than intended.
    ///
    /// # `NotAction` with Deny
    ///
    /// You can use the `NotAction` element in a statement with `"Effect": "Deny"` to deny access to all of the listed resources except for the actions specified in `NotAction`.
    /// This combination does not allow the listed items, but instead explicitly denies the actions not listed.
    ///
    /// Example: Deny all actions except IAM actions if not using MFA:
    /// ```json
    /// {
    ///     "Sid": "DenyAllUsersNotUsingMFA",
    ///     "Effect": "Deny",
    ///     "NotAction": "iam:*",
    ///     "Resource": "*",
    ///     "Condition": {"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}}
    /// }
    /// ```
    ///
    /// <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html>
    #[serde(rename = "NotAction", skip_serializing_if = "Option::is_none")]
    pub not_action: Option<IAMAction>,

    /// Optional resource(s) - what resources the statement applies to
    ///
    /// The `Resource` element specifies the object(s) that the statement applies to.
    ///
    /// You must include either a `Resource` or a `NotResource` element in a statement.
    ///
    /// You specify a resource using an Amazon Resource Name (ARN). The ARN format depends on the AWS service and the specific resource.
    /// For more information about ARNs, see: <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-arns>
    ///
    /// Some AWS services do not support resource-level permissions. In those cases, use the wildcard character (`*`) in the Resource element.
    ///
    /// Examples:
    /// * Specific SQS queue:
    ///   `"Resource": "arn:aws:sqs:us-east-2:account-ID-without-hyphens:queue1"`
    /// * Specific IAM user (user name is case sensitive):
    ///   `"Resource": "arn:aws:iam::account-ID-without-hyphens:user/Bob"`
    ///
    /// # Using wildcards in resource ARNs
    ///
    /// You can use wildcard characters (`*` and `?`) within the individual segments of an ARN (the parts separated by colons) to represent:
    /// - Any combination of characters (`*`)
    /// - Any single character (`?`)
    ///
    /// You can use multiple `*` or `?` characters in each segment.
    /// If the `*` wildcard is the last character of a resource ARN segment, it can expand to match beyond the colon boundaries.
    /// It is recommended to use wildcards within ARN segments separated by a colon.
    ///
    /// **Note:** You can't use a wildcard in the service segment that identifies the AWS product.
    ///
    /// ## Examples
    ///
    /// All IAM users whose path is `/accounting`:
    /// ```text
    /// "Resource": "arn:aws:iam::account-ID-without-hyphens:user/accounting/*"
    /// ```
    ///
    /// All items within a specific Amazon S3 bucket:
    /// ```text
    /// "Resource": "arn:aws:s3:::amzn-s3-demo-bucket/*"
    /// ```
    ///
    /// Wildcards can match across slashes and other characters:
    /// ```text
    /// "Resource": "arn:aws:s3:::amzn-s3-demo-bucket/*/test/*"
    /// ```
    /// This matches:
    /// - amzn-s3-demo-bucket/1/test/object.jpg
    /// - amzn-s3-demo-bucket/1/2/test/object.jpg
    /// - amzn-s3-demo-bucket/1/2/test/3/object.jpg
    /// - amzn-s3-demo-bucket/1/2/3/test/4/object.jpg
    /// - amzn-s3-demo-bucket/1///test///object.jpg
    /// - amzn-s3-demo-bucket/1/test/.jpg
    /// - amzn-s3-demo-bucket//test/object.jpg
    /// - amzn-s3-demo-bucket/1/test/
    ///
    /// But does **not** match:
    /// - amzn-s3-demo-bucket/1-test/object.jpg
    /// - amzn-s3-demo-bucket/test/object.jpg
    /// - amzn-s3-demo-bucket/1/2/test.jpg
    ///
    /// ## Specifying multiple resources
    ///
    /// You can specify multiple resources in the `Resource` element by using an array of ARNs:
    /// ```json
    /// "Resource": [
    ///     "arn:aws:dynamodb:us-east-2:account-ID-without-hyphens:table/books_table",
    ///     "arn:aws:dynamodb:us-east-2:account-ID-without-hyphens:table/magazines_table"
    /// ]
    /// ```
    ///
    /// ## Using policy variables in resource ARNs
    ///
    /// You can use JSON policy variables in the part of the ARN that identifies the specific resource. For example:
    /// ```text
    /// "Resource": "arn:aws:dynamodb:us-east-2:account-id:table/${aws:username}"
    /// ```
    /// This allows access to a `DynamoDB` table that matches the current user's name.
    ///
    /// For more information about JSON policy variables, see [IAM policy elements: Variables and tags](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html).
    ///
    /// <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html>
    #[serde(rename = "Resource", skip_serializing_if = "Option::is_none")]
    pub resource: Option<IAMResource>,

    /// Optional not resource(s) - what resources are not covered
    ///
    /// `NotResource` is an advanced policy element that explicitly matches every resource except those specified.
    /// Using `NotResource` can result in a shorter policy by listing only a few resources that should not match, rather than including a long list of resources that will match.
    /// This is particularly useful for policies that apply within a single AWS service.
    ///
    /// <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notresource.html>
    #[serde(rename = "NotResource", skip_serializing_if = "Option::is_none")]
    pub not_resource: Option<IAMResource>,

    /// Optional conditions for the statement
    ///
    /// The `Condition` element (or Condition block) lets you specify conditions for when a policy is in effect. The Condition element is optional.
    ///
    /// In the Condition element, you build expressions in which you use condition operators (equal, less than, and others) to match the context keys and values in the policy against keys and values in the request context.
    /// To learn more about the request context, see [Components of a request](https://docs.aws.amazon.com/IAM/latest/UserGuide/intro-structure.html#intro-structure-request).
    ///
    /// ```json
    /// "Condition" : { "{condition-operator}" : { "{condition-key}" : "{condition-value}" }}
    /// ```
    ///
    /// The context key that you specify in a policy condition can be a global condition context key or a service-specific context key.
    /// * Global condition context keys have the aws: prefix.
    /// * Service-specific context keys have the service's prefix.
    ///
    ///   For example, Amazon EC2 lets you write a condition using the ec2:InstanceType context key, which is unique to that service.
    ///
    /// Context key names are not case-sensitive.
    /// For example, including the aws:SourceIP context key is equivalent to testing for `AWS:SourceIp`.
    /// Case-sensitivity of context key values depends on the condition operator that you use.
    /// For example, the following condition includes the `StringEquals` operator to make sure that only requests made by john match.
    /// Users named John are denied access.
    ///
    /// ```json
    /// "Condition" : { "StringEquals" : { "aws:username" : "john" }}
    /// ```
    /// The following condition uses the `StringEqualsIgnoreCase` operator to match users named john or John.
    /// ```json
    /// "Condition" : { "StringEqualsIgnoreCase" : { "aws:username" : "john" }}
    /// ```
    ///
    /// <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html>
    #[serde(rename = "Condition", skip_serializing_if = "Option::is_none")]
    pub condition: Option<ConditionBlock>,
}

impl IAMStatement {
    /// Creates a new IAM statement with the specified effect
    #[must_use]
    pub fn new(effect: IAMEffect) -> Self {
        Self {
            sid: None,
            effect,
            principal: None,
            not_principal: None,
            action: None,
            not_action: None,
            resource: None,
            not_resource: None,
            condition: None,
        }
    }

    /// Sets the statement ID
    #[must_use]
    pub fn with_sid<S: Into<String>>(mut self, sid: S) -> Self {
        self.sid = Some(sid.into());
        self
    }

    /// Sets the principal
    #[must_use]
    pub fn with_principal(mut self, principal: Principal) -> Self {
        self.principal = Some(principal);
        self
    }

    /// Sets the action
    #[must_use]
    pub fn with_action(mut self, action: IAMAction) -> Self {
        self.action = Some(action);
        self
    }

    /// Sets the resource
    #[must_use]
    pub fn with_resource(mut self, resource: IAMResource) -> Self {
        self.resource = Some(resource);
        self
    }

    /// Adds a condition to the statement
    #[must_use]
    pub fn with_condition(
        mut self,
        operator: IAMOperator,
        key: String,
        value: ConditionValue,
    ) -> Self {
        let condition_block = self.condition.get_or_insert_with(ConditionBlock::new);
        let condition = super::Condition::new(operator, key, value);
        condition_block.add_condition(condition);
        self
    }

    /// Adds a condition using the Condition struct
    #[must_use]
    pub fn with_condition_struct(mut self, condition: super::Condition) -> Self {
        let condition_block = self.condition.get_or_insert_with(ConditionBlock::new);
        condition_block.add_condition(condition);
        self
    }
}

impl Validate for IAMStatement {
    fn validate(&self, context: &mut ValidationContext) -> ValidationResult {
        context.with_segment("Statement", |ctx| {
            let mut results = Vec::new();

            // Check that either Action or NotAction is present
            match (&self.action, &self.not_action) {
                (None, None) => {
                    results.push(Err(ValidationError::MissingField {
                        field: "Action or NotAction".to_string(),
                        context: ctx.current_path(),
                    }));
                }
                (Some(_), Some(_)) => {
                    results.push(Err(ValidationError::LogicalError {
                        message: "Statement cannot have both Action and NotAction".to_string(),
                    }));
                }
                _ => {} // Valid: exactly one is present
            }

            // Check that either Resource or NotResource is present
            match (&self.resource, &self.not_resource) {
                (None, None) => {
                    results.push(Err(ValidationError::MissingField {
                        field: "Resource or NotResource".to_string(),
                        context: ctx.current_path(),
                    }));
                }
                (Some(_), Some(_)) => {
                    results.push(Err(ValidationError::LogicalError {
                        message: "Statement cannot have both Resource and NotResource".to_string(),
                    }));
                }
                _ => {} // Valid: exactly one is present
            }

            // Check logical constraints on Principal/NotPrincipal
            if let (Some(_), Some(_)) = (&self.principal, &self.not_principal) {
                results.push(Err(ValidationError::LogicalError {
                    message: "Statement cannot have both Principal and NotPrincipal".to_string(),
                }));
            }

            // Validate NotPrincipal only used with Deny effect
            if self.not_principal.is_some() && self.effect != IAMEffect::Deny {
                results.push(Err(ValidationError::LogicalError {
                    message: "NotPrincipal must only be used with Effect: Deny".to_string(),
                }));
            }

            // Validate individual components if present
            if let Some(ref action) = self.action {
                results.push(action.validate(ctx));
            }
            if let Some(ref not_action) = self.not_action {
                results.push(not_action.validate(ctx));
            }
            if let Some(ref resource) = self.resource {
                results.push(resource.validate(ctx));
            }
            if let Some(ref not_resource) = self.not_resource {
                results.push(not_resource.validate(ctx));
            }
            if let Some(ref principal) = self.principal {
                results.push(principal.validate(ctx));
            }
            if let Some(ref not_principal) = self.not_principal {
                results.push(not_principal.validate(ctx));
            }
            if let Some(ref condition) = self.condition {
                results.push(condition.validate(ctx));
            }

            // Validate Sid format if present
            if let Some(ref sid) = self.sid {
                if !sid.chars().all(|c| c.is_ascii_alphanumeric()) {
                    results.push(Err(ValidationError::InvalidValue {
                        field: "Sid".to_string(),
                        value: sid.clone(),
                        reason: "Sid must contain only ASCII alphanumeric characters".to_string(),
                    }));
                }
            }

            helpers::collect_errors(results)
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::PrincipalId;

    use super::*;

    #[test]
    fn test_statement_validation() {
        // Valid statement
        let valid_statement = IAMStatement::new(IAMEffect::Allow)
            .with_action(IAMAction::Single("s3:GetObject".to_string()))
            .with_resource(IAMResource::Single("arn:aws:s3:::bucket/*".to_string()));
        assert!(valid_statement.is_valid());

        // Missing action and resource
        let invalid_statement = IAMStatement::new(IAMEffect::Allow);
        assert!(!invalid_statement.is_valid());

        // Both Action and NotAction
        let mut conflicting_statement = IAMStatement::new(IAMEffect::Allow);
        conflicting_statement.action = Some(IAMAction::Single("s3:GetObject".to_string()));
        conflicting_statement.not_action = Some(IAMAction::Single("s3:PutObject".to_string()));
        conflicting_statement.resource = Some(IAMResource::Single("*".to_string()));
        assert!(!conflicting_statement.is_valid());

        // Both Resource and NotResource
        let mut conflicting_resource = IAMStatement::new(IAMEffect::Allow);
        conflicting_resource.action = Some(IAMAction::Single("s3:GetObject".to_string()));
        conflicting_resource.resource = Some(IAMResource::Single("*".to_string()));
        conflicting_resource.not_resource =
            Some(IAMResource::Single("arn:aws:s3:::bucket/*".to_string()));
        assert!(!conflicting_resource.is_valid());
    }

    #[test]
    fn test_statement_principal_validation() {
        // NotPrincipal with Allow effect (invalid)
        let mut invalid_not_principal = IAMStatement::new(IAMEffect::Allow);
        invalid_not_principal.action = Some(IAMAction::Single("s3:GetObject".to_string()));
        invalid_not_principal.resource = Some(IAMResource::Single("*".to_string()));
        invalid_not_principal.not_principal = Some(Principal::Aws(PrincipalId::String(
            "arn:aws:iam::123456789012:user/test".to_string(),
        )));
        assert!(!invalid_not_principal.is_valid());

        // NotPrincipal with Deny effect (valid)
        let mut valid_not_principal = IAMStatement::new(IAMEffect::Deny);
        valid_not_principal.action = Some(IAMAction::Single("s3:GetObject".to_string()));
        valid_not_principal.resource = Some(IAMResource::Single("*".to_string()));
        valid_not_principal.not_principal = Some(Principal::Aws(PrincipalId::String(
            "arn:aws:iam::123456789012:user/test".to_string(),
        )));
        assert!(valid_not_principal.is_valid());

        // Both Principal and NotPrincipal (invalid)
        let mut conflicting_principal = IAMStatement::new(IAMEffect::Deny);
        conflicting_principal.action = Some(IAMAction::Single("s3:GetObject".to_string()));
        conflicting_principal.resource = Some(IAMResource::Single("*".to_string()));
        conflicting_principal.principal = Some(Principal::Aws(PrincipalId::String(
            "arn:aws:iam::123456789012:user/test".to_string(),
        )));
        conflicting_principal.not_principal = Some(Principal::Aws(PrincipalId::String(
            "arn:aws:iam::123456789012:user/other".to_string(),
        )));
        assert!(!conflicting_principal.is_valid());
    }

    #[test]
    fn test_full_statement_with_complex_conditions() {
        let statement = IAMStatement::new(IAMEffect::Allow)
            .with_sid("ComplexConditionExample")
            .with_action(IAMAction::Multiple(vec![
                "s3:GetObject".to_string(),
                "s3:PutObject".to_string(),
            ]))
            .with_resource(IAMResource::Single("arn:aws:s3:::my-bucket/*".to_string()))
            .with_condition(
                IAMOperator::StringEquals,
                "aws:PrincipalTag/department".to_string(),
                ConditionValue::StringList(vec![
                    "finance".to_string(),
                    "hr".to_string(),
                    "legal".to_string(),
                ]),
            )
            .with_condition(
                IAMOperator::ArnLike,
                "aws:PrincipalArn".to_string(),
                ConditionValue::StringList(vec![
                    "arn:aws:iam::222222222222:user/Ana".to_string(),
                    "arn:aws:iam::222222222222:user/Mary".to_string(),
                ]),
            );

        // Verify the conditions are properly structured
        assert!(statement.condition.is_some());
        let condition_block = statement.condition.as_ref().unwrap();

        assert!(
            condition_block.has_condition(&IAMOperator::StringEquals, "aws:PrincipalTag/department")
        );
        assert!(condition_block.has_condition(&IAMOperator::ArnLike, "aws:PrincipalArn"));
    }

    #[test]
    fn test_condition_handling() {
        let statement = IAMStatement::new(IAMEffect::Allow)
            .with_action(IAMAction::Single("s3:GetObject".to_string()))
            .with_condition(
                IAMOperator::StringEquals,
                "s3:prefix".to_string(),
                ConditionValue::String("uploads/".to_string()),
            );

        assert!(statement.condition.is_some());
        let condition_block = statement.condition.unwrap();
        assert!(condition_block.has_condition(&IAMOperator::StringEquals, "s3:prefix"));
    }

    #[test]
    fn test_statement_logical_validation() {
        // Test NotPrincipal with Allow (should fail)
        let mut invalid_not_principal = IAMStatement::new(IAMEffect::Allow);
        invalid_not_principal.action = Some(IAMAction::Single("s3:GetObject".to_string()));
        invalid_not_principal.resource = Some(IAMResource::Single("*".to_string()));
        invalid_not_principal.not_principal = Some(Principal::Aws(PrincipalId::String(
            "arn:aws:iam::123456789012:user/test".to_string(),
        )));

        assert!(!invalid_not_principal.is_valid());

        // Test both Action and NotAction (should fail)
        let mut conflicting_actions = IAMStatement::new(IAMEffect::Allow);
        conflicting_actions.action = Some(IAMAction::Single("s3:GetObject".to_string()));
        conflicting_actions.not_action = Some(IAMAction::Single("s3:PutObject".to_string()));
        conflicting_actions.resource = Some(IAMResource::Single("*".to_string()));

        assert!(!conflicting_actions.is_valid());

        // Test valid NotPrincipal with Deny
        let mut valid_not_principal = IAMStatement::new(IAMEffect::Deny);
        valid_not_principal.action = Some(IAMAction::Single("*".to_string()));
        valid_not_principal.resource = Some(IAMResource::Single("*".to_string()));
        valid_not_principal.not_principal = Some(Principal::Aws(PrincipalId::String(
            "arn:aws:iam::123456789012:user/test".to_string(),
        )));

        assert!(valid_not_principal.is_valid());
    }

    #[test]
    fn test_statement_sid_validation() {
        // Valid Sid
        let valid_sid = IAMStatement::new(IAMEffect::Allow)
            .with_sid("ValidSid123")
            .with_action(IAMAction::Single("s3:GetObject".to_string()))
            .with_resource(IAMResource::Single("*".to_string()));
        assert!(valid_sid.is_valid());

        // Invalid Sid with special characters
        let mut invalid_sid = IAMStatement::new(IAMEffect::Allow);
        invalid_sid.sid = Some("Invalid-Sid!".to_string());
        invalid_sid.action = Some(IAMAction::Single("s3:GetObject".to_string()));
        invalid_sid.resource = Some(IAMResource::Single("*".to_string()));
        assert!(!invalid_sid.is_valid());
    }
}
