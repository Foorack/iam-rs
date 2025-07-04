pub mod models;

// Re-export all the main types for easy access
pub use models::*;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
    fn test_condition_handling() {
        let statement = IAMStatement::new(Effect::Allow)
            .with_action(Action::Single("s3:GetObject".to_string()))
            .with_condition(
                Operator::StringEquals,
                "s3:prefix".to_string(),
                json!("uploads/"),
            );

        assert!(statement.condition.is_some());
        let condition_block = statement.condition.unwrap();
        assert!(condition_block.has_condition(&Operator::StringEquals, "s3:prefix"));
    }

    #[test]
    fn test_full_statement_with_complex_conditions() {
        let statement = IAMStatement::new(Effect::Allow)
            .with_sid("ComplexConditionExample")
            .with_action(Action::Multiple(vec![
                "s3:GetObject".to_string(),
                "s3:PutObject".to_string(),
            ]))
            .with_resource(Resource::Single("arn:aws:s3:::my-bucket/*".to_string()))
            .with_condition(
                Operator::StringEquals,
                "aws:PrincipalTag/department".to_string(),
                json!(["finance", "hr", "legal"]),
            )
            .with_condition(
                Operator::ArnLike,
                "aws:PrincipalArn".to_string(),
                json!([
                    "arn:aws:iam::222222222222:user/Ana",
                    "arn:aws:iam::222222222222:user/Mary"
                ]),
            );

        let policy = IAMPolicy::new()
            .with_id("test-complex-conditions")
            .add_statement(statement);

        let json = policy.to_json().unwrap();
        println!("Full policy JSON:\n{}", json);

        let parsed_policy = IAMPolicy::from_json(&json).unwrap();
        assert_eq!(policy, parsed_policy);

        // Verify the conditions are properly structured
        let stmt = &parsed_policy.statement[0];
        assert!(stmt.condition.is_some());
        let condition_block = stmt.condition.as_ref().unwrap();

        assert!(
            condition_block.has_condition(&Operator::StringEquals, "aws:PrincipalTag/department")
        );
        assert!(condition_block.has_condition(&Operator::ArnLike, "aws:PrincipalArn"));
    }
}
