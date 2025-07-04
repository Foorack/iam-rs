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

    #[test]
    fn test_arn_validation_in_policies() {
        // Test valid ARNs in policy resources
        let valid_arns = vec![
            "arn:aws:s3:::my-bucket/*",
            "arn:aws:s3:::my-bucket/folder/*",
            "arn:aws:iam::123456789012:user/username",
            "arn:aws:ec2:us-east-1:123456789012:instance/*",
            "arn:aws:lambda:us-east-1:123456789012:function:MyFunction",
        ];

        for arn_str in valid_arns {
            let arn = Arn::parse(arn_str).unwrap();
            assert!(arn.is_valid(), "ARN should be valid: {}", arn_str);

            // Create a policy with this ARN
            let statement = IAMStatement::new(Effect::Allow)
                .with_action(Action::Single("*".to_string()))
                .with_resource(Resource::Single(arn_str.to_string()));

            let policy = IAMPolicy::new().add_statement(statement);

            // Should serialize and deserialize without issues
            let json = policy.to_json().unwrap();
            let parsed_policy = IAMPolicy::from_json(&json).unwrap();
            assert_eq!(policy, parsed_policy);
        }
    }

    #[test]
    fn test_arn_wildcard_matching_in_policies() {
        // Test ARN pattern matching for resource access
        let resource_arn =
            Arn::parse("arn:aws:s3:::my-bucket/uploads/user123/document.pdf").unwrap();

        // These patterns should match
        let matching_patterns = vec![
            "arn:aws:s3:::my-bucket/*",
            "arn:aws:s3:::my-bucket/uploads/*",
            "arn:aws:s3:::my-bucket/uploads/user123/*",
            "arn:aws:s3:::*/uploads/user123/document.pdf",
            "arn:aws:s3:::my-bucket/uploads/*/document.pdf",
            "arn:aws:s3:::my-bucket/*/user123/document.pdf",
            "arn:aws:s3:::my-bucket/uploads/user???/document.pdf",
        ];

        for pattern in matching_patterns {
            assert!(
                resource_arn.matches(pattern).unwrap(),
                "Pattern '{}' should match ARN '{}'",
                pattern,
                resource_arn
            );
        }

        // These patterns should NOT match
        let non_matching_patterns = vec![
            "arn:aws:s3:::other-bucket/*",
            "arn:aws:s3:::my-bucket/downloads/*",
            "arn:aws:s3:::my-bucket/uploads/user456/*",
            "arn:aws:ec2:*:*:*", // Different service
            "arn:aws:s3:::my-bucket/uploads/user12/document.pdf", // user12 != user123
        ];

        for pattern in non_matching_patterns {
            assert!(
                !resource_arn.matches(pattern).unwrap(),
                "Pattern '{}' should NOT match ARN '{}'",
                pattern,
                resource_arn
            );
        }
    }

    #[test]
    fn test_arn_resource_parsing() {
        let test_cases = vec![
            ("arn:aws:s3:::bucket/object", Some("bucket"), Some("object")),
            (
                "arn:aws:iam::123456789012:user/username",
                Some("user"),
                Some("username"),
            ),
            (
                "arn:aws:iam::123456789012:role/MyRole",
                Some("role"),
                Some("MyRole"),
            ),
            (
                "arn:aws:sns:us-east-1:123456789012:my-topic",
                None,
                Some("my-topic"),
            ),
            (
                "arn:aws:dynamodb:us-east-1:123456789012:table/MyTable",
                Some("table"),
                Some("MyTable"),
            ),
            (
                "arn:aws:s3:::bucket/folder/subfolder/file.txt",
                Some("bucket"),
                Some("folder/subfolder/file.txt"),
            ),
        ];

        for (arn_str, expected_type, expected_id) in test_cases {
            let arn = Arn::parse(arn_str).unwrap();
            assert_eq!(
                arn.resource_type(),
                expected_type,
                "Resource type mismatch for {}",
                arn_str
            );
            assert_eq!(
                arn.resource_id(),
                expected_id,
                "Resource ID mismatch for {}",
                arn_str
            );
        }
    }

    #[test]
    fn test_invalid_arns() {
        let invalid_arns = vec![
            "not-an-arn",
            "arn:aws:s3",                                            // Too few parts
            "arn::s3:us-east-1:123456789012:bucket/my-bucket",       // Empty partition
            "arn:aws::us-east-1:123456789012:bucket/my-bucket",      // Empty service
            "arn:aws:s3:us-east-1:123456789012:",                    // Empty resource
            "arn:aws:s3:us-east-1:invalid-account:bucket/my-bucket", // Invalid account ID
            "arn:aws:s3:us-east-1:12345678901:bucket/my-bucket",     // Account ID too short
            "arn:aws:s3:us-east-1:1234567890123:bucket/my-bucket",   // Account ID too long
        ];

        for invalid_arn in invalid_arns {
            let result = Arn::parse(invalid_arn);
            assert!(result.is_err(), "ARN should be invalid: {}", invalid_arn);
        }
    }
}
