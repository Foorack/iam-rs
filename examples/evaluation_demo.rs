use iam_rs::{
    Action, AuthorizationRequest, ContextValue, Decision, Effect, EvaluationOptions, IAMPolicy,
    IAMStatement, Operator, PolicyEvaluator, RequestContext, Resource, evaluate_policy,
};
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== IAM Policy Evaluation Engine Demo ===\n");

    // Example 1: Simple Allow Policy
    println!("1. Simple Allow Policy:");
    let allow_policy = IAMPolicy::new()
        .with_id("550e8400-e29b-41d4-a716-446655440000")
        .add_statement(
            IAMStatement::new(Effect::Allow)
                .with_sid("AllowS3Read")
                .with_action(Action::Single("s3:GetObject".to_string()))
                .with_resource(Resource::Single("arn:aws:s3:::my-bucket/*".to_string())),
        );

    let request = AuthorizationRequest::simple(
        "arn:aws:iam::123456789012:user/alice",
        "s3:GetObject",
        "arn:aws:s3:::my-bucket/file.txt",
    );

    match evaluate_policy(&allow_policy, &request)? {
        Decision::Allow => println!("✓ Access ALLOWED"),
        Decision::Deny => println!("✗ Access DENIED"),
        Decision::NotApplicable => println!("? No applicable policy (implicit deny)"),
    }
    println!();

    // Example 2: Simple Deny Policy
    println!("2. Simple Deny Policy:");
    let deny_policy = IAMPolicy::new()
        .with_id("550e8400-e29b-41d4-a716-446655440001")
        .add_statement(
            IAMStatement::new(Effect::Deny)
                .with_sid("DenyS3Delete")
                .with_action(Action::Single("s3:DeleteObject".to_string()))
                .with_resource(Resource::Single(
                    "arn:aws:s3:::protected-bucket/*".to_string(),
                )),
        );

    let delete_request = AuthorizationRequest::simple(
        "arn:aws:iam::123456789012:user/alice",
        "s3:DeleteObject",
        "arn:aws:s3:::protected-bucket/important.txt",
    );

    match evaluate_policy(&deny_policy, &delete_request)? {
        Decision::Allow => println!("✓ Access ALLOWED"),
        Decision::Deny => println!("✗ Access DENIED"),
        Decision::NotApplicable => println!("? No applicable policy (implicit deny)"),
    }
    println!();

    // Example 3: Wildcard Action Matching
    println!("3. Wildcard Action Matching:");
    let wildcard_policy = IAMPolicy::new()
        .with_id("550e8400-e29b-41d4-a716-446655440002")
        .add_statement(
            IAMStatement::new(Effect::Allow)
                .with_sid("AllowAllS3")
                .with_action(Action::Single("s3:*".to_string()))
                .with_resource(Resource::Single("arn:aws:s3:::my-bucket/*".to_string())),
        );

    let wildcard_request = AuthorizationRequest::simple(
        "arn:aws:iam::123456789012:user/alice",
        "s3:PutObject",
        "arn:aws:s3:::my-bucket/new-file.txt",
    );

    match evaluate_policy(&wildcard_policy, &wildcard_request)? {
        Decision::Allow => println!("✓ Wildcard action matched - Access ALLOWED"),
        Decision::Deny => println!("✗ Access DENIED"),
        Decision::NotApplicable => println!("? No applicable policy"),
    }
    println!();

    // Example 4: Condition-Based Policy
    println!("4. Condition-Based Policy:");
    let mut context = RequestContext::empty();
    context.insert(
        "aws:userid".to_string(),
        ContextValue::String("alice".to_string()),
    );
    context.insert(
        "aws:CurrentTime".to_string(),
        ContextValue::String("2024-01-15T10:00:00Z".to_string()),
    );

    let condition_policy = IAMPolicy::new()
        .with_id("550e8400-e29b-41d4-a716-446655440003")
        .add_statement(
            IAMStatement::new(Effect::Allow)
                .with_sid("AllowWithCondition")
                .with_action(Action::Single("s3:GetObject".to_string()))
                .with_resource(Resource::Single(
                    "arn:aws:s3:::private-bucket/*".to_string(),
                ))
                .with_condition(
                    Operator::StringEquals,
                    "aws:userid".to_string(),
                    json!("alice"),
                ),
        );

    let condition_request = AuthorizationRequest::new(
        "arn:aws:iam::123456789012:user/alice",
        "s3:GetObject",
        "arn:aws:s3:::private-bucket/personal.txt",
        context,
    );

    match evaluate_policy(&condition_policy, &condition_request)? {
        Decision::Allow => println!("✓ Condition satisfied - Access ALLOWED"),
        Decision::Deny => println!("✗ Access DENIED"),
        Decision::NotApplicable => println!("? Condition not satisfied"),
    }
    println!();

    // Example 5: Failed Condition
    println!("5. Failed Condition:");
    let mut wrong_context = RequestContext::empty();
    wrong_context.insert(
        "aws:userid".to_string(),
        ContextValue::String("bob".to_string()),
    );

    let failed_condition_request = AuthorizationRequest::new(
        "arn:aws:iam::123456789012:user/bob",
        "s3:GetObject",
        "arn:aws:s3:::private-bucket/personal.txt",
        wrong_context,
    );

    match evaluate_policy(&condition_policy, &failed_condition_request)? {
        Decision::Allow => println!("✓ Access ALLOWED"),
        Decision::Deny => println!("✗ Access DENIED"),
        Decision::NotApplicable => println!("? Condition failed - No applicable policy"),
    }
    println!();

    // Example 6: Explicit Deny Overrides Allow
    println!("6. Explicit Deny Overrides Allow:");
    let combined_policies = vec![
        IAMPolicy::new()
            .with_id("550e8400-e29b-41d4-a716-446655440004")
            .add_statement(
                IAMStatement::new(Effect::Allow)
                    .with_sid("AllowAll")
                    .with_action(Action::Single("s3:*".to_string()))
                    .with_resource(Resource::Single("*".to_string())),
            ),
        IAMPolicy::new()
            .with_id("550e8400-e29b-41d4-a716-446655440005")
            .add_statement(
                IAMStatement::new(Effect::Deny)
                    .with_sid("DenyProtected")
                    .with_action(Action::Single("s3:DeleteObject".to_string()))
                    .with_resource(Resource::Single(
                        "arn:aws:s3:::protected-bucket/*".to_string(),
                    )),
            ),
    ];

    let evaluator = PolicyEvaluator::with_policies(combined_policies);
    let protected_request = AuthorizationRequest::simple(
        "arn:aws:iam::123456789012:user/alice",
        "s3:DeleteObject",
        "arn:aws:s3:::protected-bucket/critical.txt",
    );

    match evaluator.evaluate(&protected_request)?.decision {
        Decision::Allow => println!("✓ Access ALLOWED"),
        Decision::Deny => println!("✗ Explicit DENY overrides Allow"),
        Decision::NotApplicable => println!("? No applicable policy"),
    }
    println!();

    // Example 7: Numeric Condition
    println!("7. Numeric Condition:");
    let mut numeric_context = RequestContext::empty();
    numeric_context.insert("aws:RequestCount".to_string(), ContextValue::Number(5.0));

    let numeric_policy = IAMPolicy::new()
        .with_id("550e8400-e29b-41d4-a716-446655440006")
        .add_statement(
            IAMStatement::new(Effect::Allow)
                .with_sid("AllowLimitedRequests")
                .with_action(Action::Single("s3:GetObject".to_string()))
                .with_resource(Resource::Single("*".to_string()))
                .with_condition(
                    Operator::NumericLessThan,
                    "aws:RequestCount".to_string(),
                    json!(10),
                ),
        );

    let numeric_request = AuthorizationRequest::new(
        "arn:aws:iam::123456789012:user/alice",
        "s3:GetObject",
        "arn:aws:s3:::any-bucket/file.txt",
        numeric_context,
    );

    match evaluate_policy(&numeric_policy, &numeric_request)? {
        Decision::Allow => println!("✓ Numeric condition satisfied - Access ALLOWED"),
        Decision::Deny => println!("✗ Access DENIED"),
        Decision::NotApplicable => println!("? Numeric condition failed"),
    }
    println!();

    // Example 8: Detailed Evaluation with Options
    println!("8. Detailed Evaluation with Options:");
    let detailed_evaluator = PolicyEvaluator::with_policies(vec![allow_policy.clone()])
        .with_options(EvaluationOptions {
            collect_match_details: true,
            stop_on_explicit_deny: false,
            max_statements: 100,
        });

    let detailed_result = detailed_evaluator.evaluate(&request)?;
    println!("Decision: {:?}", detailed_result.decision);
    println!("Matched Statements:");
    for (i, statement_match) in detailed_result.matched_statements.iter().enumerate() {
        println!(
            "  {}. SID: {:?}, Effect: {:?}, Satisfied: {}, Reason: {}",
            i + 1,
            statement_match.sid,
            statement_match.effect,
            statement_match.conditions_satisfied,
            statement_match.reason
        );
    }
    println!();

    // Example 9: No Applicable Policy (Implicit Deny)
    println!("9. No Applicable Policy (Implicit Deny):");
    let unrelated_request = AuthorizationRequest::simple(
        "arn:aws:iam::123456789012:user/alice",
        "ec2:DescribeInstances",
        "arn:aws:ec2:us-east-1:123456789012:instance/*",
    );

    match evaluate_policy(&allow_policy, &unrelated_request)? {
        Decision::Allow => println!("✓ Access ALLOWED"),
        Decision::Deny => println!("✗ Access DENIED"),
        Decision::NotApplicable => println!("? No applicable policy - Implicit DENY"),
    }
    println!();

    // Example 10: Resource Pattern Matching
    println!("10. Resource Pattern Matching:");
    let pattern_policy = IAMPolicy::new()
        .with_id("550e8400-e29b-41d4-a716-446655440007")
        .add_statement(
            IAMStatement::new(Effect::Allow)
                .with_sid("AllowBucketAccess")
                .with_action(Action::Multiple(vec![
                    "s3:GetObject".to_string(),
                    "s3:PutObject".to_string(),
                ]))
                .with_resource(Resource::Single("arn:aws:s3:::user-data-*/*".to_string())),
        );

    let pattern_request = AuthorizationRequest::simple(
        "arn:aws:iam::123456789012:user/alice",
        "s3:GetObject",
        "arn:aws:s3:::user-data-alice/profile.json",
    );

    match evaluate_policy(&pattern_policy, &pattern_request)? {
        Decision::Allow => println!("✓ Resource pattern matched - Access ALLOWED"),
        Decision::Deny => println!("✗ Access DENIED"),
        Decision::NotApplicable => println!("? Resource pattern didn't match"),
    }

    println!("\n=== Policy Evaluation Demo Complete ===");
    println!("\nThe Policy Evaluation Engine successfully:");
    println!("• ✅ Evaluates Allow/Deny effects");
    println!("• ✅ Handles wildcard actions and resources");
    println!("• ✅ Processes condition blocks with various operators");
    println!("• ✅ Implements proper IAM logic (explicit deny overrides)");
    println!("• ✅ Supports detailed evaluation with match information");
    println!("• ✅ Handles multiple policies with complex interactions");
    println!("• ✅ Provides clear Allow/Deny/NotApplicable decisions");

    Ok(())
}
