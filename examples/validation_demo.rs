use iam_rs::{
    IAMAction, ConditionValue, IAMEffect, IAMOperator, IAMPolicy, IAMResource, IAMStatement,
    Principal, PrincipalId, Validate, ValidationError,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== IAM Policy Validation Demo ===\n");

    // Example 1: Valid Policy
    println!("1. Valid Policy Validation:");
    let valid_policy = IAMPolicy::new()
        .with_id("550e8400-e29b-41d4-a716-446655440000")
        .add_statement(
            IAMStatement::new(IAMEffect::Allow)
                .with_sid("AllowS3Read")
                .with_action(IAMAction::Single("s3:GetObject".to_string()))
                .with_resource(IAMResource::Single("arn:aws:s3:::my-bucket/*".to_string()))
                .with_condition(
                    IAMOperator::StringEquals,
                    "aws:PrincipalTag/department".to_string(),
                    ConditionValue::String("engineering".to_string()),
                ),
        );

    if valid_policy.is_valid() {
        println!("✓ Policy is valid!");
    } else {
        println!("✗ Policy is invalid");
    }

    match valid_policy.validate_result() {
        Ok(()) => println!("✓ Policy passes validation"),
        Err(e) => println!("✗ Policy fails validation: {}", e),
    }

    println!();

    // Example 2: Invalid Policy - Missing Required Fields
    println!("2. Invalid Policy - Missing Required Fields:");
    let invalid_policy = IAMPolicy::new().add_statement(IAMStatement::new(IAMEffect::Allow)); // Missing action and resource

    if !invalid_policy.is_valid() {
        println!("✗ Policy is invalid (as expected)");
        match invalid_policy.validate_result() {
            Err(e) => println!("   Validation errors: {}", e),
            Ok(()) => println!("   Unexpected: validation passed"),
        }
    }

    println!();

    // Example 3: Policy with Multiple Validation Errors
    println!("3. Policy with Multiple Validation Errors:");
    let multi_error_policy = IAMPolicy::new()
        .with_id("") // Empty ID
        .add_statement(
            IAMStatement::new(IAMEffect::Allow)
                .with_action(IAMAction::Single("invalid-action".to_string())) // Invalid action format
                .with_resource(IAMResource::Single("invalid-resource".to_string())), // Invalid resource
        )
        .add_statement(
            IAMStatement::new(IAMEffect::Allow)
                .with_sid("DuplicateId")
                .with_action(IAMAction::Single("s3:GetObject".to_string()))
                .with_resource(IAMResource::Single("*".to_string())),
        )
        .add_statement(
            IAMStatement::new(IAMEffect::Deny)
                .with_sid("DuplicateId") // Duplicate SID
                .with_action(IAMAction::Single("s3:DeleteObject".to_string()))
                .with_resource(IAMResource::Single("*".to_string())),
        );

    match multi_error_policy.validate_result() {
        Err(ValidationError::Multiple(errors)) => {
            println!("✗ Found {} validation errors:", errors.len());
            for (i, error) in errors.iter().enumerate() {
                println!("   {}. {}", i + 1, error);
            }
        }
        Err(e) => {
            println!("✗ Single validation error: {}", e);
        }
        Ok(()) => {
            println!("✓ Unexpected: validation passed");
        }
    }

    println!();

    // Example 4: Comprehensive Validation
    println!("4. Comprehensive Validation:");
    let comprehensive_policy = IAMPolicy::new()
        .with_id("short") // Short ID - will fail validation
        .add_statement(
            IAMStatement::new(IAMEffect::Allow)
                .with_action(IAMAction::Single("s3:GetObject".to_string()))
                .with_resource(IAMResource::Single("*".to_string()))
                .with_condition(
                    IAMOperator::NumericEquals,
                    "aws:RequestedRegion".to_string(),
                    ConditionValue::String("not-a-number".to_string()), // Numeric operator with string value - will fail
                ),
        );

    match comprehensive_policy.validate_result() {
        Ok(()) => println!("✓ Policy passes validation"),
        Err(e) => println!("✗ Policy fails validation: {}", e),
    }

    println!();

    // Example 5: Logical Policy Errors
    println!("5. Logical Policy Errors:");

    // NotPrincipal with Allow effect (invalid)
    let mut logical_error_policy = IAMStatement::new(IAMEffect::Allow);
    logical_error_policy.action = Some(IAMAction::Single("s3:GetObject".to_string()));
    logical_error_policy.resource = Some(IAMResource::Single("*".to_string()));
    logical_error_policy.not_principal = Some(Principal::Aws(iam_rs::PrincipalId::String(
        "arn:aws:iam::123456789012:user/test".to_string(),
    )));

    match logical_error_policy.validate_result() {
        Err(e) => println!("✗ Logical error detected: {}", e),
        Ok(()) => println!("✓ Unexpected: validation passed"),
    }

    // Both Action and NotAction (invalid)
    let mut conflicting_statement = IAMStatement::new(IAMEffect::Allow);
    conflicting_statement.action = Some(IAMAction::Single("s3:GetObject".to_string()));
    conflicting_statement.not_action = Some(IAMAction::Single("s3:PutObject".to_string()));
    conflicting_statement.resource = Some(IAMResource::Single("*".to_string()));

    match conflicting_statement.validate_result() {
        Err(e) => println!("✗ Logical error detected: {}", e),
        Ok(()) => println!("✓ Unexpected: validation passed"),
    }

    println!();

    // Example 6: Component Validation
    println!("6. Individual Component Validation:");

    // Invalid action
    let invalid_action = IAMAction::Single("invalid-action".to_string());
    match invalid_action.validate_result() {
        Err(e) => println!("✗ Invalid action: {}", e),
        Ok(()) => println!("✓ Action is valid"),
    }

    // Invalid principal
    let invalid_principal = Principal::Aws(PrincipalId::String("invalid-principal".to_string()));
    match invalid_principal.validate_result() {
        Err(e) => println!("✗ Invalid principal: {}", e),
        Ok(()) => println!("✓ Principal is valid"),
    }

    // Valid service principal
    let service_principal =
        Principal::Service(PrincipalId::String("lambda.amazonaws.com".to_string()));
    if service_principal.is_valid() {
        println!("✓ Service principal is valid");
    } else {
        println!("✗ Service principal is invalid");
    }

    println!("\n=== Validation Demo Complete ===");

    Ok(())
}
