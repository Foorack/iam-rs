use iam_rs::{Action, Arn, IAMEffect, IAMPolicy, IAMStatement, IAMResource};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== IAM ARN Validator Demo ===\n");

    // Example 1: Parse and validate ARNs
    println!("1. Parsing and validating ARNs:");

    let valid_arns = vec![
        "arn:aws:s3:::my-bucket/folder/file.txt",
        "arn:aws:iam::123456789012:user/alice",
        "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
        "arn:aws:lambda:us-east-1:123456789012:function:MyFunction",
        "arn:aws:dynamodb:us-east-1:123456789012:table/MyTable",
        "arn:aws-eu-gov:dynamodb:us-east-1:123456789012:table/MyTable",
    ];

    for arn_str in &valid_arns {
        match Arn::parse(arn_str) {
            Ok(arn) => {
                println!("✓ Valid ARN: {}", arn);
                println!("  - Service: {}", arn.service);
                println!(
                    "  - Region: {}",
                    if arn.region.is_empty() {
                        "global"
                    } else {
                        &arn.region
                    }
                );
                println!(
                    "  - Account: {}",
                    if arn.account_id.is_empty() {
                        "none"
                    } else {
                        &arn.account_id
                    }
                );
                if let Some(resource_type) = arn.resource_type() {
                    println!("  - Resource Type: {}", resource_type);
                }
                if let Some(resource_id) = arn.resource_id() {
                    println!("  - Resource ID: {}", resource_id);
                }
                println!();
            }
            Err(e) => println!("✗ Invalid ARN {}: {}", arn_str, e),
        }
    }

    // Example 2: Wildcard matching
    println!("2. Wildcard pattern matching:");

    let resource_arn = Arn::parse("arn:aws:s3:::my-bucket/uploads/user123/document.pdf")?;
    println!("Resource ARN: {}", resource_arn);

    let patterns = vec![
        "arn:aws:s3:::my-bucket/*",
        "arn:aws:s3:::my-bucket/uploads/*",
        "arn:aws:s3:::my-bucket/uploads/user123/*",
        "arn:aws:s3:::*/uploads/user123/document.pdf",
        "arn:aws:s3:::my-bucket/uploads/*/document.pdf",
        "arn:aws:s3:::my-bucket/uploads/user???/document.pdf",
        "arn:aws:s3:::other-bucket/*",
        "arn:aws:ec2:*:*:instance/*",
    ];

    for pattern in &patterns {
        match resource_arn.matches(pattern) {
            Ok(matches) => {
                let status = if matches { "✓ MATCH" } else { "✗ NO MATCH" };
                println!("  {} Pattern: {}", status, pattern);
            }
            Err(e) => println!("  ✗ ERROR Pattern: {} ({})", pattern, e),
        }
    }

    // Example 3: Integration with IAM policies
    println!("\n3. Using ARNs in IAM policies:");

    let policy = IAMPolicy::new()
        .with_id("s3-access-policy")
        .add_statement(
            IAMStatement::new(IAMEffect::Allow)
                .with_sid("AllowS3Read")
                .with_action(Action::Multiple(vec![
                    "s3:GetObject".to_string(),
                    "s3:ListBucket".to_string(),
                ]))
                .with_resource(IAMResource::Multiple(vec![
                    "arn:aws:s3:::my-bucket".to_string(),
                    "arn:aws:s3:::my-bucket/*".to_string(),
                ])),
        )
        .add_statement(
            IAMStatement::new(IAMEffect::Allow)
                .with_sid("AllowS3Write")
                .with_action(Action::Single("s3:PutObject".to_string()))
                .with_resource(IAMResource::Single(
                    "arn:aws:s3:::my-bucket/uploads/*".to_string(),
                )),
        );

    let policy_json = policy.to_json()?;
    println!("Generated IAM Policy:");
    println!("{}", policy_json);

    // Example 4: Validate all ARNs in the policy
    println!("\n4. Validating ARNs in policy:");

    for (i, statement) in policy.statement.iter().enumerate() {
        println!(
            "Statement {}: {}",
            i + 1,
            statement.sid.as_ref().unwrap_or(&"(no sid)".to_string())
        );

        let resources = match &statement.resource {
            Some(IAMResource::Single(arn)) => vec![arn.clone()],
            Some(IAMResource::Multiple(arns)) => arns.clone(),
            None => vec![],
        };

        for resource in resources {
            match Arn::parse(&resource) {
                Ok(arn) => {
                    let validity = if arn.is_valid() {
                        "✓ Valid"
                    } else {
                        "⚠ Invalid"
                    };
                    println!("  {} Resource: {}", validity, resource);
                }
                Err(e) => println!("  ✗ Parse Error: {} ({})", resource, e),
            }
        }
    }

    Ok(())
}
