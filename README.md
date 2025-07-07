# iam-rs

[![Crates.io](https://img.shields.io/crates/v/iam-rs.svg)](https://crates.io/crates/iam-rs)
[![Documentation](https://docs.rs/iam-rs/badge.svg)](https://docs.rs/iam-rs)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A comprehensive Rust library for parsing, validating, and evaluating AWS IAM (Identity and Access Management) policies. Provider-agnostic and designed for building flexible authorization systems with full AWS IAM compatibility.

## 🚀 Key Features

- **🔒 Complete IAM Policy Support**: Full implementation of AWS IAM policy language including conditions, principals, actions, and resources
- **⚖️ Policy Evaluation Engine**: Production-ready authorization engine with proper AWS IAM precedence rules
- **🏷️ Advanced ARN Support**: Comprehensive ARN parsing, validation, and wildcard pattern matching
- **🎯 Rich Condition Engine**: Support for all AWS condition operators (String, Numeric, Date, Boolean, IP, ARN, Binary, Null)
- **� Variable Interpolation**: Dynamic policy variables with default fallback values (e.g., `${aws:username, 'anonymous'}`)
- **📦 Type-Safe APIs**: Strong typing with comprehensive enums, builder patterns, and Serde integration
- **⚡ High Performance**: Zero-copy parsing, efficient evaluation, and minimal dependencies
- **🧪 Production Ready**: Extensive test suite with 100+ tests covering real-world scenarios

## 📦 Installation

```bash
cargo add iam-rs
```

## 🏃 Quick Start

### Simple Authorization Check

```rust
use iam_rs::{evaluate_policy, IAMRequest, IAMPolicy, IAMStatement, Effect, Action, Resource, Decision};

// Create a policy allowing S3 read access
let policy = IAMPolicy::new()
    .add_statement(
        IAMStatement::new(Effect::Allow)
            .with_action(Action::Single("s3:GetObject".to_string()))
            .with_resource(Resource::Single("arn:aws:s3:::my-bucket/*".to_string()))
    );

// Create an authorization request  
let request = IAMRequest::new(
    "arn:aws:iam::123456789012:user/alice",
    "s3:GetObject",
    "arn:aws:s3:::my-bucket/file.txt"
);

// Evaluate the request
match evaluate_policy(&policy, &request)? {
    Decision::Allow => println!("✓ Access granted"),
    Decision::Deny => println!("✗ Access denied"), 
    Decision::NotApplicable => println!("? No applicable policy (implicit deny)"),
}
```

### Policy with Conditions

```rust
use iam_rs::{IAMPolicy, IAMStatement, Effect, Action, Resource, Operator, Context, ContextValue};
use serde_json::json;

// Create context for condition evaluation
let mut context = Context::new();
context.insert("aws:username".to_string(), ContextValue::String("alice".to_string()));
context.insert("s3:prefix".to_string(), ContextValue::String("uploads/".to_string()));

// Policy with string and date conditions
let policy = IAMPolicy::new()
    .with_id("ConditionalPolicy")
    .add_statement(
        IAMStatement::new(Effect::Allow)
            .with_sid("AllowUploadToUserFolder")
            .with_action(Action::Single("s3:PutObject".to_string()))
            .with_resource(Resource::Single("arn:aws:s3:::my-bucket/${aws:username}/*".to_string()))
            .with_condition(
                Operator::StringEquals,
                "s3:prefix".to_string(),
                json!("uploads/")
            )
            .with_condition(
                Operator::DateGreaterThan,
                "aws:CurrentTime".to_string(),
                json!("2024-01-01T00:00:00Z")
            )
    );

let request = IAMRequest::new_with_context(
    "arn:aws:iam::123456789012:user/alice",
    "s3:PutObject", 
    "arn:aws:s3:::my-bucket/alice/uploads/document.pdf",
    context
);

let decision = evaluate_policy(&policy, &request)?;
```

## 📋 Core Components

### IAM Policy Structure

```rust
use iam_rs::{IAMPolicy, IAMStatement, Effect, Action, Resource, Principal};

let policy = IAMPolicy::new()
    .with_version(IAMVersion::V20121017)  // AWS standard version
    .with_id("MySecurityPolicy")
    .add_statement(
        IAMStatement::new(Effect::Allow)
            .with_sid("AllowSpecificUsers")
            .with_principal(Principal::from_aws_users(&[
                "arn:aws:iam::123456789012:user/alice",
                "arn:aws:iam::123456789012:user/bob"  
            ]))
            .with_action(Action::Multiple(vec![
                "s3:GetObject".to_string(),
                "s3:PutObject".to_string()
            ]))
            .with_resource(Resource::Single("arn:aws:s3:::secure-bucket/*".to_string()))
    );
```

### Advanced Pattern Matching

#### ARN Wildcard Patterns

```rust
use iam_rs::Arn;

let arn = Arn::parse("arn:aws:s3:::my-bucket/users/alice/documents/file.pdf")?;

// Test various wildcard patterns
let patterns = [
    "arn:aws:s3:::my-bucket/*",           // ✓ Matches any object in bucket
    "arn:aws:s3:::my-bucket/users/*",     // ✓ Matches any user path  
    "arn:aws:s3:::my-bucket/users/alice/*", // ✓ Matches Alice's files
    "arn:aws:s3:::*/documents/*",         // ✓ Matches any bucket documents
    "arn:aws:s3:::my-bucket/*/file.pdf",  // ✓ Matches file.pdf anywhere
    "arn:aws:s3:::my-bucket/users/bob/*", // ✗ Different user path
];

for pattern in patterns {
    if arn.matches(pattern)? {
        println!("✓ ARN matches pattern: {}", pattern);
    }
}
```

#### Action Wildcards

```rust
// Action wildcard matching
let actions = Action::Multiple(vec![
    "s3:*".to_string(),           // All S3 actions
    "s3:Get*".to_string(),        // All S3 Get actions  
    "s3:Put*".to_string(),        // All S3 Put actions
    "iam:List*".to_string(),      // All IAM List actions
]);
```

## 🔧 Variable Interpolation

IAM-rs supports AWS policy variables with default fallback values, enabling dynamic resource paths and conditions.

### Basic Variable Usage

```rust
use iam_rs::{interpolate_variables, Context, ContextValue};

// Set up context
let mut context = Context::new();
context.insert("aws:username".to_string(), ContextValue::String("alice".to_string()));
context.insert("aws:PrincipalTag/team".to_string(), ContextValue::String("red".to_string()));

// Basic variable interpolation
let resource_pattern = "arn:aws:s3:::company-bucket/${aws:username}/*";
let resolved = interpolate_variables(resource_pattern, &context)?;
// Result: "arn:aws:s3:::company-bucket/alice/*"

// Variable with default fallback
let team_pattern = "arn:aws:s3:::team-bucket-${aws:PrincipalTag/team, 'default'}/*";
let resolved = interpolate_variables(team_pattern, &context)?;
// Result: "arn:aws:s3:::team-bucket-red/*"
```

### Variables with Default Values

```rust
// When context key is missing, use default value
let empty_context = Context::new();

let pattern = "arn:aws:s3:::bucket-${aws:PrincipalTag/department, 'general'}/*";
let resolved = interpolate_variables(pattern, &empty_context)?;
// Result: "arn:aws:s3:::bucket-general/*" (uses default)

// Common variable patterns
let patterns = [
    "${aws:username}",                          // Current user
    "${aws:userid}",                            // User ID
    "${aws:PrincipalTag/team, 'default'}",     // Principal tag with fallback
    "${aws:RequestedRegion, 'us-east-1'}",     // Region with fallback  
    "${aws:CurrentTime}",                       // Current timestamp
    "${s3:prefix, 'uploads/'}",                 // S3 prefix with fallback
];
```

### Dynamic Policy Example

```rust
// Policy that grants access to user-specific paths with team fallback
let policy = IAMPolicy::new()
    .add_statement(
        IAMStatement::new(Effect::Allow)
            .with_action(Action::Single("s3:*".to_string()))
            .with_resource(Resource::Multiple(vec![
                // User's personal folder
                "arn:aws:s3:::company-data/${aws:username}/*".to_string(),
                // Team shared folder (with fallback)  
                "arn:aws:s3:::team-data/${aws:PrincipalTag/team, 'shared'}/*".to_string(),
                // Department folder (with fallback)
                "arn:aws:s3:::dept-data/${aws:PrincipalTag/department, 'general'}/*".to_string(),
            ]))
            .with_condition(
                Operator::StringLike,
                "s3:prefix".to_string(),
                json!("${aws:username}/*")
            )
    );
```

## 🎯 Condition Operators

IAM-rs supports all AWS condition operators with full type safety:

### String Conditions

```rust
use iam_rs::Operator;

// Basic string operations
Operator::StringEquals         // Exact match
Operator::StringNotEquals      // Not equal
Operator::StringEqualsIgnoreCase // Case-insensitive match
Operator::StringLike           // Wildcard matching (*, ?)
Operator::StringNotLike        // Inverse wildcard matching

// Set-based string operations
Operator::ForAnyValueStringEquals     // At least one value matches
Operator::ForAllValuesStringEquals    // All values match
```

### Numeric and Date Conditions

```rust
// Numeric comparisons
Operator::NumericEquals
Operator::NumericNotEquals  
Operator::NumericLessThan
Operator::NumericLessThanEquals
Operator::NumericGreaterThan
Operator::NumericGreaterThanEquals

// Date/time comparisons  
Operator::DateEquals
Operator::DateNotEquals
Operator::DateLessThan
Operator::DateGreaterThan
Operator::DateLessThanEquals
Operator::DateGreaterThanEquals
```

### Specialized Conditions

```rust
// Boolean conditions
Operator::Bool

// IP address conditions
Operator::IpAddress            // IP within CIDR range
Operator::NotIpAddress         // IP not in CIDR range

// ARN conditions
Operator::ArnEquals            // Exact ARN match
Operator::ArnLike              // ARN wildcard matching
Operator::ArnNotEquals
Operator::ArnNotLike

// Null checks
Operator::Null                 // Key exists/doesn't exist

// Binary data
Operator::BinaryEquals         // Base64 binary comparison
```

### Complex Condition Example

```rust
let statement = IAMStatement::new(Effect::Allow)
    .with_action(Action::Single("s3:GetObject".to_string()))
    .with_resource(Resource::Single("arn:aws:s3:::secure-bucket/*".to_string()))
    // Must be from trusted IP range
    .with_condition(
        Operator::IpAddress,
        "aws:SourceIp".to_string(),
        json!(["203.0.113.0/24", "198.51.100.0/24"])
    )
    // Must have MFA
    .with_condition(
        Operator::Bool,
        "aws:MultiFactorAuthPresent".to_string(),
        json!(true)
    )
    // Must be during business hours
    .with_condition(
        Operator::DateGreaterThan,
        "aws:CurrentTime".to_string(),
        json!("08:00:00Z")
    )
    .with_condition(
        Operator::DateLessThan,
        "aws:CurrentTime".to_string(),
        json!("18:00:00Z")
    )
    // User must have required tag
    .with_condition(
        Operator::StringEquals,
        "aws:PrincipalTag/clearance".to_string(),
        json!("high")
    );
```

## ⚖️ Policy Evaluation Engine

### Advanced Evaluation Options

```rust
use iam_rs::{PolicyEvaluator, EvaluationOptions};

let evaluator = PolicyEvaluator::with_policies(vec![policy1, policy2, policy3])
    .with_options(EvaluationOptions {
        stop_on_explicit_deny: true,      // Stop at first explicit deny
        collect_match_details: true,      // Collect debug information
        max_statements: 1000,             // Safety limit
    });

let result = evaluator.evaluate(&request)?;

println!("Decision: {:?}", result.decision);
println!("Evaluated {} statements", result.matched_statements.len());

// Examine detailed results
for statement_match in result.matched_statements {
    println!("Statement '{}': {} - {}", 
        statement_match.sid.unwrap_or_default(),
        if statement_match.conditions_satisfied { "MATCHED" } else { "NO MATCH" },
        statement_match.reason
    );
}
```

### IAM Precedence Rules

The evaluation engine implements proper AWS IAM logic:

1. **Explicit Deny**: Always takes precedence over Allow
2. **Explicit Allow**: Required for access (no implicit allow)  
3. **Implicit Deny**: Default when no Allow statements match
4. **Conditions**: Must be satisfied for statement to apply
5. **Multiple Policies**: Combined with proper precedence

```rust
// Example demonstrating precedence
let allow_policy = IAMPolicy::new()
    .add_statement(
        IAMStatement::new(Effect::Allow)
            .with_action(Action::Single("s3:*".to_string()))
            .with_resource(Resource::Single("*".to_string()))
    );

let deny_policy = IAMPolicy::new()
    .add_statement(
        IAMStatement::new(Effect::Deny)  // This will override the Allow
            .with_action(Action::Single("s3:DeleteObject".to_string()))
            .with_resource(Resource::Single("arn:aws:s3:::protected-bucket/*".to_string()))
    );

let policies = vec![allow_policy, deny_policy];
let result = evaluate_policies(&policies, &delete_request)?;
// Result: Decision::Deny (Explicit deny wins)
```

## 📝 JSON Policy Support

### Parsing from JSON

```rust
let json_policy = r#"
{
  "Version": "2012-10-17",
  "Id": "S3BucketPolicy", 
  "Statement": [
    {
      "Sid": "AllowUserAccess",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:user/alice"
      },
      "Action": ["s3:GetObject", "s3:PutObject"],
      "Resource": "arn:aws:s3:::my-bucket/${aws:username}/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-server-side-encryption": "AES256"
        },
        "NumericLessThan": {
          "s3:max-keys": "10"
        }
      }
    }
  ]
}
"#;

let policy = IAMPolicy::from_json(json_policy)?;
println!("Loaded policy with {} statements", policy.statement.len());
```

### Generating JSON

```rust
// Create policy programmatically
let policy = IAMPolicy::new()
    .with_id("GeneratedPolicy")
    .add_statement(
        IAMStatement::new(Effect::Allow)
            .with_sid("S3Access")
            .with_action(Action::Single("s3:GetObject".to_string()))
            .with_resource(Resource::Single("arn:aws:s3:::my-bucket/*".to_string()))
    );

// Export to JSON
let json_output = policy.to_json()?;
println!("{}", json_output);
```

## 🧪 Examples

Run the comprehensive examples to see all features in action:

```bash
# ARN parsing and wildcard matching
cargo run --example arn_demo

# Policy validation and structure
cargo run --example validation_demo  

# Complete evaluation engine with conditions
cargo run --example evaluation_demo
```

### Example Scenarios Covered

- ✅ **Basic Allow/Deny policies** with simple action/resource matching
- ✅ **Wildcard patterns** for actions, resources, and principals  
- ✅ **Complex conditions** with String, Numeric, Date, Boolean, IP, and ARN operators
- ✅ **Variable interpolation** with fallback values for dynamic policies
- ✅ **Multi-policy evaluation** with proper precedence handling
- ✅ **Real-world scenarios** like user folder access, time-based restrictions
- ✅ **Resource-based policies** for S3 buckets, Lambda functions, etc.
- ✅ **Cross-account access** with proper principal validation

## 🤝 Contributing

Contributions are welcome! This library aims to be the definitive Rust implementation of AWS IAM policy evaluation.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)  
3. Add tests for new functionality
4. Run the test suite (`cargo test`)
5. Check code quality (`cargo clippy`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
      "Action": ["iam:GetAccountPasswordPolicy", "iam:ListVirtualMFADevices"],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:RequestedRegion": "us-east-1"
        }
      }
    }
  ]
}
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
