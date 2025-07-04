# iam-rs

# STILL IN DEVELOPMENT AND VERIFICATION - DO NOT USE YET

# STILL IN DEVELOPMENT AND VERIFICATION - DO NOT USE YET

# STILL IN DEVELOPMENT AND VERIFICATION - DO NOT USE YET

# STILL IN DEVELOPMENT AND VERIFICATION - DO NOT USE YET

# STILL IN DEVELOPMENT AND VERIFICATION - DO NOT USE YET

# STILL IN DEVELOPMENT AND VERIFICATION - DO NOT USE YET

# STILL IN DEVELOPMENT AND VERIFICATION - DO NOT USE YET

[![Crates.io](https://img.shields.io/crates/v/iam-rs.svg)](https://crates.io/crates/iam-rs)
[![Documentation](https://docs.rs/iam-rs/badge.svg)](https://docs.rs/iam-rs)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A complete Rust library for parsing, validating, and evaluating IAM (Identity and Access Management) policies. Provider-agnostic and designed for building flexible authorization systems with full AWS IAM compatibility.

## Features

- 🔒 **Provider-agnostic**: Works with any AWS IAM-compatible JSON-based policy format
- 📝 **Full IAM Support**: Complete implementation of IAM policy including conditions, principals, actions, and resources
- 🏷️ **ARN Validation**: Comprehensive ARN parsing, validation, and wildcard matching
- ⚖️ **Policy Evaluation**: Complete policy evaluation engine with Allow/Deny decisions
- 🎯 **Condition Engine**: Support for all AWS condition operators (String, Numeric, Date, Boolean, IP, ARN, Null)
- 🚀 **Type-safe**: Strong typing with comprehensive enums and structs
- 🔧 **Builder Pattern**: Fluent API for constructing policies programmatically
- 📦 **Serde Integration**: Built-in JSON serialization and deserialization
- ⚡ **Zero Dependencies**: Minimal dependencies (only `serde` and serde-libs)
- 🧪 **Well Tested**: Comprehensive test suite with 72+ tests

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
iam-rs = "0.0.1"
```

## Quick Start

### Policy Evaluation (Authorization)

```rust
use iam_rs::{evaluate_policy, AuthorizationRequest, IAMPolicy, IAMStatement, Effect, Action, Resource, Decision};

// Create a policy
let policy = IAMPolicy::new()
    .add_statement(
        IAMStatement::new(Effect::Allow)
            .with_action(Action::Single("s3:GetObject".to_string()))
            .with_resource(Resource::Single("arn:aws:s3:::my-bucket/*".to_string()))
    );

// Create an authorization request
let request = AuthorizationRequest::simple(
    "arn:aws:iam::123456789012:user/alice",
    "s3:GetObject",
    "arn:aws:s3:::my-bucket/file.txt"
);

// Evaluate the request against the policy
match evaluate_policy(&policy, &request)? {
    Decision::Allow => println!("✓ Access granted"),
    Decision::Deny => println!("✗ Access denied"),
    Decision::NotApplicable => println!("? No applicable policy (implicit deny)"),
}
```

### Creating a Policy

```rust
use iam_rs::{IAMPolicy, IAMStatement, Effect, Action, Resource, Operator};
use serde_json::json;

let policy = IAMPolicy::new()
    .with_id("MyPolicy")
    .add_statement(
        IAMStatement::new(Effect::Allow)
            .with_sid("AllowS3Read")
            .with_action(Action::Single("s3:GetObject".to_string()))
            .with_resource(Resource::Single("arn:aws:s3:::my-bucket/*".to_string()))
            .with_condition(
                Operator::StringEquals,
                "s3:prefix".to_string(),
                json!("uploads/")
            )
    );

// Serialize to JSON
let policy_json = policy.to_json().unwrap();
println!("{}", policy_json);
```

### Parsing from JSON

```rust
use iam_rs::IAMPolicy;

let json_policy = r#"
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::example-bucket/*"
    }
  ]
}
"#;

let policy = IAMPolicy::from_json(json_policy).unwrap();
println!("Policy has {} statements", policy.statement.len());
```

## Core Types

### IAMPolicy

The root policy document containing version, optional ID, and statements.

```rust
use iam_rs::{IAMPolicy, IAMVersion};

let policy = IAMPolicy::new()
    .with_version(IAMVersion::V20121017)
    .with_id("my-policy-id");
```

### IAMStatement

Individual policy statements with effect, principals, actions, resources, and conditions.

```rust
use iam_rs::{IAMStatement, Effect, Action, Resource, Principal};

let statement = IAMStatement::new(Effect::Allow)
    .with_sid("ExampleStatement")
    .with_principal(Principal::Single("arn:aws:iam::123456789012:user/username".to_string()))
    .with_action(Action::Multiple(vec![
        "s3:GetObject".to_string(),
        "s3:PutObject".to_string()
    ]))
    .with_resource(Resource::Single("arn:aws:s3:::my-bucket/*".to_string()));
```

## Policy Evaluation Engine

The library includes a complete policy evaluation engine that implements AWS IAM logic for authorization decisions.

### Simple Evaluation

```rust
use iam_rs::{evaluate_policy, AuthorizationRequest, Decision};

// Simple authorization check
let decision = evaluate_policy(&policy, &request)?;
match decision {
    Decision::Allow => println!("Access granted"),
    Decision::Deny => println!("Access denied"),
    Decision::NotApplicable => println!("No applicable policy"),
}
```

### Advanced Evaluation with Context

```rust
use iam_rs::{PolicyEvaluator, RequestContext, ContextValue, EvaluationOptions};

// Create request context for condition evaluation
let mut context = RequestContext::empty();
context.insert("aws:userid".to_string(), ContextValue::String("alice".to_string()));
context.insert("aws:CurrentTime".to_string(), ContextValue::String("2024-01-15T10:00:00Z".to_string()));

let request = AuthorizationRequest::new(
    "arn:aws:iam::123456789012:user/alice",
    "s3:GetObject",
    "arn:aws:s3:::private-bucket/file.txt",
    context
);

// Advanced evaluation with multiple policies
let evaluator = PolicyEvaluator::with_policies(vec![policy1, policy2])
    .with_options(EvaluationOptions {
        collect_match_details: true,
        stop_on_explicit_deny: true,
        max_statements: 100,
    });

let result = evaluator.evaluate(&request)?;
println!("Decision: {:?}", result.decision);
for statement_match in result.matched_statements {
    println!("Matched: {:?}", statement_match);
}
```

### IAM Logic Support

The evaluation engine properly implements AWS IAM precedence rules:

- **Explicit Deny** always overrides Allow
- **Conditions** must be satisfied for statement to apply
- **Wildcard matching** for actions, resources, and principals
- **Multiple policies** are combined with proper precedence

### ARN (Amazon Resource Name)

Comprehensive ARN parsing, validation, and wildcard matching.

```rust
use iam_rs::Arn;

// Parse an ARN
let arn = Arn::parse("arn:aws:s3:::my-bucket/folder/file.txt")?;
println!("Service: {}", arn.service);
println!("Resource: {}", arn.resource);

// Validate ARN format
assert!(arn.is_valid());

// Wildcard matching
let pattern = "arn:aws:s3:::my-bucket/*";
assert!(arn.matches(pattern)?);

// Extract resource information
if let Some(resource_type) = arn.resource_type() {
    println!("Resource type: {}", resource_type);
}
if let Some(resource_id) = arn.resource_id() {
    println!("Resource ID: {}", resource_id);
}
```

### Advanced Usage

#### ARN Validation and Matching

```rust
use iam_rs::Arn;

// Parse and validate ARNs
let arn = Arn::parse("arn:aws:s3:::my-bucket/uploads/file.txt")?;

// Wildcard pattern matching
let patterns = vec![
    "arn:aws:s3:::my-bucket/*",           // ✓ Matches
    "arn:aws:s3:::my-bucket/uploads/*",   // ✓ Matches
    "arn:aws:s3:::other-bucket/*",        // ✗ No match
    "arn:aws:s3:::my-bucket/*/file.txt",  // ✓ Matches
    "arn:aws:s3:::my-bucket/uploads/file.???", // ✓ Matches
];

for pattern in patterns {
    if arn.matches(pattern)? {
        println!("✓ ARN matches pattern: {}", pattern);
    } else {
        println!("✗ ARN does not match pattern: {}", pattern);
    }
}

// Extract resource components
if let Some(resource_type) = arn.resource_type() {
    println!("Resource type: {}", resource_type); // "my-bucket"
}
if let Some(resource_id) = arn.resource_id() {
    println!("Resource ID: {}", resource_id);     // "uploads/file.txt"
}
```

#### Multiple Actions and Resources

```rust
use iam_rs::{Action, Resource};

let actions = Action::Multiple(vec![
    "s3:GetObject".to_string(),
    "s3:PutObject".to_string(),
    "s3:DeleteObject".to_string(),
]);

let resources = Resource::Multiple(vec![
    "arn:aws:s3:::bucket1/*".to_string(),
    "arn:aws:s3:::bucket2/*".to_string(),
]);
```

#### Complex Conditions

```rust
use iam_rs::{Operator};
use serde_json::json;

let statement = IAMStatement::new(Effect::Allow)
    .with_action(Action::Single("s3:GetObject".to_string()))
    .with_resource(Resource::Single("arn:aws:s3:::secure-bucket/*".to_string()))
    .with_condition(
        Operator::StringEquals,
        "aws:username".to_string(),
        json!("${aws:userid}")
    )
    .with_condition(
        Operator::DateGreaterThan,
        "aws:CurrentTime".to_string(),
        json!("2024-01-01T00:00:00Z")
    );
```

#### Principal Types

```rust
use iam_rs::Principal;
use std::collections::HashMap;

// Single principal
let single = Principal::Single("arn:aws:iam::123456789012:user/alice".to_string());

// Multiple principals
let multiple = Principal::Multiple(vec![
    "arn:aws:iam::123456789012:user/alice".to_string(),
    "arn:aws:iam::123456789012:user/bob".to_string(),
]);

// Wildcard (anyone)
let wildcard = Principal::Wildcard;

// Service principal with mapping
let mut service_map = HashMap::new();
service_map.insert("Service".to_string(), json!("lambda.amazonaws.com"));
let service = Principal::Mapped(service_map);
```

## Examples

The library includes comprehensive examples demonstrating all features:

### Running Examples

```bash
# ARN parsing and validation
cargo run --example arn_demo

# Policy validation
cargo run --example validation_demo

# Policy evaluation engine
cargo run --example evaluation_demo
```

### Example Scenarios

The evaluation demo showcases:

- ✅ Simple Allow/Deny policies
- ✅ Wildcard action and resource matching
- ✅ Condition-based authorization (String, Numeric, Date)
- ✅ Explicit deny precedence (IAM compliance)
- ✅ Multiple policy evaluation
- ✅ Detailed evaluation with match information
- ✅ Resource pattern matching
- ✅ Context-aware authorization

## JSON Schema Compatibility

This library follows the standard IAM policy JSON schema and is compatible with:

- AWS IAM policies
- AWS resource-based policies
- Custom authorization systems using IAM-like policies

Example of a complete policy:

```json
{
  "Version": "2012-10-17",
  "Id": "ExamplePolicy",
  "Statement": [
    {
      "Sid": "AllowUserToSeeAccountConfigurationInConsole",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:user/username"
      },
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

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
