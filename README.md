# iam-rs

[![Crates.io](https://img.shields.io/crates/v/iam-rs.svg)](https://crates.io/crates/iam-rs)
[![Documentation](https://docs.rs/iam-rs/badge.svg)](https://docs.rs/iam-rs)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Rust library for parsing and evaluating IAM (Identity and Access Management) policies. Provider-agnostic and designed for building flexible authorization systems.

## Features

- 🔒 **Provider-agnostic**: Works with any AWS IAM-compatible JSON-based policy format
- 📝 **Full IAM Support**: Complete implementation of IAM policy including conditions, principals, actions, and resources
- 🚀 **Type-safe**: Strong typing with comprehensive enums and structs
- 🔧 **Builder Pattern**: Fluent API for constructing policies programmatically
- 📦 **Serde Integration**: Built-in JSON serialization and deserialization
- ⚡ **Zero Dependencies**: Minimal dependencies (only `serde` and serde-libs)
- 🧪 **Well Tested**: Comprehensive test suite

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
iam-rs = "0.0.1"
```

## Quick Start

### Creating a Policy

```rust
use iam_rs::{IAMPolicy, IAMStatement, Effect, Action, Resource};
use serde_json::json;

let policy = IAMPolicy::new()
    .with_id("MyPolicy")
    .add_statement(
        IAMStatement::new(Effect::Allow)
            .with_sid("AllowS3Read")
            .with_action(Action::Single("s3:GetObject".to_string()))
            .with_resource(Resource::Single("arn:aws:s3:::my-bucket/*".to_string()))
            .with_condition(
                "StringEquals".to_string(),
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

### Advanced Usage

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
use serde_json::json;

let statement = IAMStatement::new(Effect::Allow)
    .with_action(Action::Single("s3:GetObject".to_string()))
    .with_resource(Resource::Single("arn:aws:s3:::secure-bucket/*".to_string()))
    .with_condition(
        "StringEquals".to_string(),
        "aws:username".to_string(),
        json!("${aws:userid}")
    )
    .with_condition(
        "DateGreaterThan".to_string(),
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
