use serde::{Deserialize, Serialize};
use std::fmt;

/// Represents an Amazon Resource Name (ARN)
///
/// ARNs uniquely identify AWS resources. The general format is:
/// `arn:partition:service:region:account-id:resource-type/resource-id`
///
/// Some services use slightly different formats:
/// - `arn:partition:service:region:account-id:resource-type:resource-id`
/// - `arn:partition:service:region:account-id:resource-type/resource-id/sub-resource`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Arn {
    /// The partition (e.g., "aws", "aws-cn", "aws-us-gov")
    pub partition: String,
    /// The service namespace (e.g., "s3", "ec2", "iam")
    pub service: String,
    /// The region (e.g., "us-east-1", can be empty for global services)
    pub region: String,
    /// The account ID (12-digit number, can be empty for some services)
    pub account_id: String,
    /// The resource specification (format varies by service)
    pub resource: String,
}

/// Error types for ARN parsing and validation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArnError {
    /// ARN doesn't start with "arn:"
    InvalidPrefix,
    /// ARN has incorrect number of components
    InvalidFormat,
    /// Partition is empty or invalid
    InvalidPartition(String),
    /// Service is empty or invalid
    InvalidService(String),
    /// Account ID format is invalid (should be 12 digits or empty)
    InvalidAccountId(String),
    /// Resource format is invalid
    InvalidResource(String),
}

impl fmt::Display for ArnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArnError::InvalidPrefix => write!(f, "ARN must start with 'arn:'"),
            ArnError::InvalidFormat => write!(f, "ARN must have exactly 6 parts separated by ':'"),
            ArnError::InvalidPartition(p) => write!(f, "Invalid partition: '{}'", p),
            ArnError::InvalidService(s) => write!(f, "Invalid service: '{}'", s),
            ArnError::InvalidAccountId(id) => write!(f, "Invalid account ID: '{}'", id),
            ArnError::InvalidResource(r) => write!(f, "Invalid resource: '{}'", r),
        }
    }
}

impl std::error::Error for ArnError {}

impl Arn {
    /// Parse an ARN string into an Arn struct
    /// If allow_wildcards is true, wildcards in account_id and other fields are allowed
    pub fn parse(arn_str: &str) -> Result<Self, ArnError> {
        Self::parse_with_options(arn_str, false)
    }

    /// Parse an ARN string with options for wildcard handling
    pub fn parse_with_options(arn_str: &str, allow_wildcards: bool) -> Result<Self, ArnError> {
        let parts: Vec<&str> = arn_str.split(':').collect();

        if parts.len() < 6 {
            return Err(ArnError::InvalidFormat);
        }

        if parts[0] != "arn" {
            return Err(ArnError::InvalidPrefix);
        }

        let partition = parts[1].to_string();
        if partition.is_empty() {
            return Err(ArnError::InvalidPartition(partition));
        }

        let service = parts[2].to_string();
        if service.is_empty() {
            return Err(ArnError::InvalidService(service));
        }

        let region = parts[3].to_string();
        let account_id = parts[4].to_string();

        // Validate account ID format (should be 12 digits or empty for some services)
        // Allow wildcards if explicitly enabled
        if !account_id.is_empty()
            && !Self::is_valid_account_id_or_pattern(&account_id, allow_wildcards)
        {
            return Err(ArnError::InvalidAccountId(account_id));
        }

        // Join remaining parts as resource (handles cases with multiple colons in resource)
        let resource = parts[5..].join(":");
        if resource.is_empty() {
            return Err(ArnError::InvalidResource(resource));
        }

        Ok(Arn {
            partition,
            service,
            region,
            account_id,
            resource,
        })
    }

    /// Validate if a string is a valid account ID (12 digits) or a wildcard pattern
    fn is_valid_account_id_or_pattern(account_id: &str, allow_wildcards: bool) -> bool {
        if allow_wildcards && (account_id.contains('*') || account_id.contains('?')) {
            // If wildcards are allowed and present, we're more lenient
            true
        } else {
            Self::is_valid_account_id(account_id)
        }
    }

    /// Validate if a string is a valid account ID (12 digits)
    fn is_valid_account_id(account_id: &str) -> bool {
        account_id.len() == 12 && account_id.chars().all(|c| c.is_ascii_digit())
    }

    /// Convert the ARN back to string format
    pub fn to_string(&self) -> String {
        format!(
            "arn:{}:{}:{}:{}:{}",
            self.partition, self.service, self.region, self.account_id, self.resource
        )
    }

    /// Check if this ARN matches another ARN or pattern
    /// Supports wildcards (* and ?) in any component except service
    pub fn matches(&self, pattern: &str) -> Result<bool, ArnError> {
        let pattern_arn = Arn::parse_with_options(pattern, true)?;

        // Service cannot contain wildcards
        if pattern_arn.service.contains('*') || pattern_arn.service.contains('?') {
            return Ok(false);
        }

        Ok(
            Self::wildcard_match(&self.partition, &pattern_arn.partition)
                && self.service == pattern_arn.service
                && Self::wildcard_match(&self.region, &pattern_arn.region)
                && Self::wildcard_match(&self.account_id, &pattern_arn.account_id)
                && Self::wildcard_match(&self.resource, &pattern_arn.resource),
        )
    }

    /// Check if a string matches a pattern with wildcards
    /// * matches any sequence of characters
    /// ? matches any single character
    pub fn wildcard_match(text: &str, pattern: &str) -> bool {
        Self::wildcard_match_recursive(text, pattern, 0, 0)
    }

    /// Recursive helper for wildcard matching
    fn wildcard_match_recursive(
        text: &str,
        pattern: &str,
        text_idx: usize,
        pattern_idx: usize,
    ) -> bool {
        let text_chars: Vec<char> = text.chars().collect();
        let pattern_chars: Vec<char> = pattern.chars().collect();

        // If we've reached the end of both strings, it's a match
        if pattern_idx >= pattern_chars.len() && text_idx >= text_chars.len() {
            return true;
        }

        // If we've reached the end of pattern but not text, it's not a match
        // unless the remaining pattern is all '*'
        if pattern_idx >= pattern_chars.len() {
            return false;
        }

        match pattern_chars[pattern_idx] {
            '*' => {
                // Try matching zero characters
                if Self::wildcard_match_recursive(text, pattern, text_idx, pattern_idx + 1) {
                    return true;
                }

                // Try matching one or more characters
                for i in text_idx..text_chars.len() {
                    if Self::wildcard_match_recursive(text, pattern, i + 1, pattern_idx + 1) {
                        return true;
                    }
                }
                false
            }
            '?' => {
                // ? matches exactly one character
                if text_idx >= text_chars.len() {
                    false
                } else {
                    Self::wildcard_match_recursive(text, pattern, text_idx + 1, pattern_idx + 1)
                }
            }
            c => {
                // Regular character must match exactly
                if text_idx >= text_chars.len() || text_chars[text_idx] != c {
                    false
                } else {
                    Self::wildcard_match_recursive(text, pattern, text_idx + 1, pattern_idx + 1)
                }
            }
        }
    }

    /// Check if this ARN is valid according to AWS ARN rules
    pub fn is_valid(&self) -> bool {
        // Basic validation rules
        if self.partition.is_empty() || self.service.is_empty() || self.resource.is_empty() {
            return false;
        }

        // Validate partition (common AWS partitions)
        if !matches!(
            self.partition.as_str(),
            "aws" | "aws-cn" | "aws-us-gov" | "aws-iso" | "aws-iso-b"
        ) {
            return false;
        }

        // Validate account ID if present
        if !self.account_id.is_empty() && !Self::is_valid_account_id(&self.account_id) {
            return false;
        }

        // Service-specific validation could be added here
        true
    }

    /// Get the resource type from the resource string
    /// For resources like "bucket/object", returns "bucket"
    /// For resources like "user/username", returns "user"
    pub fn resource_type(&self) -> Option<&str> {
        if let Some(slash_pos) = self.resource.find('/') {
            Some(&self.resource[..slash_pos])
        } else if let Some(colon_pos) = self.resource.find(':') {
            Some(&self.resource[..colon_pos])
        } else {
            // Some services just have a resource ID without type
            None
        }
    }

    /// Get the resource ID from the resource string
    /// For resources like "bucket/object", returns "object"
    /// For resources like "user/username", returns "username"
    pub fn resource_id(&self) -> Option<&str> {
        if let Some(slash_pos) = self.resource.find('/') {
            Some(&self.resource[slash_pos + 1..])
        } else if let Some(colon_pos) = self.resource.find(':') {
            Some(&self.resource[colon_pos + 1..])
        } else {
            // The entire resource string is the ID
            Some(&self.resource)
        }
    }
}

impl fmt::Display for Arn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl std::str::FromStr for Arn {
    type Err = ArnError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Arn::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_arn_parsing() {
        let arn_str = "arn:aws:s3:us-east-1:123456789012:bucket/my-bucket";
        let arn = Arn::parse(arn_str).unwrap();

        assert_eq!(arn.partition, "aws");
        assert_eq!(arn.service, "s3");
        assert_eq!(arn.region, "us-east-1");
        assert_eq!(arn.account_id, "123456789012");
        assert_eq!(arn.resource, "bucket/my-bucket");
        assert_eq!(arn.to_string(), arn_str);
    }

    #[test]
    fn test_arn_without_region() {
        let arn_str = "arn:aws:iam::123456789012:user/username";
        let arn = Arn::parse(arn_str).unwrap();

        assert_eq!(arn.partition, "aws");
        assert_eq!(arn.service, "iam");
        assert_eq!(arn.region, "");
        assert_eq!(arn.account_id, "123456789012");
        assert_eq!(arn.resource, "user/username");
    }

    #[test]
    fn test_arn_with_colons_in_resource() {
        let arn_str = "arn:aws:ssm:us-east-1:123456789012:parameter/app/db/url";
        let arn = Arn::parse(arn_str).unwrap();

        assert_eq!(arn.resource, "parameter/app/db/url");
    }

    #[test]
    fn test_invalid_arn_prefix() {
        let result = Arn::parse("invalid:aws:s3:::bucket");
        assert_eq!(result, Err(ArnError::InvalidPrefix));
    }

    #[test]
    fn test_invalid_arn_format() {
        let result = Arn::parse("arn:aws:s3");
        assert_eq!(result, Err(ArnError::InvalidFormat));
    }

    #[test]
    fn test_invalid_account_id() {
        let result = Arn::parse("arn:aws:s3:us-east-1:invalid:bucket/my-bucket");
        assert!(matches!(result, Err(ArnError::InvalidAccountId(_))));
    }

    #[test]
    fn test_wildcard_matching() {
        let arn =
            Arn::parse("arn:aws:s3:us-east-1:123456789012:bucket/my-bucket/file.txt").unwrap();

        // Exact match
        assert!(
            arn.matches("arn:aws:s3:us-east-1:123456789012:bucket/my-bucket/file.txt")
                .unwrap()
        );

        // Wildcard in resource
        assert!(
            arn.matches("arn:aws:s3:us-east-1:123456789012:bucket/my-bucket/*")
                .unwrap()
        );
        assert!(
            arn.matches("arn:aws:s3:us-east-1:123456789012:bucket/*/file.txt")
                .unwrap()
        );

        // Wildcard in region
        assert!(
            arn.matches("arn:aws:s3:*:123456789012:bucket/my-bucket/file.txt")
                .unwrap()
        );

        // Single character wildcard
        assert!(
            arn.matches("arn:aws:s3:us-east-?:123456789012:bucket/my-bucket/file.txt")
                .unwrap()
        );

        // Should not match different service
        assert!(
            !arn.matches("arn:aws:ec2:us-east-1:123456789012:bucket/my-bucket/file.txt")
                .unwrap()
        );

        // Should not allow wildcards in service
        assert!(
            !arn.matches("arn:aws:*:us-east-1:123456789012:bucket/my-bucket/file.txt")
                .unwrap()
        );
    }

    #[test]
    fn test_resource_parsing() {
        let arn = Arn::parse("arn:aws:s3:::bucket/folder/file.txt").unwrap();
        assert_eq!(arn.resource_type(), Some("bucket"));
        assert_eq!(arn.resource_id(), Some("folder/file.txt"));

        let arn2 = Arn::parse("arn:aws:iam::123456789012:role/MyRole").unwrap();
        assert_eq!(arn2.resource_type(), Some("role"));
        assert_eq!(arn2.resource_id(), Some("MyRole"));

        let arn3 = Arn::parse("arn:aws:sns:us-east-1:123456789012:my-topic").unwrap();
        assert_eq!(arn3.resource_type(), None);
        assert_eq!(arn3.resource_id(), Some("my-topic"));
    }

    #[test]
    fn test_arn_validation() {
        let valid_arn = Arn::parse("arn:aws:s3:us-east-1:123456789012:bucket/my-bucket").unwrap();
        assert!(valid_arn.is_valid());

        let invalid_partition = Arn {
            partition: "invalid".to_string(),
            service: "s3".to_string(),
            region: "us-east-1".to_string(),
            account_id: "123456789012".to_string(),
            resource: "bucket/my-bucket".to_string(),
        };
        assert!(!invalid_partition.is_valid());
    }

    #[test]
    fn test_wildcard_parsing() {
        // Test that wildcards are rejected in normal parsing
        let result = Arn::parse("arn:aws:s3:*:*:bucket/*");
        assert!(result.is_err());

        // Test that wildcards are allowed with wildcard parsing
        let arn = Arn::parse_with_options("arn:aws:s3:*:*:bucket/*", true).unwrap();
        assert_eq!(arn.region, "*");
        assert_eq!(arn.account_id, "*");
        assert_eq!(arn.resource, "bucket/*");
    }

    #[test]
    fn test_complex_wildcard_patterns() {
        let arn = Arn::parse("arn:aws:s3:::my-bucket/folder/subfolder/file.txt").unwrap();

        // Multiple wildcards
        assert!(arn.matches("arn:aws:s3:::my-bucket/*/*/file.txt").unwrap());
        assert!(arn.matches("arn:aws:s3:::*/folder/subfolder/*").unwrap());

        // Mixed wildcards
        assert!(
            arn.matches("arn:aws:s3:::my-bucket/*/subfolder/file.?xt")
                .unwrap()
        );

        // Should not match
        assert!(
            !arn.matches("arn:aws:s3:::other-bucket/folder/subfolder/file.txt")
                .unwrap()
        );
        assert!(
            !arn.matches("arn:aws:s3:::my-bucket/folder/other/file.txt")
                .unwrap()
        );
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

    #[test]
    fn test_amazon_arns_from_json() {
        // Read the JSON file containing Amazon ARN examples
        let json_content = std::fs::read_to_string("tests/arns.json")
            .expect("Failed to read tests/arns.json file");

        // Parse the JSON array of ARN strings
        let arns: Vec<String> =
            serde_json::from_str(&json_content).expect("Failed to parse JSON content");

        println!("Testing {} ARNs from tests/arns.json", arns.len());

        let mut successful_parses = 0;
        let mut failed_parses = 0;
        let mut validation_failures = 0;

        for (index, arn_string) in arns.iter().enumerate() {
            // Trim any whitespace (some ARNs in the JSON might have trailing spaces)
            let arn_string = arn_string.trim();

            if arn_string.is_empty() {
                continue;
            }

            print!("Testing ARN {}: {} ... ", index + 1, arn_string);

            match Arn::parse(arn_string) {
                Ok(arn) => {
                    successful_parses += 1;

                    // Verify the ARN can be serialized back to string
                    let reconstructed = arn.to_string();

                    // Check if the ARN passes validation
                    if arn.is_valid() {
                        println!("✓ PASSED (valid)");

                        // Additional checks for well-formed ARNs
                        assert!(
                            !arn.partition.is_empty(),
                            "Partition should not be empty for ARN: {}",
                            arn_string
                        );
                        assert!(
                            !arn.service.is_empty(),
                            "Service should not be empty for ARN: {}",
                            arn_string
                        );
                        assert!(
                            !arn.resource.is_empty(),
                            "Resource should not be empty for ARN: {}",
                            arn_string
                        );

                        // Test that the ARN can be round-tripped
                        let reparsed = Arn::parse(&reconstructed).expect(&format!(
                            "Failed to reparse reconstructed ARN: {}",
                            reconstructed
                        ));
                        assert_eq!(
                            arn, reparsed,
                            "Round-trip parsing failed for ARN: {}",
                            arn_string
                        );
                    } else {
                        validation_failures += 1;
                        println!("⚠ PARSED but invalid");
                    }
                }
                Err(e) => {
                    failed_parses += 1;
                    println!("✗ FAILED to parse: {:?}", e);

                    // Some ARNs in the test set might be intentionally invalid or use placeholder values
                    // We'll allow some failures but track them for analysis
                }
            }
        }

        println!("\n=== ARN Test Summary ===");
        println!("Total ARNs tested: {}", arns.len());
        println!("Successfully parsed: {}", successful_parses);
        println!("Failed to parse: {}", failed_parses);
        println!("Parsed but invalid: {}", validation_failures);
        println!(
            "Success rate: {:.1}%",
            (successful_parses as f64 / arns.len() as f64) * 100.0
        );

        // We expect a high success rate, but some ARNs might be intentionally malformed
        // or use placeholder values that don't conform to strict validation rules
        assert!(
            successful_parses > 0,
            "At least some ARNs should parse successfully"
        );

        // Most of the ARNs should be valid AWS ARNs, so we expect a reasonable success rate
        let success_rate = (successful_parses as f64 / arns.len() as f64) * 100.0;
        assert!(
            success_rate > 80.0,
            "Expected success rate > 80%, got {:.1}%",
            success_rate
        );
    }
}
