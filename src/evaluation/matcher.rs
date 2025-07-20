use crate::{Arn, ArnError};
use std::collections::HashSet;

/// Advanced ARN matching capabilities for policy evaluation
#[derive(Debug, Clone)]
pub struct ArnMatcher {
    /// Pre-compiled patterns for efficient matching
    patterns: Vec<ArnPattern>,
}

/// Internal representation of an ARN pattern with pre-computed matching data
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
struct ArnPattern {
    /// The original pattern string
    pattern: String,
    /// Parsed ARN (with wildcards allowed)
    arn: Arn,
    /// Pre-computed flags for optimization
    has_wildcards: bool,
    /// Component-level wildcard flags
    partition_wildcard: bool,
    service_wildcard: bool,
    region_wildcard: bool,
    account_wildcard: bool,
    resource_wildcard: bool,
}

impl ArnMatcher {
    /// Create a new ARN matcher with a set of patterns
    ///
    /// # Errors
    ///
    /// Returns `ArnError` if any of the provided patterns cannot be parsed as valid ARNs.
    pub fn new<I>(patterns: I) -> Result<Self, ArnError>
    where
        I: IntoIterator<Item = String>,
    {
        let mut compiled_patterns = Vec::new();

        for pattern in patterns {
            let arn_pattern = ArnPattern::compile(&pattern)?;
            compiled_patterns.push(arn_pattern);
        }

        Ok(ArnMatcher {
            patterns: compiled_patterns,
        })
    }

    /// Create a matcher from a single pattern
    ///
    /// # Errors
    ///
    /// Returns `ArnError` if the pattern cannot be parsed as a valid ARN.
    pub fn from_pattern(pattern: &str) -> Result<Self, ArnError> {
        Self::new(vec![pattern.to_string()])
    }

    /// Check if any pattern matches the given ARN
    ///
    /// # Errors
    ///
    /// Returns `ArnError` if the ARN cannot be parsed or if pattern matching fails.
    pub fn matches(&self, arn: &Arn) -> Result<bool, ArnError> {
        for pattern in &self.patterns {
            if pattern.matches(arn) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Check if any pattern matches the given parsed ARN
    #[must_use]
    pub fn matches_arn(&self, arn: &Arn) -> bool {
        self.patterns.iter().any(|pattern| pattern.matches(arn))
    }

    /// Get all patterns that match the given ARN
    ///
    /// # Errors
    ///
    /// Returns `ArnError` if the ARN cannot be parsed.
    pub fn matching_patterns(&self, arn: &str) -> Result<Vec<&str>, ArnError> {
        let target_arn = Arn::parse(arn)?;

        Ok(self
            .patterns
            .iter()
            .filter(|pattern| pattern.matches(&target_arn))
            .map(|pattern| pattern.pattern.as_str())
            .collect())
    }

    /// Find ARNs from a collection that match any of our patterns
    ///
    /// # Errors
    ///
    /// Returns `ArnError` if any ARN in the collection cannot be parsed.
    pub fn filter_matching<'a>(&self, arns: &'a [Arn]) -> Result<Vec<&'a Arn>, ArnError> {
        let mut matching = Vec::new();

        for arn in arns {
            if self.matches(arn)? {
                matching.push(arn);
            }
        }

        Ok(matching)
    }

    /// Check if this matcher would match everything (contains "*")
    #[must_use]
    pub fn matches_all(&self) -> bool {
        self.patterns.iter().any(|p| p.pattern == "*")
    }

    /// Get the list of patterns this matcher uses
    #[must_use]
    pub fn patterns(&self) -> Vec<&str> {
        self.patterns.iter().map(|p| p.pattern.as_str()).collect()
    }

    /// Create a matcher that combines multiple matchers (OR logic)
    #[must_use]
    pub fn combine(matchers: Vec<ArnMatcher>) -> Self {
        let mut all_patterns = Vec::new();

        for matcher in matchers {
            all_patterns.extend(matcher.patterns);
        }

        ArnMatcher {
            patterns: all_patterns,
        }
    }
}

impl ArnPattern {
    /// Compile a pattern string into an optimized pattern
    fn compile(pattern: &str) -> Result<Self, ArnError> {
        // Handle the special case of "*" (matches everything)
        if pattern == "*" {
            return Ok(ArnPattern {
                pattern: pattern.to_string(),
                arn: Arn {
                    partition: "*".to_string(),
                    service: "*".to_string(),
                    region: "*".to_string(),
                    account_id: "*".to_string(),
                    resource: "*".to_string(),
                },
                has_wildcards: true,
                partition_wildcard: true,
                service_wildcard: true,
                region_wildcard: true,
                account_wildcard: true,
                resource_wildcard: true,
            });
        }

        let arn = Arn::parse(pattern)?;
        let has_wildcards = pattern.contains('*') || pattern.contains('?');

        Ok(ArnPattern {
            pattern: pattern.to_string(),
            partition_wildcard: arn.partition.contains('*') || arn.partition.contains('?'),
            service_wildcard: arn.service.contains('*') || arn.service.contains('?'),
            region_wildcard: arn.region.contains('*') || arn.region.contains('?'),
            account_wildcard: arn.account_id.contains('*') || arn.account_id.contains('?'),
            resource_wildcard: arn.resource.contains('*') || arn.resource.contains('?'),
            arn,
            has_wildcards,
        })
    }

    /// Check if this pattern matches the given ARN
    fn matches(&self, target: &Arn) -> bool {
        // Special case: "*" matches everything
        if self.pattern == "*" {
            return true;
        }

        // For performance, check exact matches first if no wildcards
        if !self.has_wildcards {
            return self.arn.partition == target.partition
                && self.arn.service == target.service
                && self.arn.region == target.region
                && self.arn.account_id == target.account_id
                && self.arn.resource == target.resource;
        }

        // Service cannot contain wildcards for security reasons
        if self.service_wildcard {
            return false;
        }

        // Check each component
        Self::match_component(&target.partition, &self.arn.partition, self.partition_wildcard)
            && target.service == self.arn.service  // Service must match exactly
            && Self::match_component(&target.region, &self.arn.region, self.region_wildcard)
            && Self::match_component(&target.account_id, &self.arn.account_id, self.account_wildcard)
            && Self::match_component(&target.resource, &self.arn.resource, self.resource_wildcard)
    }

    /// Match a single component, using wildcards if needed
    fn match_component(target: &str, pattern: &str, has_wildcard: bool) -> bool {
        if has_wildcard {
            Arn::wildcard_match(target, pattern)
        } else {
            target == pattern
        }
    }
}

/// ARN builder for creating ARNs programmatically
#[derive(Debug, Clone, Default)]
pub struct ArnBuilder {
    partition: Option<String>,
    service: Option<String>,
    region: Option<String>,
    account_id: Option<String>,
    resource_type: Option<String>,
    resource_id: Option<String>,
}

impl ArnBuilder {
    /// Create a new ARN builder
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the partition (e.g., "aws", "aws-cn")
    #[must_use]
    pub fn partition<S: Into<String>>(mut self, partition: S) -> Self {
        self.partition = Some(partition.into());
        self
    }

    /// Set the service (e.g., "s3", "ec2", "iam")
    #[must_use]
    pub fn service<S: Into<String>>(mut self, service: S) -> Self {
        self.service = Some(service.into());
        self
    }

    /// Set the region (e.g., "us-east-1")
    #[must_use]
    pub fn region<S: Into<String>>(mut self, region: S) -> Self {
        self.region = Some(region.into());
        self
    }

    /// Set the account ID
    #[must_use]
    pub fn account_id<S: Into<String>>(mut self, account_id: S) -> Self {
        self.account_id = Some(account_id.into());
        self
    }

    /// Set the resource type and ID separately
    #[must_use]
    pub fn resource<S: Into<String>>(mut self, resource_type: S, resource_id: S) -> Self {
        self.resource_type = Some(resource_type.into());
        self.resource_id = Some(resource_id.into());
        self
    }

    /// Set the full resource string
    #[must_use]
    pub fn resource_string<S: Into<String>>(mut self, resource: S) -> Self {
        let resource_str = resource.into();
        if let Some(slash_pos) = resource_str.find('/') {
            self.resource_type = Some(resource_str[..slash_pos].to_string());
            self.resource_id = Some(resource_str[slash_pos + 1..].to_string());
        } else if let Some(colon_pos) = resource_str.find(':') {
            self.resource_type = Some(resource_str[..colon_pos].to_string());
            self.resource_id = Some(resource_str[colon_pos + 1..].to_string());
        } else {
            self.resource_type = None;
            self.resource_id = Some(resource_str);
        }
        self
    }

    /// Build the ARN
    ///
    /// # Errors
    ///
    /// Returns `ArnError` if the ARN cannot be built due to missing components.
    pub fn build(self) -> Result<Arn, ArnError> {
        let partition = self.partition.unwrap_or_else(|| "aws".to_string());
        let service = self
            .service
            .ok_or_else(|| ArnError::InvalidService("Service is required".to_string()))?;
        let region = self.region.unwrap_or_default();
        let account_id = self.account_id.unwrap_or_default();

        let resource = match (self.resource_type, self.resource_id) {
            (Some(rt), Some(ri)) => format!("{rt}/{ri}"),
            (None, Some(ri)) => ri,
            (Some(rt), None) => rt,
            (None, None) => {
                return Err(ArnError::InvalidResource(
                    "Resource is required".to_string(),
                ));
            }
        };

        Ok(Arn {
            partition,
            service,
            region,
            account_id,
            resource,
        })
    }

    /// Build the ARN and convert to string
    ///
    /// # Errors
    ///
    /// Returns `ArnError` if the ARN cannot be built due to missing components.
    pub fn build_string(self) -> Result<String, ArnError> {
        Ok(self.build()?.to_string())
    }
}

/// ARN set operations for working with collections of ARNs
pub struct ArnSet {
    arns: HashSet<String>,
}

impl ArnSet {
    /// Create a new ARN set
    #[must_use]
    pub fn new() -> Self {
        Self {
            arns: HashSet::new(),
        }
    }

    /// Create from a collection of ARNs
    ///
    /// # Errors
    ///
    /// Returns `ArnError` if any of the provided ARNs are invalid.
    pub fn from_arns<I>(arns: I) -> Result<Self, ArnError>
    where
        I: IntoIterator<Item = String>,
    {
        let mut set = Self::new();
        for arn in arns {
            set.add(arn)?;
        }
        Ok(set)
    }

    /// Add an ARN to the set (validates it first)
    ///
    /// # Errors
    ///
    /// Returns `ArnError` if the ARN is invalid.
    pub fn add(&mut self, arn: String) -> Result<(), ArnError> {
        // Validate the ARN
        Arn::parse(&arn)?;
        self.arns.insert(arn);
        Ok(())
    }

    /// Check if the set contains an ARN
    #[must_use]
    pub fn contains(&self, arn: &str) -> bool {
        self.arns.contains(arn)
    }

    /// Get ARNs that match any of the given patterns
    ///
    /// # Errors
    ///
    /// Returns `ArnError` if any ARN in the set is invalid.
    pub fn filter_by_patterns(&self, patterns: &[String]) -> Result<Vec<&str>, ArnError> {
        let matcher = ArnMatcher::new(patterns.iter().cloned())?;

        let mut matching = Vec::new();
        for arn in &self.arns {
            if matcher.matches(&Arn::parse(arn)?)? {
                matching.push(arn.as_str());
            }
        }

        Ok(matching)
    }

    /// Get all ARNs for a specific service
    ///
    /// # Errors
    ///
    /// Returns `ArnError` if any ARN in the set is invalid.
    pub fn filter_by_service(&self, service: &str) -> Result<Vec<&str>, ArnError> {
        let mut matching = Vec::new();

        for arn_str in &self.arns {
            let arn = Arn::parse(arn_str)?;
            if arn.service == service {
                matching.push(arn_str.as_str());
            }
        }

        Ok(matching)
    }

    /// Get all ARNs for a specific account
    ///
    /// # Errors
    ///
    /// Returns `ArnError` if any ARN in the set is invalid.
    pub fn filter_by_account(&self, account_id: &str) -> Result<Vec<&str>, ArnError> {
        let mut matching = Vec::new();

        for arn_str in &self.arns {
            let arn = Arn::parse(arn_str)?;
            if arn.account_id == account_id {
                matching.push(arn_str.as_str());
            }
        }

        Ok(matching)
    }

    /// Get the number of ARNs in the set
    #[must_use]
    pub fn len(&self) -> usize {
        self.arns.len()
    }

    /// Check if the set is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.arns.is_empty()
    }

    /// Get all ARNs as a vector
    #[must_use]
    pub fn to_vec(&self) -> Vec<&str> {
        self.arns.iter().map(std::string::String::as_str).collect()
    }
}

impl Default for ArnSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arn_matcher_exact_match() {
        let matcher = ArnMatcher::from_pattern("arn:aws:s3:::my-bucket/*").unwrap();

        assert!(
            matcher
                .matches(&Arn::parse("arn:aws:s3:::my-bucket/file.txt").unwrap())
                .unwrap()
        );
        assert!(
            matcher
                .matches(&Arn::parse("arn:aws:s3:::my-bucket/folder/file.txt").unwrap())
                .unwrap()
        );
        assert!(
            !matcher
                .matches(&Arn::parse("arn:aws:s3:::other-bucket/file.txt").unwrap())
                .unwrap()
        );
        assert!(
            !matcher
                .matches(
                    &Arn::parse("arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0")
                        .unwrap()
                )
                .unwrap()
        );
    }

    #[test]
    fn test_arn_matcher_wildcard() {
        let matcher = ArnMatcher::from_pattern("arn:aws:s3:*:*:*").unwrap();

        assert!(
            matcher
                .matches(&Arn::parse("arn:aws:s3:::my-bucket/file.txt").unwrap())
                .unwrap()
        );
        assert!(
            matcher
                .matches(&Arn::parse("arn:aws:s3:us-east-1:123456789012:bucket/my-bucket").unwrap())
                .unwrap()
        );
        assert!(
            !matcher
                .matches(
                    &Arn::parse("arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0")
                        .unwrap()
                )
                .unwrap()
        );
    }

    #[test]
    fn test_arn_matcher_multiple_patterns() {
        let patterns = vec![
            "arn:aws:s3:::my-bucket/*".to_string(),
            "arn:aws:ec2:*:*:instance/*".to_string(),
        ];
        let matcher = ArnMatcher::new(patterns).unwrap();

        assert!(
            matcher
                .matches(&Arn::parse("arn:aws:s3:::my-bucket/file.txt").unwrap())
                .unwrap()
        );
        assert!(
            matcher
                .matches(
                    &Arn::parse("arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0")
                        .unwrap()
                )
                .unwrap()
        );
        assert!(
            !matcher
                .matches(&Arn::parse("arn:aws:iam::123456789012:user/username").unwrap())
                .unwrap()
        );
    }

    #[test]
    fn test_arn_matcher_star_matches_all() {
        let matcher = ArnMatcher::from_pattern("*").unwrap();

        assert!(matcher.matches_all());
        assert!(
            matcher
                .matches(&Arn::parse("arn:aws:s3:::my-bucket/file.txt").unwrap())
                .unwrap()
        );
        assert!(
            matcher
                .matches(
                    &Arn::parse("arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0")
                        .unwrap()
                )
                .unwrap()
        );
        assert!(
            matcher
                .matches(&Arn::parse("arn:aws:iam::123456789012:user/username").unwrap())
                .unwrap()
        );
    }

    #[test]
    fn test_arn_matcher_service_wildcards_rejected() {
        let matcher = ArnMatcher::from_pattern("arn:aws:*:*:*:*").unwrap();

        // Service wildcards should not match anything for security
        assert!(
            !matcher
                .matches(&Arn::parse("arn:aws:s3:::my-bucket/file.txt").unwrap())
                .unwrap()
        );
        assert!(
            !matcher
                .matches(
                    &Arn::parse("arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0")
                        .unwrap()
                )
                .unwrap()
        );
    }

    #[test]
    fn test_arn_builder() {
        let arn = ArnBuilder::new()
            .partition("aws")
            .service("s3")
            .region("us-east-1")
            .account_id("123456789012")
            .resource("bucket", "my-bucket")
            .build()
            .unwrap();

        assert_eq!(arn.partition, "aws");
        assert_eq!(arn.service, "s3");
        assert_eq!(arn.region, "us-east-1");
        assert_eq!(arn.account_id, "123456789012");
        assert_eq!(arn.resource, "bucket/my-bucket");
        assert_eq!(
            arn.to_string(),
            "arn:aws:s3:us-east-1:123456789012:bucket/my-bucket"
        );
    }

    #[test]
    fn test_arn_builder_defaults() {
        let arn = ArnBuilder::new()
            .service("iam")
            .resource("user", "test-user")
            .build()
            .unwrap();

        assert_eq!(arn.partition, "aws");
        assert_eq!(arn.service, "iam");
        assert_eq!(arn.region, "");
        assert_eq!(arn.account_id, "");
        assert_eq!(arn.resource, "user/test-user");
    }

    #[test]
    fn test_arn_set_operations() {
        let mut arn_set = ArnSet::new();

        arn_set
            .add("arn:aws:s3:::bucket1/file1.txt".to_string())
            .unwrap();
        arn_set
            .add("arn:aws:s3:::bucket2/file2.txt".to_string())
            .unwrap();
        arn_set
            .add("arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0".to_string())
            .unwrap();

        assert_eq!(arn_set.len(), 3);
        assert!(arn_set.contains("arn:aws:s3:::bucket1/file1.txt"));
        assert!(!arn_set.contains("arn:aws:s3:::bucket3/file3.txt"));

        let s3_arns = arn_set.filter_by_service("s3").unwrap();
        assert_eq!(s3_arns.len(), 2);

        let ec2_arns = arn_set.filter_by_service("ec2").unwrap();
        assert_eq!(ec2_arns.len(), 1);
    }

    #[test]
    fn test_arn_set_pattern_filtering() {
        let arns = vec![
            "arn:aws:s3:::my-bucket/file1.txt".to_string(),
            "arn:aws:s3:::my-bucket/file2.txt".to_string(),
            "arn:aws:s3:::other-bucket/file3.txt".to_string(),
            "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0".to_string(),
        ];
        let arn_set = ArnSet::from_arns(arns).unwrap();

        let patterns = vec!["arn:aws:s3:::my-bucket/*".to_string()];
        let matching = arn_set.filter_by_patterns(&patterns).unwrap();

        assert_eq!(matching.len(), 2);
        assert!(matching.contains(&"arn:aws:s3:::my-bucket/file1.txt"));
        assert!(matching.contains(&"arn:aws:s3:::my-bucket/file2.txt"));
        assert!(!matching.contains(&"arn:aws:s3:::other-bucket/file3.txt"));
    }

    #[test]
    fn test_arn_matcher_performance_optimization() {
        // Test that exact matches (no wildcards) are handled efficiently
        let matcher = ArnMatcher::from_pattern("arn:aws:s3:::my-bucket/specific-file.txt").unwrap();

        assert!(
            matcher
                .matches(&Arn::parse("arn:aws:s3:::my-bucket/specific-file.txt").unwrap())
                .unwrap()
        );
        assert!(
            !matcher
                .matches(&Arn::parse("arn:aws:s3:::my-bucket/other-file.txt").unwrap())
                .unwrap()
        );
    }

    #[test]
    fn test_matching_patterns_list() {
        let patterns = vec![
            "arn:aws:s3:::bucket1/*".to_string(),
            "arn:aws:s3:::bucket2/*".to_string(),
            "arn:aws:ec2:*:*:instance/*".to_string(),
        ];
        let matcher = ArnMatcher::new(patterns).unwrap();

        let matching = matcher
            .matching_patterns("arn:aws:s3:::bucket1/file.txt")
            .unwrap();
        assert_eq!(matching, vec!["arn:aws:s3:::bucket1/*"]);

        let matching2 = matcher
            .matching_patterns("arn:aws:ec2:us-east-1:123456789012:instance/i-123")
            .unwrap();
        assert_eq!(matching2, vec!["arn:aws:ec2:*:*:instance/*"]);
    }
}
