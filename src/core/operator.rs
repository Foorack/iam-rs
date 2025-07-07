use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum OperatorType {
    String,
    Numeric,
    Date,
    Boolean,
    Binary,
    IpAddress,
    Arn,
    Null,
}

/// Represents the different types of condition operators available in IAM policies
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "PascalCase")]
pub enum Operator {
    // String condition operators
    #[serde(rename = "StringEquals")]
    StringEquals,
    #[serde(rename = "StringNotEquals")]
    StringNotEquals,
    #[serde(rename = "StringEqualsIgnoreCase")]
    StringEqualsIgnoreCase,
    #[serde(rename = "StringNotEqualsIgnoreCase")]
    StringNotEqualsIgnoreCase,
    #[serde(rename = "StringLike")]
    StringLike,
    #[serde(rename = "StringNotLike")]
    StringNotLike,

    // Multivalued string condition operators
    #[serde(rename = "ForAllValues:StringEquals")]
    ForAllValuesStringEquals,
    #[serde(rename = "ForAllValues:StringEqualsIgnoreCase")]
    ForAllValuesStringEqualsIgnoreCase,
    #[serde(rename = "ForAnyValue:StringEquals")]
    ForAnyValueStringEquals,
    #[serde(rename = "ForAnyValue:StringEqualsIgnoreCase")]
    ForAnyValueStringEqualsIgnoreCase,
    #[serde(rename = "ForAllValues:StringNotEquals")]
    ForAllValuesStringNotEquals,
    #[serde(rename = "ForAllValues:StringNotEqualsIgnoreCase")]
    ForAllValuesStringNotEqualsIgnoreCase,
    #[serde(rename = "ForAnyValue:StringNotEquals")]
    ForAnyValueStringNotEquals,
    #[serde(rename = "ForAnyValue:StringNotEqualsIgnoreCase")]
    ForAnyValueStringNotEqualsIgnoreCase,
    #[serde(rename = "ForAllValues:StringLike")]
    ForAllValuesStringLike,
    #[serde(rename = "ForAnyValue:StringLike")]
    ForAnyValueStringLike,
    #[serde(rename = "ForAllValues:StringNotLike")]
    ForAllValuesStringNotLike,
    #[serde(rename = "ForAnyValue:StringNotLike")]
    ForAnyValueStringNotLike,

    // Numeric condition operators
    #[serde(rename = "NumericEquals")]
    NumericEquals,
    #[serde(rename = "NumericNotEquals")]
    NumericNotEquals,
    #[serde(rename = "NumericLessThan")]
    NumericLessThan,
    #[serde(rename = "NumericLessThanEquals")]
    NumericLessThanEquals,
    #[serde(rename = "NumericGreaterThan")]
    NumericGreaterThan,
    #[serde(rename = "NumericGreaterThanEquals")]
    NumericGreaterThanEquals,

    // Date condition operators
    #[serde(rename = "DateEquals")]
    DateEquals,
    #[serde(rename = "DateNotEquals")]
    DateNotEquals,
    #[serde(rename = "DateLessThan")]
    DateLessThan,
    #[serde(rename = "DateLessThanEquals")]
    DateLessThanEquals,
    #[serde(rename = "DateGreaterThan")]
    DateGreaterThan,
    #[serde(rename = "DateGreaterThanEquals")]
    DateGreaterThanEquals,

    // Boolean condition operators
    #[serde(rename = "Bool")]
    Bool,
    #[serde(rename = "ForAllValues:Bool")]
    ForAllValuesBool,
    #[serde(rename = "ForAnyValue:Bool")]
    ForAnyValueBool,

    // Binary condition operators
    #[serde(rename = "BinaryEquals")]
    BinaryEquals,

    // IP address condition operators
    #[serde(rename = "IpAddress")]
    IpAddress,
    #[serde(rename = "NotIpAddress")]
    NotIpAddress,

    // ARN condition operators
    #[serde(rename = "ArnEquals")]
    ArnEquals,
    #[serde(rename = "ArnLike")]
    ArnLike,
    #[serde(rename = "ArnNotEquals")]
    ArnNotEquals,
    #[serde(rename = "ArnNotLike")]
    ArnNotLike,

    // Multivalued ARN condition operators
    #[serde(rename = "ForAllValues:ArnEquals")]
    ForAllValuesArnEquals,
    #[serde(rename = "ForAllValues:ArnLike")]
    ForAllValuesArnLike,
    #[serde(rename = "ForAnyValue:ArnEquals")]
    ForAnyValueArnEquals,
    #[serde(rename = "ForAnyValue:ArnLike")]
    ForAnyValueArnLike,
    #[serde(rename = "ForAllValues:ArnNotEquals")]
    ForAllValuesArnNotEquals,
    #[serde(rename = "ForAllValues:ArnNotLike")]
    ForAllValuesArnNotLike,
    #[serde(rename = "ForAnyValue:ArnNotEquals")]
    ForAnyValueArnNotEquals,
    #[serde(rename = "ForAnyValue:ArnNotLike")]
    ForAnyValueArnNotLike,

    // Null condition operator
    #[serde(rename = "Null")]
    Null,

    // IfExists variants (can be applied to most operators)
    #[serde(rename = "StringEqualsIfExists")]
    StringEqualsIfExists,
    #[serde(rename = "StringNotEqualsIfExists")]
    StringNotEqualsIfExists,
    #[serde(rename = "StringEqualsIgnoreCaseIfExists")]
    StringEqualsIgnoreCaseIfExists,
    #[serde(rename = "StringNotEqualsIgnoreCaseIfExists")]
    StringNotEqualsIgnoreCaseIfExists,
    #[serde(rename = "StringLikeIfExists")]
    StringLikeIfExists,
    #[serde(rename = "StringNotLikeIfExists")]
    StringNotLikeIfExists,
    #[serde(rename = "NumericEqualsIfExists")]
    NumericEqualsIfExists,
    #[serde(rename = "NumericNotEqualsIfExists")]
    NumericNotEqualsIfExists,
    #[serde(rename = "NumericLessThanIfExists")]
    NumericLessThanIfExists,
    #[serde(rename = "NumericLessThanEqualsIfExists")]
    NumericLessThanEqualsIfExists,
    #[serde(rename = "NumericGreaterThanIfExists")]
    NumericGreaterThanIfExists,
    #[serde(rename = "NumericGreaterThanEqualsIfExists")]
    NumericGreaterThanEqualsIfExists,
    #[serde(rename = "DateEqualsIfExists")]
    DateEqualsIfExists,
    #[serde(rename = "DateNotEqualsIfExists")]
    DateNotEqualsIfExists,
    #[serde(rename = "DateLessThanIfExists")]
    DateLessThanIfExists,
    #[serde(rename = "DateLessThanEqualsIfExists")]
    DateLessThanEqualsIfExists,
    #[serde(rename = "DateGreaterThanIfExists")]
    DateGreaterThanIfExists,
    #[serde(rename = "DateGreaterThanEqualsIfExists")]
    DateGreaterThanEqualsIfExists,
    #[serde(rename = "BoolIfExists")]
    BoolIfExists,
    #[serde(rename = "BinaryEqualsIfExists")]
    BinaryEqualsIfExists,
    #[serde(rename = "IpAddressIfExists")]
    IpAddressIfExists,
    #[serde(rename = "NotIpAddressIfExists")]
    NotIpAddressIfExists,
    #[serde(rename = "ArnEqualsIfExists")]
    ArnEqualsIfExists,
    #[serde(rename = "ArnLikeIfExists")]
    ArnLikeIfExists,
    #[serde(rename = "ArnNotEqualsIfExists")]
    ArnNotEqualsIfExists,
    #[serde(rename = "ArnNotLikeIfExists")]
    ArnNotLikeIfExists,
}

impl Operator {
    /// Returns true if this operator is a string-based operator
    #[must_use]
    pub fn is_string_operator(&self) -> bool {
        matches!(
            self,
            Operator::StringEquals
                | Operator::StringNotEquals
                | Operator::StringEqualsIgnoreCase
                | Operator::StringNotEqualsIgnoreCase
                | Operator::StringLike
                | Operator::StringNotLike
                | Operator::ForAllValuesStringEquals
                | Operator::ForAllValuesStringEqualsIgnoreCase
                | Operator::ForAnyValueStringEquals
                | Operator::ForAnyValueStringEqualsIgnoreCase
                | Operator::ForAllValuesStringNotEquals
                | Operator::ForAllValuesStringNotEqualsIgnoreCase
                | Operator::ForAnyValueStringNotEquals
                | Operator::ForAnyValueStringNotEqualsIgnoreCase
                | Operator::ForAllValuesStringLike
                | Operator::ForAnyValueStringLike
                | Operator::ForAllValuesStringNotLike
                | Operator::ForAnyValueStringNotLike
                | Operator::StringEqualsIfExists
                | Operator::StringNotEqualsIfExists
                | Operator::StringEqualsIgnoreCaseIfExists
                | Operator::StringNotEqualsIgnoreCaseIfExists
                | Operator::StringLikeIfExists
                | Operator::StringNotLikeIfExists
        )
    }

    /// Returns true if this operator is a numeric-based operator
    #[must_use]
    pub fn is_numeric_operator(&self) -> bool {
        matches!(
            self,
            Operator::NumericEquals
                | Operator::NumericNotEquals
                | Operator::NumericLessThan
                | Operator::NumericLessThanEquals
                | Operator::NumericGreaterThan
                | Operator::NumericGreaterThanEquals
                | Operator::NumericEqualsIfExists
                | Operator::NumericNotEqualsIfExists
                | Operator::NumericLessThanIfExists
                | Operator::NumericLessThanEqualsIfExists
                | Operator::NumericGreaterThanIfExists
                | Operator::NumericGreaterThanEqualsIfExists
        )
    }

    /// Returns true if this operator is a date-based operator
    #[must_use]
    pub fn is_date_operator(&self) -> bool {
        matches!(
            self,
            Operator::DateEquals
                | Operator::DateNotEquals
                | Operator::DateLessThan
                | Operator::DateLessThanEquals
                | Operator::DateGreaterThan
                | Operator::DateGreaterThanEquals
                | Operator::DateEqualsIfExists
                | Operator::DateNotEqualsIfExists
                | Operator::DateLessThanIfExists
                | Operator::DateLessThanEqualsIfExists
                | Operator::DateGreaterThanIfExists
                | Operator::DateGreaterThanEqualsIfExists
        )
    }

    /// Returns true if this operator is a boolean-based operator
    #[must_use]
    pub fn is_boolean_operator(&self) -> bool {
        matches!(
            self,
            Operator::Bool
                | Operator::ForAllValuesBool
                | Operator::ForAnyValueBool
                | Operator::BoolIfExists
        )
    }

    /// Returns true if this operator is an ARN-based operator
    #[must_use]
    pub fn is_arn_operator(&self) -> bool {
        matches!(
            self,
            Operator::ArnEquals
                | Operator::ArnLike
                | Operator::ArnNotEquals
                | Operator::ArnNotLike
                | Operator::ForAllValuesArnEquals
                | Operator::ForAllValuesArnLike
                | Operator::ForAnyValueArnEquals
                | Operator::ForAnyValueArnLike
                | Operator::ForAllValuesArnNotEquals
                | Operator::ForAllValuesArnNotLike
                | Operator::ForAnyValueArnNotEquals
                | Operator::ForAnyValueArnNotLike
                | Operator::ArnEqualsIfExists
                | Operator::ArnLikeIfExists
                | Operator::ArnNotEqualsIfExists
                | Operator::ArnNotLikeIfExists
        )
    }

    /// Returns true if this operator is an IP address-based operator
    #[must_use]
    pub fn is_ip_operator(&self) -> bool {
        matches!(
            self,
            Operator::IpAddress
                | Operator::NotIpAddress
                | Operator::IpAddressIfExists
                | Operator::NotIpAddressIfExists
        )
    }

    /// Returns true if this operator is a binary-based operator
    #[must_use]
    pub fn is_binary_operator(&self) -> bool {
        matches!(
            self,
            Operator::BinaryEquals | Operator::BinaryEqualsIfExists
        )
    }

    /// Returns true if this operator supports wildcards
    #[must_use]
    pub fn supports_wildcards(&self) -> bool {
        matches!(
            self,
            Operator::StringLike
                | Operator::StringNotLike
                | Operator::ForAllValuesStringLike
                | Operator::ForAnyValueStringLike
                | Operator::ForAllValuesStringNotLike
                | Operator::ForAnyValueStringNotLike
                | Operator::StringLikeIfExists
                | Operator::StringNotLikeIfExists
                | Operator::ArnEquals
                | Operator::ArnLike
                | Operator::ArnNotEquals
                | Operator::ArnNotLike
                | Operator::ForAllValuesArnEquals
                | Operator::ForAllValuesArnLike
                | Operator::ForAnyValueArnEquals
                | Operator::ForAnyValueArnLike
                | Operator::ForAllValuesArnNotEquals
                | Operator::ForAllValuesArnNotLike
                | Operator::ForAnyValueArnNotEquals
                | Operator::ForAnyValueArnNotLike
                | Operator::ArnEqualsIfExists
                | Operator::ArnLikeIfExists
                | Operator::ArnNotEqualsIfExists
                | Operator::ArnNotLikeIfExists
        )
    }

    /// Returns true if this operator supports policy variables
    #[must_use]
    pub fn supports_policy_variables(&self) -> bool {
        !self.is_numeric_operator()
            && !self.is_date_operator()
            && !self.is_binary_operator()
            && !self.is_ip_operator()
    }

    /// Returns true if this operator is a multivalued operator (ForAllValues/ForAnyValue)
    #[must_use]
    pub fn is_multivalued_operator(&self) -> bool {
        self.to_string().starts_with("ForAllValues:")
            || self.to_string().starts_with("ForAnyValue:")
    }

    /// Returns true if this operator is an "`IfExists`" variant
    #[must_use]
    pub fn is_if_exists_operator(&self) -> bool {
        self.to_string().ends_with("IfExists")
    }

    /// Returns true if this operator is a negated operator (Not*)
    #[must_use]
    pub fn is_negated_operator(&self) -> bool {
        matches!(
            self,
            Operator::StringNotEquals
                | Operator::StringNotEqualsIgnoreCase
                | Operator::StringNotLike
                | Operator::ForAllValuesStringNotEquals
                | Operator::ForAllValuesStringNotEqualsIgnoreCase
                | Operator::ForAnyValueStringNotEquals
                | Operator::ForAnyValueStringNotEqualsIgnoreCase
                | Operator::ForAllValuesStringNotLike
                | Operator::ForAnyValueStringNotLike
                | Operator::NumericNotEquals
                | Operator::DateNotEquals
                | Operator::NotIpAddress
                | Operator::ArnNotEquals
                | Operator::ArnNotLike
                | Operator::ForAllValuesArnNotEquals
                | Operator::ForAllValuesArnNotLike
                | Operator::ForAnyValueArnNotEquals
                | Operator::ForAnyValueArnNotLike
                | Operator::StringNotEqualsIfExists
                | Operator::StringNotEqualsIgnoreCaseIfExists
                | Operator::StringNotLikeIfExists
                | Operator::NumericNotEqualsIfExists
                | Operator::DateNotEqualsIfExists
                | Operator::NotIpAddressIfExists
                | Operator::ArnNotEqualsIfExists
                | Operator::ArnNotLikeIfExists
        )
    }

    /// Returns true if this operator supports multiple values (arrays)
    /// Most operators in AWS IAM can accept arrays, not just ForAllValues/ForAnyValue
    #[must_use]
    pub fn supports_multiple_values(&self) -> bool {
        // Most operators support multiple values except for these specific ones
        !matches!(
            self,
            Operator::Null | Operator::Bool | Operator::BoolIfExists
        )
    }

    /// Returns the operator category as a string
    /// Determine the category of this operator
    ///
    /// # Panics
    ///
    /// Panics if the operator is not recognized (this should never happen)
    #[must_use]
    pub fn category(&self) -> OperatorType {
        if self.is_string_operator() {
            OperatorType::String
        } else if self.is_numeric_operator() {
            OperatorType::Numeric
        } else if self.is_date_operator() {
            OperatorType::Date
        } else if self.is_boolean_operator() {
            OperatorType::Boolean
        } else if self.is_binary_operator() {
            OperatorType::Binary
        } else if self.is_ip_operator() {
            OperatorType::IpAddress
        } else if self.is_arn_operator() {
            OperatorType::Arn
        } else if matches!(self, Operator::Null) {
            OperatorType::Null
        } else {
            panic!("Unknown operator category for operator: {}", self.as_str())
        }
    }

    /// Returns the string representation of the operator for use in JSON
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Operator::StringEquals => "StringEquals",
            Operator::StringNotEquals => "StringNotEquals",
            Operator::StringEqualsIgnoreCase => "StringEqualsIgnoreCase",
            Operator::StringNotEqualsIgnoreCase => "StringNotEqualsIgnoreCase",
            Operator::StringLike => "StringLike",
            Operator::StringNotLike => "StringNotLike",
            Operator::ForAllValuesStringEquals => "ForAllValues:StringEquals",
            Operator::ForAllValuesStringEqualsIgnoreCase => "ForAllValues:StringEqualsIgnoreCase",
            Operator::ForAnyValueStringEquals => "ForAnyValue:StringEquals",
            Operator::ForAnyValueStringEqualsIgnoreCase => "ForAnyValue:StringEqualsIgnoreCase",
            Operator::ForAllValuesStringNotEquals => "ForAllValues:StringNotEquals",
            Operator::ForAllValuesStringNotEqualsIgnoreCase => {
                "ForAllValues:StringNotEqualsIgnoreCase"
            }
            Operator::ForAnyValueStringNotEquals => "ForAnyValue:StringNotEquals",
            Operator::ForAnyValueStringNotEqualsIgnoreCase => {
                "ForAnyValue:StringNotEqualsIgnoreCase"
            }
            Operator::ForAllValuesStringLike => "ForAllValues:StringLike",
            Operator::ForAnyValueStringLike => "ForAnyValue:StringLike",
            Operator::ForAllValuesStringNotLike => "ForAllValues:StringNotLike",
            Operator::ForAnyValueStringNotLike => "ForAnyValue:StringNotLike",
            Operator::NumericEquals => "NumericEquals",
            Operator::NumericNotEquals => "NumericNotEquals",
            Operator::NumericLessThan => "NumericLessThan",
            Operator::NumericLessThanEquals => "NumericLessThanEquals",
            Operator::NumericGreaterThan => "NumericGreaterThan",
            Operator::NumericGreaterThanEquals => "NumericGreaterThanEquals",
            Operator::DateEquals => "DateEquals",
            Operator::DateNotEquals => "DateNotEquals",
            Operator::DateLessThan => "DateLessThan",
            Operator::DateLessThanEquals => "DateLessThanEquals",
            Operator::DateGreaterThan => "DateGreaterThan",
            Operator::DateGreaterThanEquals => "DateGreaterThanEquals",
            Operator::Bool => "Bool",
            Operator::ForAllValuesBool => "ForAllValues:Bool",
            Operator::ForAnyValueBool => "ForAnyValue:Bool",
            Operator::BinaryEquals => "BinaryEquals",
            Operator::IpAddress => "IpAddress",
            Operator::NotIpAddress => "NotIpAddress",
            Operator::ArnEquals => "ArnEquals",
            Operator::ArnLike => "ArnLike",
            Operator::ArnNotEquals => "ArnNotEquals",
            Operator::ArnNotLike => "ArnNotLike",
            Operator::ForAllValuesArnEquals => "ForAllValues:ArnEquals",
            Operator::ForAllValuesArnLike => "ForAllValues:ArnLike",
            Operator::ForAnyValueArnEquals => "ForAnyValue:ArnEquals",
            Operator::ForAnyValueArnLike => "ForAnyValue:ArnLike",
            Operator::ForAllValuesArnNotEquals => "ForAllValues:ArnNotEquals",
            Operator::ForAllValuesArnNotLike => "ForAllValues:ArnNotLike",
            Operator::ForAnyValueArnNotEquals => "ForAnyValue:ArnNotEquals",
            Operator::ForAnyValueArnNotLike => "ForAnyValue:ArnNotLike",
            Operator::Null => "Null",
            Operator::StringEqualsIfExists => "StringEqualsIfExists",
            Operator::StringNotEqualsIfExists => "StringNotEqualsIfExists",
            Operator::StringEqualsIgnoreCaseIfExists => "StringEqualsIgnoreCaseIfExists",
            Operator::StringNotEqualsIgnoreCaseIfExists => "StringNotEqualsIgnoreCaseIfExists",
            Operator::StringLikeIfExists => "StringLikeIfExists",
            Operator::StringNotLikeIfExists => "StringNotLikeIfExists",
            Operator::NumericEqualsIfExists => "NumericEqualsIfExists",
            Operator::NumericNotEqualsIfExists => "NumericNotEqualsIfExists",
            Operator::NumericLessThanIfExists => "NumericLessThanIfExists",
            Operator::NumericLessThanEqualsIfExists => "NumericLessThanEqualsIfExists",
            Operator::NumericGreaterThanIfExists => "NumericGreaterThanIfExists",
            Operator::NumericGreaterThanEqualsIfExists => "NumericGreaterThanEqualsIfExists",
            Operator::DateEqualsIfExists => "DateEqualsIfExists",
            Operator::DateNotEqualsIfExists => "DateNotEqualsIfExists",
            Operator::DateLessThanIfExists => "DateLessThanIfExists",
            Operator::DateLessThanEqualsIfExists => "DateLessThanEqualsIfExists",
            Operator::DateGreaterThanIfExists => "DateGreaterThanIfExists",
            Operator::DateGreaterThanEqualsIfExists => "DateGreaterThanEqualsIfExists",
            Operator::BoolIfExists => "BoolIfExists",
            Operator::BinaryEqualsIfExists => "BinaryEqualsIfExists",
            Operator::IpAddressIfExists => "IpAddressIfExists",
            Operator::NotIpAddressIfExists => "NotIpAddressIfExists",
            Operator::ArnEqualsIfExists => "ArnEqualsIfExists",
            Operator::ArnLikeIfExists => "ArnLikeIfExists",
            Operator::ArnNotEqualsIfExists => "ArnNotEqualsIfExists",
            Operator::ArnNotLikeIfExists => "ArnNotLikeIfExists",
        }
    }
}

impl std::fmt::Display for Operator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for Operator {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "StringEquals" => Ok(Operator::StringEquals),
            "StringNotEquals" => Ok(Operator::StringNotEquals),
            "StringEqualsIgnoreCase" => Ok(Operator::StringEqualsIgnoreCase),
            "StringNotEqualsIgnoreCase" => Ok(Operator::StringNotEqualsIgnoreCase),
            "StringLike" => Ok(Operator::StringLike),
            "StringNotLike" => Ok(Operator::StringNotLike),
            "ForAllValues:StringEquals" => Ok(Operator::ForAllValuesStringEquals),
            "ForAllValues:StringEqualsIgnoreCase" => {
                Ok(Operator::ForAllValuesStringEqualsIgnoreCase)
            }
            "ForAnyValue:StringEquals" => Ok(Operator::ForAnyValueStringEquals),
            "ForAnyValue:StringEqualsIgnoreCase" => Ok(Operator::ForAnyValueStringEqualsIgnoreCase),
            "ForAllValues:StringNotEquals" => Ok(Operator::ForAllValuesStringNotEquals),
            "ForAllValues:StringNotEqualsIgnoreCase" => {
                Ok(Operator::ForAllValuesStringNotEqualsIgnoreCase)
            }
            "ForAnyValue:StringNotEquals" => Ok(Operator::ForAnyValueStringNotEquals),
            "ForAnyValue:StringNotEqualsIgnoreCase" => {
                Ok(Operator::ForAnyValueStringNotEqualsIgnoreCase)
            }
            "ForAllValues:StringLike" => Ok(Operator::ForAllValuesStringLike),
            "ForAnyValue:StringLike" => Ok(Operator::ForAnyValueStringLike),
            "ForAllValues:StringNotLike" => Ok(Operator::ForAllValuesStringNotLike),
            "ForAnyValue:StringNotLike" => Ok(Operator::ForAnyValueStringNotLike),
            "NumericEquals" => Ok(Operator::NumericEquals),
            "NumericNotEquals" => Ok(Operator::NumericNotEquals),
            "NumericLessThan" => Ok(Operator::NumericLessThan),
            "NumericLessThanEquals" => Ok(Operator::NumericLessThanEquals),
            "NumericGreaterThan" => Ok(Operator::NumericGreaterThan),
            "NumericGreaterThanEquals" => Ok(Operator::NumericGreaterThanEquals),
            "DateEquals" => Ok(Operator::DateEquals),
            "DateNotEquals" => Ok(Operator::DateNotEquals),
            "DateLessThan" => Ok(Operator::DateLessThan),
            "DateLessThanEquals" => Ok(Operator::DateLessThanEquals),
            "DateGreaterThan" => Ok(Operator::DateGreaterThan),
            "DateGreaterThanEquals" => Ok(Operator::DateGreaterThanEquals),
            "Bool" => Ok(Operator::Bool),
            "ForAllValues:Bool" => Ok(Operator::ForAllValuesBool),
            "ForAnyValue:Bool" => Ok(Operator::ForAnyValueBool),
            "BinaryEquals" => Ok(Operator::BinaryEquals),
            "IpAddress" => Ok(Operator::IpAddress),
            "NotIpAddress" => Ok(Operator::NotIpAddress),
            "ArnEquals" => Ok(Operator::ArnEquals),
            "ArnLike" => Ok(Operator::ArnLike),
            "ArnNotEquals" => Ok(Operator::ArnNotEquals),
            "ArnNotLike" => Ok(Operator::ArnNotLike),
            "ForAllValues:ArnEquals" => Ok(Operator::ForAllValuesArnEquals),
            "ForAllValues:ArnLike" => Ok(Operator::ForAllValuesArnLike),
            "ForAnyValue:ArnEquals" => Ok(Operator::ForAnyValueArnEquals),
            "ForAnyValue:ArnLike" => Ok(Operator::ForAnyValueArnLike),
            "ForAllValues:ArnNotEquals" => Ok(Operator::ForAllValuesArnNotEquals),
            "ForAllValues:ArnNotLike" => Ok(Operator::ForAllValuesArnNotLike),
            "ForAnyValue:ArnNotEquals" => Ok(Operator::ForAnyValueArnNotEquals),
            "ForAnyValue:ArnNotLike" => Ok(Operator::ForAnyValueArnNotLike),
            "Null" => Ok(Operator::Null),
            "StringEqualsIfExists" => Ok(Operator::StringEqualsIfExists),
            "StringNotEqualsIfExists" => Ok(Operator::StringNotEqualsIfExists),
            "StringEqualsIgnoreCaseIfExists" => Ok(Operator::StringEqualsIgnoreCaseIfExists),
            "StringNotEqualsIgnoreCaseIfExists" => Ok(Operator::StringNotEqualsIgnoreCaseIfExists),
            "StringLikeIfExists" => Ok(Operator::StringLikeIfExists),
            "StringNotLikeIfExists" => Ok(Operator::StringNotLikeIfExists),
            "NumericEqualsIfExists" => Ok(Operator::NumericEqualsIfExists),
            "NumericNotEqualsIfExists" => Ok(Operator::NumericNotEqualsIfExists),
            "NumericLessThanIfExists" => Ok(Operator::NumericLessThanIfExists),
            "NumericLessThanEqualsIfExists" => Ok(Operator::NumericLessThanEqualsIfExists),
            "NumericGreaterThanIfExists" => Ok(Operator::NumericGreaterThanIfExists),
            "NumericGreaterThanEqualsIfExists" => Ok(Operator::NumericGreaterThanEqualsIfExists),
            "DateEqualsIfExists" => Ok(Operator::DateEqualsIfExists),
            "DateNotEqualsIfExists" => Ok(Operator::DateNotEqualsIfExists),
            "DateLessThanIfExists" => Ok(Operator::DateLessThanIfExists),
            "DateLessThanEqualsIfExists" => Ok(Operator::DateLessThanEqualsIfExists),
            "DateGreaterThanIfExists" => Ok(Operator::DateGreaterThanIfExists),
            "DateGreaterThanEqualsIfExists" => Ok(Operator::DateGreaterThanEqualsIfExists),
            "BoolIfExists" => Ok(Operator::BoolIfExists),
            "BinaryEqualsIfExists" => Ok(Operator::BinaryEqualsIfExists),
            "IpAddressIfExists" => Ok(Operator::IpAddressIfExists),
            "NotIpAddressIfExists" => Ok(Operator::NotIpAddressIfExists),
            "ArnEqualsIfExists" => Ok(Operator::ArnEqualsIfExists),
            "ArnLikeIfExists" => Ok(Operator::ArnLikeIfExists),
            "ArnNotEqualsIfExists" => Ok(Operator::ArnNotEqualsIfExists),
            "ArnNotLikeIfExists" => Ok(Operator::ArnNotLikeIfExists),
            _ => Err(format!("Unknown operator: {s}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_operator_serialization() {
        let operator = Operator::StringEquals;
        let json = serde_json::to_string(&operator).unwrap();
        assert_eq!(json, "\"StringEquals\"");

        let deserialized: Operator = serde_json::from_str(&json).unwrap();
        assert_eq!(operator, deserialized);
    }

    #[test]
    fn test_multivalued_operators() {
        let operator = Operator::ForAllValuesStringEquals;
        let json = serde_json::to_string(&operator).unwrap();
        assert_eq!(json, "\"ForAllValues:StringEquals\"");

        let deserialized: Operator = serde_json::from_str(&json).unwrap();
        assert_eq!(operator, deserialized);
    }

    #[test]
    fn test_operator_categories() {
        assert!(Operator::StringEquals.is_string_operator());
        assert!(Operator::NumericEquals.is_numeric_operator());
        assert!(Operator::DateEquals.is_date_operator());
        assert!(Operator::Bool.is_boolean_operator());
        assert!(Operator::ArnEquals.is_arn_operator());
        assert!(Operator::IpAddress.is_ip_operator());
        assert!(Operator::BinaryEquals.is_binary_operator());
    }

    #[test]
    fn test_operator_features() {
        assert!(Operator::StringLike.supports_wildcards());
        assert!(Operator::StringEquals.supports_policy_variables());
        assert!(!Operator::NumericEquals.supports_policy_variables());
        assert!(Operator::ForAllValuesStringEquals.is_multivalued_operator());
        assert!(Operator::StringEqualsIfExists.is_if_exists_operator());
        assert!(Operator::StringNotEquals.is_negated_operator());

        // Test multiple values support
        assert!(Operator::StringEquals.supports_multiple_values());
        assert!(Operator::StringNotEquals.supports_multiple_values());
        assert!(Operator::NumericEquals.supports_multiple_values());
        assert!(Operator::DateEquals.supports_multiple_values());
        assert!(Operator::IpAddress.supports_multiple_values());
        assert!(Operator::ArnEquals.supports_multiple_values());

        // These should not support multiple values
        assert!(!Operator::Bool.supports_multiple_values());
        assert!(!Operator::BoolIfExists.supports_multiple_values());
        assert!(!Operator::Null.supports_multiple_values());
    }

    #[test]
    fn test_operator_category_strings() {
        assert_eq!(Operator::StringEquals.category(), OperatorType::String);
        assert_eq!(Operator::NumericEquals.category(), OperatorType::Numeric);
        assert_eq!(Operator::DateEquals.category(), OperatorType::Date);
        assert_eq!(Operator::Bool.category(), OperatorType::Boolean);
        assert_eq!(Operator::BinaryEquals.category(), OperatorType::Binary);
        assert_eq!(Operator::IpAddress.category(), OperatorType::IpAddress);
        assert_eq!(Operator::ArnEquals.category(), OperatorType::Arn);
        assert_eq!(Operator::Null.category(), OperatorType::Null);
    }

    #[test]
    fn test_operator_string_conversion() {
        assert_eq!(Operator::StringEquals.as_str(), "StringEquals");
        assert_eq!(
            Operator::ForAllValuesStringEquals.as_str(),
            "ForAllValues:StringEquals"
        );
        assert_eq!(
            Operator::StringEqualsIfExists.as_str(),
            "StringEqualsIfExists"
        );
    }

    #[test]
    fn test_operator_from_str() {
        assert_eq!(
            "StringEquals".parse::<Operator>().unwrap(),
            Operator::StringEquals
        );
        assert_eq!(
            "ForAllValues:StringEquals".parse::<Operator>().unwrap(),
            Operator::ForAllValuesStringEquals
        );
        assert_eq!(
            "StringEqualsIfExists".parse::<Operator>().unwrap(),
            Operator::StringEqualsIfExists
        );

        assert!("InvalidOperator".parse::<Operator>().is_err());
    }
}
