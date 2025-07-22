use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash, PartialOrd, Ord)]
#[serde(rename_all = "PascalCase")]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum IAMOperator {
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

impl IAMOperator {
    /// Returns true if this operator is a string-based operator
    #[must_use]
    pub fn is_string_operator(&self) -> bool {
        matches!(
            self,
            IAMOperator::StringEquals
                | IAMOperator::StringNotEquals
                | IAMOperator::StringEqualsIgnoreCase
                | IAMOperator::StringNotEqualsIgnoreCase
                | IAMOperator::StringLike
                | IAMOperator::StringNotLike
                | IAMOperator::ForAllValuesStringEquals
                | IAMOperator::ForAllValuesStringEqualsIgnoreCase
                | IAMOperator::ForAnyValueStringEquals
                | IAMOperator::ForAnyValueStringEqualsIgnoreCase
                | IAMOperator::ForAllValuesStringNotEquals
                | IAMOperator::ForAllValuesStringNotEqualsIgnoreCase
                | IAMOperator::ForAnyValueStringNotEquals
                | IAMOperator::ForAnyValueStringNotEqualsIgnoreCase
                | IAMOperator::ForAllValuesStringLike
                | IAMOperator::ForAnyValueStringLike
                | IAMOperator::ForAllValuesStringNotLike
                | IAMOperator::ForAnyValueStringNotLike
                | IAMOperator::StringEqualsIfExists
                | IAMOperator::StringNotEqualsIfExists
                | IAMOperator::StringEqualsIgnoreCaseIfExists
                | IAMOperator::StringNotEqualsIgnoreCaseIfExists
                | IAMOperator::StringLikeIfExists
                | IAMOperator::StringNotLikeIfExists
        )
    }

    /// Returns true if this operator is a numeric-based operator
    #[must_use]
    pub fn is_numeric_operator(&self) -> bool {
        matches!(
            self,
            IAMOperator::NumericEquals
                | IAMOperator::NumericNotEquals
                | IAMOperator::NumericLessThan
                | IAMOperator::NumericLessThanEquals
                | IAMOperator::NumericGreaterThan
                | IAMOperator::NumericGreaterThanEquals
                | IAMOperator::NumericEqualsIfExists
                | IAMOperator::NumericNotEqualsIfExists
                | IAMOperator::NumericLessThanIfExists
                | IAMOperator::NumericLessThanEqualsIfExists
                | IAMOperator::NumericGreaterThanIfExists
                | IAMOperator::NumericGreaterThanEqualsIfExists
        )
    }

    /// Returns true if this operator is a date-based operator
    #[must_use]
    pub fn is_date_operator(&self) -> bool {
        matches!(
            self,
            IAMOperator::DateEquals
                | IAMOperator::DateNotEquals
                | IAMOperator::DateLessThan
                | IAMOperator::DateLessThanEquals
                | IAMOperator::DateGreaterThan
                | IAMOperator::DateGreaterThanEquals
                | IAMOperator::DateEqualsIfExists
                | IAMOperator::DateNotEqualsIfExists
                | IAMOperator::DateLessThanIfExists
                | IAMOperator::DateLessThanEqualsIfExists
                | IAMOperator::DateGreaterThanIfExists
                | IAMOperator::DateGreaterThanEqualsIfExists
        )
    }

    /// Returns true if this operator is a boolean-based operator
    #[must_use]
    pub fn is_boolean_operator(&self) -> bool {
        matches!(
            self,
            IAMOperator::Bool
                | IAMOperator::ForAllValuesBool
                | IAMOperator::ForAnyValueBool
                | IAMOperator::BoolIfExists
        )
    }

    /// Returns true if this operator is an ARN-based operator
    #[must_use]
    pub fn is_arn_operator(&self) -> bool {
        matches!(
            self,
            IAMOperator::ArnEquals
                | IAMOperator::ArnLike
                | IAMOperator::ArnNotEquals
                | IAMOperator::ArnNotLike
                | IAMOperator::ForAllValuesArnEquals
                | IAMOperator::ForAllValuesArnLike
                | IAMOperator::ForAnyValueArnEquals
                | IAMOperator::ForAnyValueArnLike
                | IAMOperator::ForAllValuesArnNotEquals
                | IAMOperator::ForAllValuesArnNotLike
                | IAMOperator::ForAnyValueArnNotEquals
                | IAMOperator::ForAnyValueArnNotLike
                | IAMOperator::ArnEqualsIfExists
                | IAMOperator::ArnLikeIfExists
                | IAMOperator::ArnNotEqualsIfExists
                | IAMOperator::ArnNotLikeIfExists
        )
    }

    /// Returns true if this operator is an IP address-based operator
    #[must_use]
    pub fn is_ip_operator(&self) -> bool {
        matches!(
            self,
            IAMOperator::IpAddress
                | IAMOperator::NotIpAddress
                | IAMOperator::IpAddressIfExists
                | IAMOperator::NotIpAddressIfExists
        )
    }

    /// Returns true if this operator is a binary-based operator
    #[must_use]
    pub fn is_binary_operator(&self) -> bool {
        matches!(
            self,
            IAMOperator::BinaryEquals | IAMOperator::BinaryEqualsIfExists
        )
    }

    /// Returns true if this operator supports wildcards
    #[must_use]
    pub fn supports_wildcards(&self) -> bool {
        matches!(
            self,
            IAMOperator::StringLike
                | IAMOperator::StringNotLike
                | IAMOperator::ForAllValuesStringLike
                | IAMOperator::ForAnyValueStringLike
                | IAMOperator::ForAllValuesStringNotLike
                | IAMOperator::ForAnyValueStringNotLike
                | IAMOperator::StringLikeIfExists
                | IAMOperator::StringNotLikeIfExists
                | IAMOperator::ArnEquals
                | IAMOperator::ArnLike
                | IAMOperator::ArnNotEquals
                | IAMOperator::ArnNotLike
                | IAMOperator::ForAllValuesArnEquals
                | IAMOperator::ForAllValuesArnLike
                | IAMOperator::ForAnyValueArnEquals
                | IAMOperator::ForAnyValueArnLike
                | IAMOperator::ForAllValuesArnNotEquals
                | IAMOperator::ForAllValuesArnNotLike
                | IAMOperator::ForAnyValueArnNotEquals
                | IAMOperator::ForAnyValueArnNotLike
                | IAMOperator::ArnEqualsIfExists
                | IAMOperator::ArnLikeIfExists
                | IAMOperator::ArnNotEqualsIfExists
                | IAMOperator::ArnNotLikeIfExists
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
            IAMOperator::StringNotEquals
                | IAMOperator::StringNotEqualsIgnoreCase
                | IAMOperator::StringNotLike
                | IAMOperator::ForAllValuesStringNotEquals
                | IAMOperator::ForAllValuesStringNotEqualsIgnoreCase
                | IAMOperator::ForAnyValueStringNotEquals
                | IAMOperator::ForAnyValueStringNotEqualsIgnoreCase
                | IAMOperator::ForAllValuesStringNotLike
                | IAMOperator::ForAnyValueStringNotLike
                | IAMOperator::NumericNotEquals
                | IAMOperator::DateNotEquals
                | IAMOperator::NotIpAddress
                | IAMOperator::ArnNotEquals
                | IAMOperator::ArnNotLike
                | IAMOperator::ForAllValuesArnNotEquals
                | IAMOperator::ForAllValuesArnNotLike
                | IAMOperator::ForAnyValueArnNotEquals
                | IAMOperator::ForAnyValueArnNotLike
                | IAMOperator::StringNotEqualsIfExists
                | IAMOperator::StringNotEqualsIgnoreCaseIfExists
                | IAMOperator::StringNotLikeIfExists
                | IAMOperator::NumericNotEqualsIfExists
                | IAMOperator::DateNotEqualsIfExists
                | IAMOperator::NotIpAddressIfExists
                | IAMOperator::ArnNotEqualsIfExists
                | IAMOperator::ArnNotLikeIfExists
        )
    }

    /// Returns true if this operator supports multiple values (arrays)
    /// Most operators in AWS IAM can accept arrays, not just ForAllValues/ForAnyValue
    #[must_use]
    pub fn supports_multiple_values(&self) -> bool {
        // Most operators support multiple values except for these specific ones
        !matches!(
            self,
            IAMOperator::Null | IAMOperator::Bool | IAMOperator::BoolIfExists
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
        } else if matches!(self, IAMOperator::Null) {
            OperatorType::Null
        } else {
            panic!("Unknown operator category for operator: {}", self.as_str())
        }
    }

    /// Returns the string representation of the operator for use in JSON
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            IAMOperator::StringEquals => "StringEquals",
            IAMOperator::StringNotEquals => "StringNotEquals",
            IAMOperator::StringEqualsIgnoreCase => "StringEqualsIgnoreCase",
            IAMOperator::StringNotEqualsIgnoreCase => "StringNotEqualsIgnoreCase",
            IAMOperator::StringLike => "StringLike",
            IAMOperator::StringNotLike => "StringNotLike",
            IAMOperator::ForAllValuesStringEquals => "ForAllValues:StringEquals",
            IAMOperator::ForAllValuesStringEqualsIgnoreCase => {
                "ForAllValues:StringEqualsIgnoreCase"
            }
            IAMOperator::ForAnyValueStringEquals => "ForAnyValue:StringEquals",
            IAMOperator::ForAnyValueStringEqualsIgnoreCase => "ForAnyValue:StringEqualsIgnoreCase",
            IAMOperator::ForAllValuesStringNotEquals => "ForAllValues:StringNotEquals",
            IAMOperator::ForAllValuesStringNotEqualsIgnoreCase => {
                "ForAllValues:StringNotEqualsIgnoreCase"
            }
            IAMOperator::ForAnyValueStringNotEquals => "ForAnyValue:StringNotEquals",
            IAMOperator::ForAnyValueStringNotEqualsIgnoreCase => {
                "ForAnyValue:StringNotEqualsIgnoreCase"
            }
            IAMOperator::ForAllValuesStringLike => "ForAllValues:StringLike",
            IAMOperator::ForAnyValueStringLike => "ForAnyValue:StringLike",
            IAMOperator::ForAllValuesStringNotLike => "ForAllValues:StringNotLike",
            IAMOperator::ForAnyValueStringNotLike => "ForAnyValue:StringNotLike",
            IAMOperator::NumericEquals => "NumericEquals",
            IAMOperator::NumericNotEquals => "NumericNotEquals",
            IAMOperator::NumericLessThan => "NumericLessThan",
            IAMOperator::NumericLessThanEquals => "NumericLessThanEquals",
            IAMOperator::NumericGreaterThan => "NumericGreaterThan",
            IAMOperator::NumericGreaterThanEquals => "NumericGreaterThanEquals",
            IAMOperator::DateEquals => "DateEquals",
            IAMOperator::DateNotEquals => "DateNotEquals",
            IAMOperator::DateLessThan => "DateLessThan",
            IAMOperator::DateLessThanEquals => "DateLessThanEquals",
            IAMOperator::DateGreaterThan => "DateGreaterThan",
            IAMOperator::DateGreaterThanEquals => "DateGreaterThanEquals",
            IAMOperator::Bool => "Bool",
            IAMOperator::ForAllValuesBool => "ForAllValues:Bool",
            IAMOperator::ForAnyValueBool => "ForAnyValue:Bool",
            IAMOperator::BinaryEquals => "BinaryEquals",
            IAMOperator::IpAddress => "IpAddress",
            IAMOperator::NotIpAddress => "NotIpAddress",
            IAMOperator::ArnEquals => "ArnEquals",
            IAMOperator::ArnLike => "ArnLike",
            IAMOperator::ArnNotEquals => "ArnNotEquals",
            IAMOperator::ArnNotLike => "ArnNotLike",
            IAMOperator::ForAllValuesArnEquals => "ForAllValues:ArnEquals",
            IAMOperator::ForAllValuesArnLike => "ForAllValues:ArnLike",
            IAMOperator::ForAnyValueArnEquals => "ForAnyValue:ArnEquals",
            IAMOperator::ForAnyValueArnLike => "ForAnyValue:ArnLike",
            IAMOperator::ForAllValuesArnNotEquals => "ForAllValues:ArnNotEquals",
            IAMOperator::ForAllValuesArnNotLike => "ForAllValues:ArnNotLike",
            IAMOperator::ForAnyValueArnNotEquals => "ForAnyValue:ArnNotEquals",
            IAMOperator::ForAnyValueArnNotLike => "ForAnyValue:ArnNotLike",
            IAMOperator::Null => "Null",
            IAMOperator::StringEqualsIfExists => "StringEqualsIfExists",
            IAMOperator::StringNotEqualsIfExists => "StringNotEqualsIfExists",
            IAMOperator::StringEqualsIgnoreCaseIfExists => "StringEqualsIgnoreCaseIfExists",
            IAMOperator::StringNotEqualsIgnoreCaseIfExists => "StringNotEqualsIgnoreCaseIfExists",
            IAMOperator::StringLikeIfExists => "StringLikeIfExists",
            IAMOperator::StringNotLikeIfExists => "StringNotLikeIfExists",
            IAMOperator::NumericEqualsIfExists => "NumericEqualsIfExists",
            IAMOperator::NumericNotEqualsIfExists => "NumericNotEqualsIfExists",
            IAMOperator::NumericLessThanIfExists => "NumericLessThanIfExists",
            IAMOperator::NumericLessThanEqualsIfExists => "NumericLessThanEqualsIfExists",
            IAMOperator::NumericGreaterThanIfExists => "NumericGreaterThanIfExists",
            IAMOperator::NumericGreaterThanEqualsIfExists => "NumericGreaterThanEqualsIfExists",
            IAMOperator::DateEqualsIfExists => "DateEqualsIfExists",
            IAMOperator::DateNotEqualsIfExists => "DateNotEqualsIfExists",
            IAMOperator::DateLessThanIfExists => "DateLessThanIfExists",
            IAMOperator::DateLessThanEqualsIfExists => "DateLessThanEqualsIfExists",
            IAMOperator::DateGreaterThanIfExists => "DateGreaterThanIfExists",
            IAMOperator::DateGreaterThanEqualsIfExists => "DateGreaterThanEqualsIfExists",
            IAMOperator::BoolIfExists => "BoolIfExists",
            IAMOperator::BinaryEqualsIfExists => "BinaryEqualsIfExists",
            IAMOperator::IpAddressIfExists => "IpAddressIfExists",
            IAMOperator::NotIpAddressIfExists => "NotIpAddressIfExists",
            IAMOperator::ArnEqualsIfExists => "ArnEqualsIfExists",
            IAMOperator::ArnLikeIfExists => "ArnLikeIfExists",
            IAMOperator::ArnNotEqualsIfExists => "ArnNotEqualsIfExists",
            IAMOperator::ArnNotLikeIfExists => "ArnNotLikeIfExists",
        }
    }
}

impl std::fmt::Display for IAMOperator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for IAMOperator {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "StringEquals" => Ok(IAMOperator::StringEquals),
            "StringNotEquals" => Ok(IAMOperator::StringNotEquals),
            "StringEqualsIgnoreCase" => Ok(IAMOperator::StringEqualsIgnoreCase),
            "StringNotEqualsIgnoreCase" => Ok(IAMOperator::StringNotEqualsIgnoreCase),
            "StringLike" => Ok(IAMOperator::StringLike),
            "StringNotLike" => Ok(IAMOperator::StringNotLike),
            "ForAllValues:StringEquals" => Ok(IAMOperator::ForAllValuesStringEquals),
            "ForAllValues:StringEqualsIgnoreCase" => {
                Ok(IAMOperator::ForAllValuesStringEqualsIgnoreCase)
            }
            "ForAnyValue:StringEquals" => Ok(IAMOperator::ForAnyValueStringEquals),
            "ForAnyValue:StringEqualsIgnoreCase" => {
                Ok(IAMOperator::ForAnyValueStringEqualsIgnoreCase)
            }
            "ForAllValues:StringNotEquals" => Ok(IAMOperator::ForAllValuesStringNotEquals),
            "ForAllValues:StringNotEqualsIgnoreCase" => {
                Ok(IAMOperator::ForAllValuesStringNotEqualsIgnoreCase)
            }
            "ForAnyValue:StringNotEquals" => Ok(IAMOperator::ForAnyValueStringNotEquals),
            "ForAnyValue:StringNotEqualsIgnoreCase" => {
                Ok(IAMOperator::ForAnyValueStringNotEqualsIgnoreCase)
            }
            "ForAllValues:StringLike" => Ok(IAMOperator::ForAllValuesStringLike),
            "ForAnyValue:StringLike" => Ok(IAMOperator::ForAnyValueStringLike),
            "ForAllValues:StringNotLike" => Ok(IAMOperator::ForAllValuesStringNotLike),
            "ForAnyValue:StringNotLike" => Ok(IAMOperator::ForAnyValueStringNotLike),
            "NumericEquals" => Ok(IAMOperator::NumericEquals),
            "NumericNotEquals" => Ok(IAMOperator::NumericNotEquals),
            "NumericLessThan" => Ok(IAMOperator::NumericLessThan),
            "NumericLessThanEquals" => Ok(IAMOperator::NumericLessThanEquals),
            "NumericGreaterThan" => Ok(IAMOperator::NumericGreaterThan),
            "NumericGreaterThanEquals" => Ok(IAMOperator::NumericGreaterThanEquals),
            "DateEquals" => Ok(IAMOperator::DateEquals),
            "DateNotEquals" => Ok(IAMOperator::DateNotEquals),
            "DateLessThan" => Ok(IAMOperator::DateLessThan),
            "DateLessThanEquals" => Ok(IAMOperator::DateLessThanEquals),
            "DateGreaterThan" => Ok(IAMOperator::DateGreaterThan),
            "DateGreaterThanEquals" => Ok(IAMOperator::DateGreaterThanEquals),
            "Bool" => Ok(IAMOperator::Bool),
            "ForAllValues:Bool" => Ok(IAMOperator::ForAllValuesBool),
            "ForAnyValue:Bool" => Ok(IAMOperator::ForAnyValueBool),
            "BinaryEquals" => Ok(IAMOperator::BinaryEquals),
            "IpAddress" => Ok(IAMOperator::IpAddress),
            "NotIpAddress" => Ok(IAMOperator::NotIpAddress),
            "ArnEquals" => Ok(IAMOperator::ArnEquals),
            "ArnLike" => Ok(IAMOperator::ArnLike),
            "ArnNotEquals" => Ok(IAMOperator::ArnNotEquals),
            "ArnNotLike" => Ok(IAMOperator::ArnNotLike),
            "ForAllValues:ArnEquals" => Ok(IAMOperator::ForAllValuesArnEquals),
            "ForAllValues:ArnLike" => Ok(IAMOperator::ForAllValuesArnLike),
            "ForAnyValue:ArnEquals" => Ok(IAMOperator::ForAnyValueArnEquals),
            "ForAnyValue:ArnLike" => Ok(IAMOperator::ForAnyValueArnLike),
            "ForAllValues:ArnNotEquals" => Ok(IAMOperator::ForAllValuesArnNotEquals),
            "ForAllValues:ArnNotLike" => Ok(IAMOperator::ForAllValuesArnNotLike),
            "ForAnyValue:ArnNotEquals" => Ok(IAMOperator::ForAnyValueArnNotEquals),
            "ForAnyValue:ArnNotLike" => Ok(IAMOperator::ForAnyValueArnNotLike),
            "Null" => Ok(IAMOperator::Null),
            "StringEqualsIfExists" => Ok(IAMOperator::StringEqualsIfExists),
            "StringNotEqualsIfExists" => Ok(IAMOperator::StringNotEqualsIfExists),
            "StringEqualsIgnoreCaseIfExists" => Ok(IAMOperator::StringEqualsIgnoreCaseIfExists),
            "StringNotEqualsIgnoreCaseIfExists" => {
                Ok(IAMOperator::StringNotEqualsIgnoreCaseIfExists)
            }
            "StringLikeIfExists" => Ok(IAMOperator::StringLikeIfExists),
            "StringNotLikeIfExists" => Ok(IAMOperator::StringNotLikeIfExists),
            "NumericEqualsIfExists" => Ok(IAMOperator::NumericEqualsIfExists),
            "NumericNotEqualsIfExists" => Ok(IAMOperator::NumericNotEqualsIfExists),
            "NumericLessThanIfExists" => Ok(IAMOperator::NumericLessThanIfExists),
            "NumericLessThanEqualsIfExists" => Ok(IAMOperator::NumericLessThanEqualsIfExists),
            "NumericGreaterThanIfExists" => Ok(IAMOperator::NumericGreaterThanIfExists),
            "NumericGreaterThanEqualsIfExists" => Ok(IAMOperator::NumericGreaterThanEqualsIfExists),
            "DateEqualsIfExists" => Ok(IAMOperator::DateEqualsIfExists),
            "DateNotEqualsIfExists" => Ok(IAMOperator::DateNotEqualsIfExists),
            "DateLessThanIfExists" => Ok(IAMOperator::DateLessThanIfExists),
            "DateLessThanEqualsIfExists" => Ok(IAMOperator::DateLessThanEqualsIfExists),
            "DateGreaterThanIfExists" => Ok(IAMOperator::DateGreaterThanIfExists),
            "DateGreaterThanEqualsIfExists" => Ok(IAMOperator::DateGreaterThanEqualsIfExists),
            "BoolIfExists" => Ok(IAMOperator::BoolIfExists),
            "BinaryEqualsIfExists" => Ok(IAMOperator::BinaryEqualsIfExists),
            "IpAddressIfExists" => Ok(IAMOperator::IpAddressIfExists),
            "NotIpAddressIfExists" => Ok(IAMOperator::NotIpAddressIfExists),
            "ArnEqualsIfExists" => Ok(IAMOperator::ArnEqualsIfExists),
            "ArnLikeIfExists" => Ok(IAMOperator::ArnLikeIfExists),
            "ArnNotEqualsIfExists" => Ok(IAMOperator::ArnNotEqualsIfExists),
            "ArnNotLikeIfExists" => Ok(IAMOperator::ArnNotLikeIfExists),
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
        let operator = IAMOperator::StringEquals;
        let json = serde_json::to_string(&operator).unwrap();
        assert_eq!(json, "\"StringEquals\"");

        let deserialized: IAMOperator = serde_json::from_str(&json).unwrap();
        assert_eq!(operator, deserialized);
    }

    #[test]
    fn test_multivalued_operators() {
        let operator = IAMOperator::ForAllValuesStringEquals;
        let json = serde_json::to_string(&operator).unwrap();
        assert_eq!(json, "\"ForAllValues:StringEquals\"");

        let deserialized: IAMOperator = serde_json::from_str(&json).unwrap();
        assert_eq!(operator, deserialized);
    }

    #[test]
    fn test_operator_categories() {
        assert!(IAMOperator::StringEquals.is_string_operator());
        assert!(IAMOperator::NumericEquals.is_numeric_operator());
        assert!(IAMOperator::DateEquals.is_date_operator());
        assert!(IAMOperator::Bool.is_boolean_operator());
        assert!(IAMOperator::ArnEquals.is_arn_operator());
        assert!(IAMOperator::IpAddress.is_ip_operator());
        assert!(IAMOperator::BinaryEquals.is_binary_operator());
    }

    #[test]
    fn test_operator_features() {
        assert!(IAMOperator::StringLike.supports_wildcards());
        assert!(IAMOperator::StringEquals.supports_policy_variables());
        assert!(!IAMOperator::NumericEquals.supports_policy_variables());
        assert!(IAMOperator::ForAllValuesStringEquals.is_multivalued_operator());
        assert!(IAMOperator::StringEqualsIfExists.is_if_exists_operator());
        assert!(IAMOperator::StringNotEquals.is_negated_operator());

        // Test multiple values support
        assert!(IAMOperator::StringEquals.supports_multiple_values());
        assert!(IAMOperator::StringNotEquals.supports_multiple_values());
        assert!(IAMOperator::NumericEquals.supports_multiple_values());
        assert!(IAMOperator::DateEquals.supports_multiple_values());
        assert!(IAMOperator::IpAddress.supports_multiple_values());
        assert!(IAMOperator::ArnEquals.supports_multiple_values());

        // These should not support multiple values
        assert!(!IAMOperator::Bool.supports_multiple_values());
        assert!(!IAMOperator::BoolIfExists.supports_multiple_values());
        assert!(!IAMOperator::Null.supports_multiple_values());
    }

    #[test]
    fn test_operator_category_strings() {
        assert_eq!(IAMOperator::StringEquals.category(), OperatorType::String);
        assert_eq!(IAMOperator::NumericEquals.category(), OperatorType::Numeric);
        assert_eq!(IAMOperator::DateEquals.category(), OperatorType::Date);
        assert_eq!(IAMOperator::Bool.category(), OperatorType::Boolean);
        assert_eq!(IAMOperator::BinaryEquals.category(), OperatorType::Binary);
        assert_eq!(IAMOperator::IpAddress.category(), OperatorType::IpAddress);
        assert_eq!(IAMOperator::ArnEquals.category(), OperatorType::Arn);
        assert_eq!(IAMOperator::Null.category(), OperatorType::Null);
    }

    #[test]
    fn test_operator_string_conversion() {
        assert_eq!(IAMOperator::StringEquals.as_str(), "StringEquals");
        assert_eq!(
            IAMOperator::ForAllValuesStringEquals.as_str(),
            "ForAllValues:StringEquals"
        );
        assert_eq!(
            IAMOperator::StringEqualsIfExists.as_str(),
            "StringEqualsIfExists"
        );
    }

    #[test]
    fn test_operator_from_str() {
        assert_eq!(
            "StringEquals".parse::<IAMOperator>().unwrap(),
            IAMOperator::StringEquals
        );
        assert_eq!(
            "ForAllValues:StringEquals".parse::<IAMOperator>().unwrap(),
            IAMOperator::ForAllValuesStringEquals
        );
        assert_eq!(
            "StringEqualsIfExists".parse::<IAMOperator>().unwrap(),
            IAMOperator::StringEqualsIfExists
        );

        assert!("InvalidOperator".parse::<IAMOperator>().is_err());
    }
}
