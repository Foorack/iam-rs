use crate::{Context, ContextValue, EvaluationError};

/// Represents a parsed policy variable
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyVariable {
    /// The context key to look up
    pub key: String,
    /// Optional default value if key is not found
    pub default_value: Option<String>,
}

impl PolicyVariable {
    /// Parse a policy variable from a string like "${aws:PrincipalTag/team, 'company-wide'}"
    pub fn parse(input: &str) -> Result<Self, EvaluationError> {
        if !input.starts_with("${") || !input.ends_with('}') {
            return Err(EvaluationError::InvalidVariable(
                "Policy variable must be wrapped in ${}".to_string(),
            ));
        }

        let content = &input[2..input.len() - 1]; // Remove ${ and }

        if let Some(comma_pos) = content.find(", '") {
            // Has default value
            let key = content[..comma_pos].trim().to_string();
            let default_part = &content[comma_pos + 3..]; // Skip ", '"

            if !default_part.ends_with('\'') {
                return Err(EvaluationError::InvalidVariable(
                    "Default value must be wrapped in single quotes".to_string(),
                ));
            }

            let default_value = default_part[..default_part.len() - 1].to_string(); // Remove trailing '

            Ok(PolicyVariable {
                key,
                default_value: Some(default_value),
            })
        } else {
            // No default value
            Ok(PolicyVariable {
                key: content.trim().to_string(),
                default_value: None,
            })
        }
    }

    /// Resolve the variable against a context
    pub fn resolve(&self, context: &Context) -> String {
        match context.get(&self.key) {
            Some(ContextValue::String(value)) => value.clone(),
            Some(other) => {
                // Convert other types to string representation
                match other {
                    ContextValue::Boolean(b) => b.to_string(),
                    ContextValue::Number(n) => n.to_string(),
                    ContextValue::DateTime(dt) => dt.to_rfc3339(),
                    ContextValue::StringList(list) => list.join(","),
                    _ => self.default_value.clone().unwrap_or_default(),
                }
            }
            None => self.default_value.clone().unwrap_or_default(),
        }
    }
}

/// Interpolate policy variables in a string
pub fn interpolate_variables(input: &str, context: &Context) -> Result<String, EvaluationError> {
    let mut result = input.to_string();
    let mut start = 0;

    while let Some(var_start) = result[start..].find("${") {
        let absolute_start = start + var_start;
        if let Some(var_end) = result[absolute_start..].find('}') {
            let absolute_end = absolute_start + var_end + 1;
            let variable_str = &result[absolute_start..absolute_end];

            let variable = PolicyVariable::parse(variable_str)?;
            let resolved_value = variable.resolve(context);

            result.replace_range(absolute_start..absolute_end, &resolved_value);
            start = absolute_start + resolved_value.len();
        } else {
            return Err(EvaluationError::InvalidVariable(
                "Unclosed policy variable".to_string(),
            ));
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_variable_with_default() {
        let var = PolicyVariable::parse("${aws:PrincipalTag/team, 'company-wide'}").unwrap();
        assert_eq!(var.key, "aws:PrincipalTag/team");
        assert_eq!(var.default_value, Some("company-wide".to_string()));
    }

    #[test]
    fn test_parse_variable_without_default() {
        let var = PolicyVariable::parse("${aws:username}").unwrap();
        assert_eq!(var.key, "aws:username");
        assert_eq!(var.default_value, None);
    }

    #[test]
    fn test_resolve_with_context() {
        let mut context = Context::new();
        context.insert(
            "aws:PrincipalTag/team".to_string(),
            ContextValue::String("yellow".to_string()),
        );

        let var = PolicyVariable::parse("${aws:PrincipalTag/team, 'company-wide'}").unwrap();
        assert_eq!(var.resolve(&context), "yellow");
    }

    #[test]
    fn test_resolve_with_default() {
        let context = Context::new(); // Empty context

        let var = PolicyVariable::parse("${aws:PrincipalTag/team, 'company-wide'}").unwrap();
        assert_eq!(var.resolve(&context), "company-wide");
    }

    #[test]
    fn test_interpolate_full_string() {
        let mut context = Context::new();
        context.insert(
            "aws:PrincipalTag/team".to_string(),
            ContextValue::String("yellow".to_string()),
        );

        let input = "arn:aws:s3:::amzn-s3-demo-bucket-${aws:PrincipalTag/team, 'company-wide'}";
        let result = interpolate_variables(input, &context).unwrap();
        assert_eq!(result, "arn:aws:s3:::amzn-s3-demo-bucket-yellow");
    }

    #[test]
    fn test_interpolate_with_default() {
        let context = Context::new(); // Empty context

        let input = "arn:aws:s3:::amzn-s3-demo-bucket-${aws:PrincipalTag/team, 'company-wide'}";
        let result = interpolate_variables(input, &context).unwrap();
        assert_eq!(result, "arn:aws:s3:::amzn-s3-demo-bucket-company-wide");
    }
}
