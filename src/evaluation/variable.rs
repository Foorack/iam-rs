use crate::{Context, ContextValue, EvaluationError};

/// Represents a parsed policy variable
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct PolicyVariable {
    /// The context key to look up
    pub key: String,
    /// Optional default value if key is not found
    pub default_value: Option<String>,
}

impl PolicyVariable {
    /// Parse a policy variable from a string like "${aws:PrincipalTag/team, 'company-wide'}"
    ///
    /// AWS default values are wrapped in single quotes and separated from the
    /// key by a comma, e.g. `${aws:username, 'default'}`. Whitespace after the
    /// comma is optional. Any other use of a comma (unquoted or double-quoted
    /// defaults) is rejected so malformed variables fail loudly instead of
    /// silently resolving to an empty string.
    pub fn parse(input: &str) -> Result<Self, EvaluationError> {
        if !input.starts_with("${") || !input.ends_with('}') {
            return Err(EvaluationError::InvalidVariable(
                "Policy variable must be wrapped in ${}".to_string(),
            ));
        }

        let content = &input[2..input.len() - 1]; // Remove ${ and }

        // A comma separates the key from an optional default value.
        if let Some(comma_pos) = content.find(',') {
            let key = content[..comma_pos].trim().to_string();
            let default_part = content[comma_pos + 1..].trim();

            if !default_part.starts_with('\'')
                || !default_part.ends_with('\'')
                || default_part.len() < 2
            {
                return Err(EvaluationError::InvalidVariable(
                    "Default value must be wrapped in single quotes, e.g. ${key, 'default'}"
                        .to_string(),
                ));
            }

            let default_value = default_part[1..default_part.len() - 1].to_string();
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
    #[must_use]
    pub fn resolve(&self, context: &Context) -> String {
        self.resolve_checked(context).unwrap_or_default()
    }

    /// Resolve the variable, reporting an unresolvable variable as `None`.
    ///
    /// A variable is unresolvable when the context key is absent (or holds a
    /// type that does not render, such as a boolean list) *and* the policy
    /// author supplied no default. AWS calls that a null value, which does not
    /// equal anything — so it must not be confused with the empty string.
    #[must_use]
    pub fn resolve_checked(&self, context: &Context) -> Option<String> {
        match context.get(&self.key) {
            Some(ContextValue::String(value)) => Some(value.clone()),
            Some(ContextValue::Boolean(b)) => Some(b.to_string()),
            Some(ContextValue::Number(n)) => Some(n.to_string()),
            Some(ContextValue::DateTime(dt)) => Some(dt.to_rfc3339()),
            Some(ContextValue::StringList(list)) => Some(list.join(",")),
            Some(ContextValue::BooleanList(_)) | None => self.default_value.clone(),
        }
    }
}

/// Interpolate policy variables in a string
///
/// An unresolvable variable resolves to the empty string here, matching
/// [`PolicyVariable::resolve`]. AWS instead treats such a variable as null,
/// which equals nothing; that distinction is not observable through this
/// function, so the evaluation engine uses the crate-internal checked variant.
///
/// # Errors
///
/// Returns `EvaluationError::InvalidVariable` for a malformed variable, an
/// unclosed `${`, or a context-derived value containing a wildcard.
pub fn interpolate_variables(input: &str, context: &Context) -> Result<String, EvaluationError> {
    interpolate_variables_checked(input, context).map(|interpolation| interpolation.text)
}

/// The result of interpolating a policy pattern.
pub(crate) struct Interpolation {
    /// The pattern with every variable that had a value substituted.
    pub(crate) text: String,
    /// Whether at least one variable had no value and no default, which AWS
    /// treats as null rather than as an empty string.
    pub(crate) unresolved: bool,
}

pub(crate) fn interpolate_variables_checked(
    input: &str,
    context: &Context,
) -> Result<Interpolation, EvaluationError> {
    let mut result = input.to_string();
    let mut start = 0;
    let mut unresolved = false;

    while let Some(var_start) = result[start..].find("${") {
        let absolute_start = start + var_start;
        if let Some(var_end) = result[absolute_start..].find('}') {
            let absolute_end = absolute_start + var_end + 1;
            let variable_str = &result[absolute_start..absolute_end];

            let variable = PolicyVariable::parse(variable_str)?;
            // Nothing to substitute: AWS leaves the pattern with no value, so it
            // cannot equal anything. The caller decides what that means for the
            // operator it is evaluating.
            let Some(resolved_value) = variable.resolve_checked(context) else {
                unresolved = true;
                result.replace_range(absolute_start..absolute_end, "");
                start = absolute_start;
                continue;
            };

            // Context values are attacker-controlled in most deployments. Splicing
            // one into a pattern verbatim lets a value of "*" turn
            // `home/${aws:username}/*` into `home/*/*`, granting every user's home
            // directory. AWS restricts the characters it substitutes for the same
            // reason; here the policy refuses to resolve.
            //
            // A default written by the policy author is not attacker-controlled, so
            // `${aws:PrincipalTag/team, '*'}` keeps working.
            if context.get(&variable.key).is_some() && resolved_value.contains(['*', '?']) {
                return Err(EvaluationError::InvalidVariable(format!(
                    "policy variable `{variable_str}` resolved to a value containing a wildcard"
                )));
            }

            result.replace_range(absolute_start..absolute_end, &resolved_value);
            start = absolute_start + resolved_value.len();
        } else {
            return Err(EvaluationError::InvalidVariable(
                "Unclosed policy variable".to_string(),
            ));
        }
    }

    Ok(Interpolation {
        text: result,
        unresolved,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interpolate_rejects_wildcards_in_resolved_values() {
        let context = Context::new().with_string("aws:username", "*");
        let error =
            interpolate_variables("arn:aws:s3:::home/${aws:username}/*", &context).unwrap_err();
        assert!(
            matches!(error, EvaluationError::InvalidVariable(_)),
            "expected InvalidVariable, got {error:?}"
        );
    }

    #[test]
    fn test_interpolate_accepts_plain_resolved_values() {
        let context = Context::new().with_string("aws:username", "alice");
        assert_eq!(
            interpolate_variables("arn:aws:s3:::home/${aws:username}/*", &context).unwrap(),
            "arn:aws:s3:::home/alice/*"
        );
    }

    #[test]
    fn test_policy_authored_default_may_contain_a_wildcard() {
        // The default comes from the policy, not from the caller, so a wildcard
        // in it is the author's intent.
        let context = Context::new();
        assert_eq!(
            interpolate_variables("arn:aws:s3:::home/${aws:PrincipalTag/team, '*'}", &context)
                .unwrap(),
            "arn:aws:s3:::home/*"
        );
    }

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
    fn test_parse_variable_with_default_no_space() {
        // AWS separates key and default with a comma; whitespace is optional.
        let var = PolicyVariable::parse("${aws:PrincipalTag/team,'company-wide'}").unwrap();
        assert_eq!(var.key, "aws:PrincipalTag/team");
        assert_eq!(var.default_value, Some("company-wide".to_string()));
    }

    #[test]
    fn test_parse_variable_default_contains_comma() {
        // The first comma separates the key from the default, so a default
        // value may itself contain commas.
        let var = PolicyVariable::parse("${aws:username, 'Smith, John'}").unwrap();
        assert_eq!(var.key, "aws:username");
        assert_eq!(var.default_value, Some("Smith, John".to_string()));
    }

    #[test]
    fn test_parse_variable_malformed_default() {
        // Malformed defaults must error instead of being silently treated as a
        // plain key (which would resolve to an empty string and corrupt the
        // interpolated string).
        assert!(PolicyVariable::parse("${aws:username, \"john\"}").is_err());
        assert!(PolicyVariable::parse("${aws:username, john}").is_err());
        assert!(PolicyVariable::parse("${aws:username, 'john}").is_err());
        assert!(PolicyVariable::parse("${aws:username,}").is_err());
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

    #[test]
    fn test_interpolate_with_default_no_space() {
        // Regression: the no-space form used to be treated as a plain key and
        // resolve to "", silently corrupting the interpolated string.
        let context = Context::new(); // Empty context

        let input = "arn:aws:s3:::amzn-s3-demo-bucket-${aws:PrincipalTag/team,'company-wide'}";
        let result = interpolate_variables(input, &context).unwrap();
        assert_eq!(result, "arn:aws:s3:::amzn-s3-demo-bucket-company-wide");
    }
}
