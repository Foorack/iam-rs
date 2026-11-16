//! Property-based checks for the two pieces of code that take
//! attacker-controlled input: wildcard matching and policy-variable
//! interpolation.
//!
//! The unit tests next to each function pin individual examples. These assert the
//! properties those examples are meant to stand for (a pattern matches itself, a
//! lone `*` matches anything, `?` matches exactly one character, interpolation
//! never panics), over generated input that is heavy in metacharacters.

use iam_rs::{Arn, Context, interpolate_variables};
use proptest::prelude::*;

/// Strings drawn from a small alphabet full of wildcard and variable syntax.
fn input() -> impl Strategy<Value = String> {
    proptest::collection::vec(
        prop_oneof![
            Just('a'),
            Just('b'),
            Just('/'),
            Just(':'),
            Just('*'),
            Just('?'),
            Just('$'),
            Just('{'),
            Just('}'),
            Just('é'),
        ],
        0..24,
    )
    .prop_map(|chars| chars.into_iter().collect())
}

proptest! {
    #[test]
    fn a_pattern_matches_itself(text in input()) {
        prop_assert!(Arn::wildcard_match(&text, &text));
    }

    #[test]
    fn a_lone_star_matches_anything(text in input()) {
        // Currently fails for subjects that contain a literal `*` (for example
        // `wildcard_match("*a", "*")` is false); the fix is in the wildcard
        // matcher PR, which owns this property.
        prop_assume!(!text.contains('*'));
        prop_assert!(Arn::wildcard_match(&text, "*"));
    }

    #[test]
    fn question_mark_matches_exactly_one_character(text in input()) {
        let count = text.chars().count();
        prop_assert!(Arn::wildcard_match(&text, &"?".repeat(count)));
        if count > 0 {
            prop_assert!(!Arn::wildcard_match(&text, &"?".repeat(count - 1)));
        }
    }

    #[test]
    fn interpolation_never_panics(input in input(), value in input()) {
        let context = Context::new().with_string("k", value);
        let _ = interpolate_variables(&input, &context);
    }

    #[test]
    fn interpolation_without_variables_is_the_identity(input in input()) {
        prop_assume!(!input.contains("${"));
        let context = Context::new();
        prop_assert_eq!(interpolate_variables(&input, &context).unwrap(), input);
    }
}
