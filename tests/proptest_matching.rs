//! Property-based checks for the two pieces of code that take
//! attacker-controlled input: wildcard matching and policy-variable
//! interpolation.
//!
//! The unit tests next to each function pin individual examples. These check the
//! properties those examples stand for — agreement with an independently written
//! reference matcher, and the absence of panics — over generated input that is
//! heavy in metacharacters.

use iam_rs::{Arn, Context, interpolate_variables};
use proptest::prelude::*;

/// Strings drawn from a small alphabet full of wildcard and variable syntax.
fn input() -> impl Strategy<Value = String> {
    proptest::collection::vec(
        prop_oneof![
            Just('a'),
            Just('b'),
            Just('k'),
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

/// Reference glob matcher: dynamic programming over characters, O(n·m).
///
/// Written independently of the implementation under test (a greedy matcher with
/// backtracking to the last `*`), so agreement between the two is evidence rather
/// than a restatement of the same code.
fn reference_match(text: &str, pattern: &str) -> bool {
    let text: Vec<char> = text.chars().collect();
    let pattern: Vec<char> = pattern.chars().collect();

    // `reachable[j]`: the text consumed so far matches the first `j` pattern chars.
    let mut reachable = vec![false; pattern.len() + 1];
    reachable[0] = true;
    for (j, &p) in pattern.iter().enumerate() {
        reachable[j + 1] = p == '*' && reachable[j];
    }

    for &t in &text {
        let mut next = vec![false; pattern.len() + 1];
        for (j, &p) in pattern.iter().enumerate() {
            next[j + 1] = match p {
                '*' => next[j] || reachable[j + 1],
                '?' => reachable[j],
                literal => literal == t && reachable[j],
            };
        }
        reachable = next;
    }

    reachable[pattern.len()]
}

proptest! {
    #[test]
    fn wildcard_matching_agrees_with_a_reference_matcher(text in input(), pattern in input()) {
        prop_assert_eq!(
            Arn::wildcard_match(&text, &pattern),
            reference_match(&text, &pattern),
            "text {:?}, pattern {:?}",
            text,
            pattern
        );
    }

    #[test]
    fn interpolation_never_panics(input in input(), value in input()) {
        let context = Context::new().with_string("k", value);
        let _ = interpolate_variables(&input, &context);
    }

    #[test]
    fn interpolation_substitutes_present_keys(value in "[abk]{1,8}") {
        let context = Context::new().with_string("k", value.clone());
        prop_assert_eq!(
            interpolate_variables("x${k}y", &context).unwrap(),
            format!("x{value}y")
        );
    }

    #[test]
    fn interpolation_without_variables_is_the_identity(input in input()) {
        prop_assume!(!input.contains("${"));
        let context = Context::new();
        prop_assert_eq!(interpolate_variables(&input, &context).unwrap(), input);
    }
}
