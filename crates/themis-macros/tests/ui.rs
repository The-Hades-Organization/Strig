//! Compile-time behaviour: valid policies build, invalid ones stop the build with the diagnostic.

#[test]
fn compile_cases() {
    let cases = trybuild::TestCases::new();
    cases.pass("tests/ui/pass.rs");
    cases.compile_fail("tests/ui/bad_field.rs");
    cases.compile_fail("tests/ui/unknown_language.rs");
    cases.compile_fail("tests/ui/not_a_literal.rs");
    cases.compile_fail("tests/ui/include_outside.rs");
}
