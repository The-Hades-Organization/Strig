fn main() {
    let _ = themis_macros::policy!(r#"language blocks

# café ☃ ñ
target_kinds = [org]

permission org.read {
  targets = [org]
  bogus = 1
}
"#);
}
