fn main() {
    let _ = themis_macros::policy!("language blocks\n\npermission org.read {\n  bogus = 1\n}\n");
}
