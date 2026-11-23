fn main() {
    let _: themis::dsl::Policy = themis_macros::policy!("language blocks\n\ntarget_kinds = [org]\n\npermission org.read {\n  targets = [org]\n}\n");
}
