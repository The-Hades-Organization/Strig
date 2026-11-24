fn main() {
    let _: strig::dsl::Policy = strig_macros::policy!("language blocks\n\ntarget_kinds = [org]\n\npermission org.read {\n  targets = [org]\n}\n");
}
