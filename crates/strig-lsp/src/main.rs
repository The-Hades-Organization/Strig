fn main() -> std::process::ExitCode {
    match strig_lsp::serve_stdio() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("strig-lsp: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
