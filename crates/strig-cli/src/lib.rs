//! The `strig` command, as a library so its behavior is testable without a process.

mod audit_command;
mod junit;
mod report;
mod test_command;

use std::io::Write;
use std::process::ExitCode;

pub use junit::junit_xml;
pub use report::human;

/// Everything went as asked.
pub const EXIT_OK: u8 = 0;
/// A case failed or could not be judged.
pub const EXIT_FAILED: u8 = 1;
/// The arguments, the policy or a test file are wrong, or there is nothing to run.
pub const EXIT_USAGE: u8 = 2;

const USAGE: &str = "\
usage: strig <command> [options]

commands:
  test <dir> [--junit <file>]   run the *.strig-test.json files of <dir> against its *.strig policy
  audit report <trail.jsonl> [--json] [--anchor-head <hash>] [--anchor-start <hash>]
               [--timestamp <resp.tsr>]... [--root <ca.pem>]...
                                conformance report over an audit trail; exits 1 when it does not conform
  help                          show this text
";

/// Runs the command `args` (without the program name), writing to `out` and `err`.
pub fn run(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> ExitCode {
    ExitCode::from(execute(args, out, err))
}

/// Like [`run`], with the exit code as a number (`EXIT_OK`, `EXIT_FAILED` or `EXIT_USAGE`).
pub fn execute(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    match args.first().map(String::as_str) {
        Some("audit") => audit_command::run(&args[1..], out, err),
        Some("test") => test_command::run(&args[1..], out, err),
        Some("help" | "--help" | "-h") => {
            write!(out, "{USAGE}").ok();
            EXIT_OK
        }
        Some(other) => {
            writeln!(err, "strig: unknown command `{other}`\n\n{USAGE}").ok();
            EXIT_USAGE
        }
        None => {
            write!(err, "{USAGE}").ok();
            EXIT_USAGE
        }
    }
}

/// Entry point of the binary.
pub fn main_with_env() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    run(&args, &mut std::io::stdout(), &mut std::io::stderr())
}
