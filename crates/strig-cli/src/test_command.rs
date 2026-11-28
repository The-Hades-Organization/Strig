//! `strig test <dir> [--junit <file>]`.

use std::io::Write;
use std::path::PathBuf;

use strig::dsl::fs;
use strig::dsl::testing;

use crate::{EXIT_FAILED, EXIT_OK, EXIT_USAGE, human, junit_xml};

pub(crate) fn run(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let mut dir: Option<&str> = None;
    let mut junit: Option<PathBuf> = None;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--junit" => match rest.next() {
                Some(path) => junit = Some(PathBuf::from(path)),
                None => return usage(err, "`--junit` needs a file"),
            },
            flag if flag.starts_with('-') => return usage(err, &format!("unknown option `{flag}`")),
            path if dir.is_none() => dir = Some(path),
            _ => return usage(err, "`test` takes one directory"),
        }
    }
    let Some(dir) = dir else {
        return usage(err, "`test` needs the directory of the policy");
    };

    let built = match fs::read_dir(dir).map_err(|e| e.to_string()).and_then(|project| {
        if project.is_empty() {
            return Err(format!("no *.strig file in `{dir}`"));
        }
        project.build().map_err(|e| e.to_string())
    }) {
        Ok(built) => built,
        Err(message) => return usage(err, &message),
    };
    let files = match fs::read_tests(dir) {
        Ok(files) if files.is_empty() => return usage(err, &format!("no *.strig-test.json file in `{dir}`")),
        Ok(files) => files,
        Err(error) => return usage(err, &error.to_string()),
    };

    let report = testing::run(&built.policy, &files);
    write!(out, "{}", human(&report)).ok();
    if let Some(path) = junit
        && let Err(error) = std::fs::write(&path, junit_xml(&report))
    {
        return usage(err, &format!("cannot write `{}`: {error}", path.display()));
    }
    if report.is_success() { EXIT_OK } else { EXIT_FAILED }
}

fn usage(err: &mut dyn Write, message: &str) -> u8 {
    writeln!(err, "strig test: {message}").ok();
    EXIT_USAGE
}
