//! `strig import casbin|openfga`: converts another library's model and policy into a `.strig` file.

use std::io::Write;
use std::path::PathBuf;

use strig::dsl::{Language, print};
use strig::import::{ImportError, Report, casbin, openfga};

use crate::{EXIT_FAILED, EXIT_OK, EXIT_USAGE};

const USAGE: &str = "\
usage: strig import casbin <model.conf> <policy.csv> -o <dir> [--language blocks|rules|actors] [--action <name>]...
       strig import openfga <model> <tuples> -o <dir> [--language blocks|rules|actors]";

struct Args {
    inputs: Vec<String>,
    output: PathBuf,
    language: Language,
    actions: Vec<String>,
}

pub(crate) fn run(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let Some((source, rest)) = args.split_first() else {
        return usage(err, "`import` needs `casbin` or `openfga`");
    };
    let parsed = match parse(rest, source == "casbin") {
        Ok(parsed) => parsed,
        Err(message) => return usage(err, &message),
    };
    match source.as_str() {
        "casbin" => casbin_import(&parsed, out, err),
        "openfga" => openfga_import(&parsed, out, err),
        other => usage(err, &format!("unknown source `{other}`: `casbin` or `openfga`")),
    }
}

fn parse(args: &[String], accepts_actions: bool) -> Result<Args, String> {
    let mut inputs = Vec::new();
    let mut output = None;
    let mut language = Language::Blocks;
    let mut actions = Vec::new();
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "-o" | "--output" => output = Some(PathBuf::from(rest.next().ok_or("`-o` needs a directory")?)),
            "--language" => {
                language = match rest.next().map(String::as_str) {
                    Some("blocks") => Language::Blocks,
                    Some("rules") => Language::Rules,
                    Some("actors") => Language::Actors,
                    _ => return Err("`--language` is `blocks`, `rules` or `actors`".to_string()),
                }
            }
            "--action" if accepts_actions => actions.push(rest.next().ok_or("`--action` needs a name")?.clone()),
            flag if flag.starts_with('-') => return Err(format!("unknown option `{flag}`")),
            path => inputs.push(path.to_string()),
        }
    }
    if inputs.len() != 2 {
        return Err("expected the model file and the policy (or tuples) file".to_string());
    }
    let output = output.ok_or("`-o <dir>` is required")?;
    Ok(Args {
        inputs,
        output,
        language,
        actions,
    })
}

fn read(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|error| format!("cannot read `{path}`: {error}"))
}

fn casbin_import(args: &Args, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let (model, policy) = match (read(&args.inputs[0]), read(&args.inputs[1])) {
        (Ok(model), Ok(policy)) => (model, policy),
        (Err(message), _) | (_, Err(message)) => return usage(err, &message),
    };
    let options = casbin::Options {
        actions: args.actions.clone(),
        model_file: args.inputs[0].clone(),
        policy_file: args.inputs[1].clone(),
    };
    match casbin::import(&model, &policy, &options) {
        Ok(imported) => write_policy(imported.policy(), imported.report(), args, out, err),
        Err(error) => refused(&error, out),
    }
}

fn openfga_import(args: &Args, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let (model, tuples) = match (read(&args.inputs[0]), read(&args.inputs[1])) {
        (Ok(model), Ok(tuples)) => (model, tuples),
        (Err(message), _) | (_, Err(message)) => return usage(err, &message),
    };
    let options = openfga::Options {
        model_file: args.inputs[0].clone(),
        tuples_file: args.inputs[1].clone(),
    };
    match openfga::import(&model, &tuples, &options) {
        Ok(imported) => write_policy(imported.policy(), imported.report(), args, out, err),
        Err(error) => refused(&error, out),
    }
}

fn write_policy(
    policy: &strig::dsl::Policy,
    report: &Report,
    args: &Args,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let text = match print(policy, args.language) {
        Ok(text) => text,
        Err(error) => return usage(err, &format!("cannot print the imported policy: {error}")),
    };
    let target = args.output.join("policy.strig");
    if let Err(error) = std::fs::create_dir_all(&args.output).and_then(|()| std::fs::write(&target, text)) {
        return usage(err, &format!("cannot write `{}`: {error}", target.display()));
    }
    writeln!(out, "wrote {}", target.display()).ok();
    write!(out, "{report}").ok();
    EXIT_OK
}

fn refused(error: &ImportError, out: &mut dyn Write) -> u8 {
    write!(out, "{}", error.report).ok();
    EXIT_FAILED
}

fn usage(err: &mut dyn Write, message: &str) -> u8 {
    writeln!(err, "strig import: {message}\n\n{USAGE}").ok();
    EXIT_USAGE
}
