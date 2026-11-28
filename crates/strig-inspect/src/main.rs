use std::path::PathBuf;
use std::process::ExitCode;

use strig_inspect::{Inspector, Scenario, Trail, render};

const USAGE: &str = "\
usage:
  strig-inspect [--scenario SCENARIO.json] [--audit TRAIL.jsonl]   opens the window
      [--subject S] [--permission P] [--resource R] [--disable ID]... [--tab evaluation|matrix|audit]
  strig-inspect explain --scenario F --subject S --permission P --resource R
  strig-inspect matrix  --scenario F --resource R [--disable ID]... [--add GRANT.json]...
  strig-inspect audit   --audit F [--scenario F]                     lists, checks the chain and re-evaluates
  strig-inspect fmt [--check] FILE|DIR                              formats .strig files; --check only lists and exits with 1

The scenario is a JSON file with spec, grants, tuples, env, subjects and resources (see the README).";

#[derive(Default)]
struct Args {
    command: Option<String>,
    scenario: Option<PathBuf>,
    audit: Option<PathBuf>,
    subject: Option<String>,
    permission: Option<String>,
    resource: Option<String>,
    disable: Vec<String>,
    add: Vec<PathBuf>,
    tab: Option<String>,
    check: bool,
    path: Option<PathBuf>,
}

fn parse() -> Result<Args, String> {
    let mut args = Args::default();
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("{arg} needs a value"));
        match arg.as_str() {
            "--scenario" => args.scenario = Some(value()?.into()),
            "--audit" => args.audit = Some(value()?.into()),
            "--subject" => args.subject = Some(value()?),
            "--permission" => args.permission = Some(value()?),
            "--resource" => args.resource = Some(value()?),
            "--disable" => args.disable.push(value()?),
            "--add" => args.add.push(value()?.into()),
            "--tab" => args.tab = Some(value()?),
            "--check" => args.check = true,
            "-h" | "--help" => return Err(String::new()),
            command if args.command.is_none() && !command.starts_with('-') => args.command = Some(command.into()),
            path if args.command.as_deref() == Some("fmt") && args.path.is_none() && !path.starts_with('-') => {
                args.path = Some(path.into());
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(args)
}

fn inspector(args: &Args) -> Result<Inspector, String> {
    let path = args.scenario.as_ref().ok_or("missing --scenario")?;
    let mut inspector = Inspector::new(Scenario::load(path).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    for id in &args.disable {
        inspector.toggle(id);
    }
    for path in &args.add {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        inspector.add(serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?);
    }
    Ok(inspector)
}

fn need<'a>(value: &'a Option<String>, flag: &str) -> Result<&'a str, String> {
    value.as_deref().ok_or_else(|| format!("missing {flag}"))
}

fn run(args: Args) -> Result<ExitCode, String> {
    if args.command.as_deref() == Some("fmt") {
        return format_files(&args);
    }
    run_inspect(args).map(|()| ExitCode::SUCCESS)
}

fn run_inspect(args: Args) -> Result<(), String> {
    match args.command.as_deref() {
        Some("explain") => {
            let inspector = inspector(&args)?;
            let explanation = inspector
                .explain_named(
                    need(&args.subject, "--subject")?,
                    need(&args.permission, "--permission")?,
                    need(&args.resource, "--resource")?,
                )
                .map_err(|e| e.to_string())?;
            print!("{}", render::explanation(&explanation));
            if !explanation.decision.is_allowed() {
                let asked = (
                    need(&args.subject, "--subject")?,
                    need(&args.permission, "--permission")?,
                    need(&args.resource, "--resource")?,
                );
                let why = inspector
                    .why_not_named(asked.0, asked.1, asked.2)
                    .map_err(|e| e.to_string())?;
                if let Some(why) = why {
                    print!("\n{}", render::remedies(&why));
                }
            }
            Ok(())
        }
        Some("matrix") => {
            let inspector = inspector(&args)?;
            let matrix = inspector
                .matrix(need(&args.resource, "--resource")?)
                .map_err(|e| e.to_string())?;
            print!("{}", render::matrix(&matrix));
            Ok(())
        }
        Some("audit") => {
            let trail = Trail::load(args.audit.as_ref().ok_or("missing --audit")?).map_err(|e| e.to_string())?;
            let inspector = args.scenario.is_some().then(|| inspector(&args)).transpose()?;
            println!("{}", render::chain(&trail.chain()));
            for record in &trail.records {
                println!("{}", render::record_line(record));
                if let Some(replay) = inspector.as_ref().and_then(|i| Trail::replay(record, i)) {
                    println!("    {}", render::replay(&replay));
                }
            }
            Ok(())
        }
        None => open_window(args),
        Some(other) => Err(format!("unknown command: {other}")),
    }
}

fn format_files(args: &Args) -> Result<ExitCode, String> {
    let path = args.path.as_ref().ok_or("fmt needs a file or a directory")?;
    let report = strig_inspect::fmt::run(path, args.check)?;
    for file in &report.changed {
        println!("{}{}", if args.check { "" } else { "formatted: " }, file.display());
    }
    for error in &report.errors {
        eprintln!("{error}");
    }
    if !args.check {
        println!("{} formatted, {} already tidy", report.changed.len(), report.unchanged);
    }
    let failed = !report.errors.is_empty() || (args.check && !report.changed.is_empty());
    Ok(if failed { ExitCode::from(1) } else { ExitCode::SUCCESS })
}

#[cfg(feature = "gui")]
fn open_window(args: Args) -> Result<(), String> {
    let tab = match args.tab.as_deref() {
        None | Some("evaluation") => strig_inspect::gui::Tab::Evaluate,
        Some("matrix") => strig_inspect::gui::Tab::Matrix,
        Some("audit") => strig_inspect::gui::Tab::Audit,
        Some(other) => {
            return Err(format!("unknown tab: {other} (use evaluation, matrix or audit)"));
        }
    };
    let start = strig_inspect::gui::Start {
        subject: args.subject,
        permission: args.permission,
        resource: args.resource,
        disable: args.disable,
        tab: args.tab.is_some().then_some(tab),
    };
    strig_inspect::gui::run(args.scenario, args.audit, start);
    Ok(())
}

#[cfg(not(feature = "gui"))]
fn open_window(_: Args) -> Result<(), String> {
    Err("built without the `gui` feature: use explain, matrix or audit".into())
}

fn main() -> ExitCode {
    match parse().and_then(run) {
        Ok(code) => code,
        Err(message) => {
            if !message.is_empty() {
                eprintln!("strig-inspect: {message}");
            }
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}
