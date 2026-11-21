use std::path::PathBuf;
use std::process::ExitCode;

use themis_inspect::{Inspector, Scenario, Trail, render};

const USAGE: &str = "\
uso:
  themis-inspect [--scenario CENARIO.json] [--audit TRILHA.jsonl]     abre a janela
  themis-inspect explain --scenario F --subject S --permission P --resource R
  themis-inspect matrix  --scenario F --resource R [--disable ID]... [--add GRANT.json]...
  themis-inspect audit   --audit F [--scenario F]                     lista, confere a cadeia e reavalia

O cenário é um JSON com spec, grants, tuples, env, subjects e resources (ver README).";

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
}

fn parse() -> Result<Args, String> {
    let mut args = Args::default();
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("{arg} precisa de valor"));
        match arg.as_str() {
            "--scenario" => args.scenario = Some(value()?.into()),
            "--audit" => args.audit = Some(value()?.into()),
            "--subject" => args.subject = Some(value()?),
            "--permission" => args.permission = Some(value()?),
            "--resource" => args.resource = Some(value()?),
            "--disable" => args.disable.push(value()?),
            "--add" => args.add.push(value()?.into()),
            "-h" | "--help" => return Err(String::new()),
            command if args.command.is_none() && !command.starts_with('-') => args.command = Some(command.into()),
            other => return Err(format!("argumento desconhecido: {other}")),
        }
    }
    Ok(args)
}

fn inspector(args: &Args) -> Result<Inspector, String> {
    let path = args.scenario.as_ref().ok_or("falta --scenario")?;
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
    value.as_deref().ok_or_else(|| format!("falta {flag}"))
}

fn run(args: Args) -> Result<(), String> {
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
            let trail = Trail::load(args.audit.as_ref().ok_or("falta --audit")?).map_err(|e| e.to_string())?;
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
        Some(other) => Err(format!("comando desconhecido: {other}")),
    }
}

#[cfg(feature = "gui")]
fn open_window(args: Args) -> Result<(), String> {
    themis_inspect::gui::run(args.scenario, args.audit);
    Ok(())
}

#[cfg(not(feature = "gui"))]
fn open_window(_: Args) -> Result<(), String> {
    Err("compilado sem a feature `gui`: use explain, matrix ou audit".into())
}

fn main() -> ExitCode {
    match parse().and_then(run) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            if !message.is_empty() {
                eprintln!("themis-inspect: {message}");
            }
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}
