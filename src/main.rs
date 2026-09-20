use std::fs;
use std::path::PathBuf;

use clap::Parser;

use tfstatescan::scan::{scan, DetectorKind};
use tfstatescan::state::parse_state;

#[derive(Parser)]
#[command(
    name = "tfstatescan",
    about = "Scans a Terraform .tfstate file for plaintext secrets persisted in resource attributes"
)]
struct Cli {
    /// Path to a Terraform state file (format version 4, Terraform 0.12+).
    state: PathBuf,

    /// Emit findings as a JSON array instead of the human-readable report.
    #[arg(long)]
    json: bool,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let content = fs::read_to_string(&cli.state)
        .map_err(|e| anyhow::anyhow!("reading {}: {e}", cli.state.display()))?;
    let state = parse_state(&content).map_err(|e| anyhow::anyhow!(e))?;
    let findings = scan(&state);

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&findings)?);
    } else if findings.is_empty() {
        println!(
            "{}: no plaintext secrets found — {} resource(s) checked",
            cli.state.display(),
            state.resources.len()
        );
    } else {
        println!(
            "{}: {} plaintext secret(s) found across {} resource(s)\n",
            cli.state.display(),
            findings.len(),
            state.resources.len()
        );
        for f in &findings {
            let tag = match f.detector {
                DetectorKind::Known => "known",
                DetectorKind::Heuristic => "heuristic",
            };
            println!(
                "[{tag}] {}.{} (instance #{}) {} = {}",
                f.resource_type,
                f.resource_name,
                f.instance_index,
                f.attribute_path,
                f.redacted_value
            );
        }
    }

    if !findings.is_empty() {
        std::process::exit(1);
    }
    Ok(())
}
