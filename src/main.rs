mod correlate;
mod eventlog;
mod ntfs;
mod prefetch;
mod recycle_bin;
mod registry;
mod shell;
mod shimcache;
mod srum;
mod time;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "vamparser",
    version,
    about = "Parse collected Windows forensic artifacts"
)]
struct Cli {
    /// Emit a machine-readable completion record.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Parse one .pf file or every .pf below a directory.
    Prefetch {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Parse $I metadata and correlate it with neighboring $R content.
    RecycleBin {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Parse a raw AppCompatCache value exported from SYSTEM.
    Shimcache {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Parse an extracted NTFS $MFT file.
    Mft {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long, default_value = "C:")]
        volume: String,
    },
    /// Parse an extracted NTFS $UsnJrnl:$J stream.
    Usn {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long, default_value = "C:")]
        volume: String,
    },
    /// Parse .lnk files below a file or directory.
    Lnk {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Parse Automatic and Custom Destinations Jump Lists.
    JumpLists {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Parse one EVTX file or a directory tree of logs.
    Evtx {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Parse an offline Windows Registry hive into normalized SQLite rows.
    Registry {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Parse an offline Amcache.hve into normalized inventory rows.
    Amcache {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Extract and parse AppCompatCache directly from an offline SYSTEM hive.
    ShimcacheHive {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Parse every table and column from an SRUDB.dat ESE database.
    Srum {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Correlate parser-produced MFT and USN databases and reconstruct paths.
    Correlate {
        #[arg(long)]
        mft: PathBuf,
        #[arg(long)]
        usn: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let parser = match &cli.command {
        Command::Prefetch { .. } => "prefetch",
        Command::RecycleBin { .. } => "recycle-bin",
        Command::Shimcache { .. } => "shimcache",
        Command::Mft { .. } => "mft",
        Command::Usn { .. } => "usn",
        Command::Lnk { .. } => "lnk",
        Command::JumpLists { .. } => "jump-lists",
        Command::Evtx { .. } => "evtx",
        Command::Registry { .. } => "registry",
        Command::Amcache { .. } => "amcache",
        Command::ShimcacheHive { .. } => "shimcache-hive",
        Command::Srum { .. } => "srum",
        Command::Correlate { .. } => "correlate",
    };
    let output = match &cli.command {
        Command::Prefetch { output, .. }
        | Command::RecycleBin { output, .. }
        | Command::Shimcache { output, .. }
        | Command::Mft { output, .. }
        | Command::Usn { output, .. }
        | Command::Lnk { output, .. }
        | Command::JumpLists { output, .. }
        | Command::Evtx { output, .. }
        | Command::Registry { output, .. }
        | Command::Amcache { output, .. }
        | Command::ShimcacheHive { output, .. }
        | Command::Srum { output, .. }
        | Command::Correlate { output, .. } => output.display().to_string(),
    };
    let count = match cli.command {
        Command::Prefetch { input, output } => prefetch::run(&input, &output)?,
        Command::RecycleBin { input, output } => recycle_bin::run(&input, &output)?,
        Command::Shimcache { input, output } => shimcache::run(&input, &output)?,
        Command::Mft {
            input,
            output,
            volume,
        } => ntfs::parse_mft(&input, &output, &volume)?,
        Command::Usn {
            input,
            output,
            volume,
        } => ntfs::parse_usn(&input, &output, &volume)?,
        Command::Lnk { input, output } => shell::parse_links(&input, &output)?,
        Command::JumpLists { input, output } => shell::parse_jump_lists(&input, &output)?,
        Command::Evtx { input, output } => eventlog::run(&input, &output)?,
        Command::Registry { input, output } => registry::run(&input, &output, false)?,
        Command::Amcache { input, output } => registry::run(&input, &output, true)?,
        Command::ShimcacheHive { input, output } => registry::shimcache_hive(&input, &output)?,
        Command::Srum { input, output } => srum::run(&input, &output)?,
        Command::Correlate { mft, usn, output } => correlate::run(&mft, &usn, &output)?,
    };
    if cli.json {
        println!(
            "{}",
            serde_json::json!({
                "type": "complete",
                "parser": parser,
                "parsed": count,
                "output": output
            })
        );
    } else {
        println!("Parsed {count} record(s)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_machine_readable_output_flag() {
        let cli = Cli::try_parse_from([
            "vamparser",
            "--json",
            "mft",
            "evidence.mft",
            "--output",
            "mft.db",
        ])
        .unwrap();
        assert!(cli.json);
    }
}
