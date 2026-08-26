use clap::{Parser, Subcommand};
use firsefile_lib::{
    scan_image_core, list_recovered_files_core, get_ledger_core,
    verify_chain_core, get_case_status_core, export_report_core,
};

#[derive(Parser)]
#[command(name = "recover")]
#[command(about = "FirSeFile forensic recovery CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan an evidence disk image (.img, .raw, .dd, .bin)
    Scan {
        image_path: String,
    },
    /// List recovered files for the active case
    ListCase {
        case_id: Option<String>,
    },
    /// Show detailed info for a recovered file
    ShowFile {
        file_id: String,
    },
    /// Verify the integrity of the forensic recovery chain
    VerifyChain {
        case_id: Option<String>,
    },
    /// Export forensic recovery report
    ExportReport {
        case_id: String,
        #[arg(long, default_value = "Forensic Analyst")]
        investigator: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { image_path } => {
            println!("Starting forensic acquisition & recovery scan on: {}", image_path);
            match scan_image_core(&image_path) {
                Ok(status) => {
                    println!("\n=======================================================");
                    println!("             RECOVERY SCAN COMPLETED");
                    println!("=======================================================");
                    println!("Case ID:          {}", status.case_id);
                    println!("Filesystem:       {}", status.filesystem);
                    println!("Status:           {}", status.status);
                    println!("Files Recovered:  {}", status.files_recovered);
                    println!("Blocks Processed: {} / {}", status.blocks_processed, status.total_blocks);
                    println!("-------------------------------------------------------");
                    println!("Recovered files:");
                    for f in list_recovered_files_core() {
                        println!(
                            "  {} | {} | {} bytes | {} | confidence {:?}",
                            f.filename, f.file_type, f.size, f.recovery_method, f.confidence
                        );
                    }
                    println!("=======================================================\n");
                }
                Err(e) => {
                    eprintln!("Error during recovery scan: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::ListCase { case_id } => {
            let status = get_case_status_core();
            let c_id = case_id.unwrap_or(status.case_id.clone());
            println!("Case: {}", c_id);
            println!("Filesystem: {}", status.filesystem);
            println!("Status: {}", status.status);
            println!("Files recovered: {}", status.files_recovered);
            println!("Blocks processed: {} / {}", status.blocks_processed, status.total_blocks);
            println!();
            println!("Recovered files:");
            for f in list_recovered_files_core() {
                println!(
                    "  {} | {} | {} bytes | {} | confidence {:?}",
                    f.filename, f.file_type, f.size, f.recovery_method, f.confidence
                );
            }
        }

        Commands::ShowFile { file_id } => {
            let files = list_recovered_files_core();
            match files.iter().find(|f| f.file_id == file_id) {
                Some(f) => {
                    println!("File ID:          {}", f.file_id);
                    println!("Filename:         {}", f.filename);
                    println!("Type:             {}", f.file_type);
                    println!("Size:             {} bytes", f.size);
                    println!("Filesystem:       {}", f.filesystem);
                    println!("Recovery method:  {}", f.recovery_method);
                    println!("Confidence:       {:?}", f.confidence);
                    println!("Source locations: {:?}", f.source_locations);
                    println!("SHA-256:          {:?}", f.sha256);
                }
                None => {
                    eprintln!("No file found with id: {}", file_id);
                    std::process::exit(1);
                }
            }
        }

        Commands::VerifyChain { case_id: _ } => {
            let ledger = get_ledger_core();
            println!("Verifying chain with {} blocks...", ledger.len());
            let result = verify_chain_core();
            if result {
                println!("Chain Verified: PASS (cryptographically sound)");
            } else {
                println!("Verification Failed: No blocks or corrupted chain");
                std::process::exit(1);
            }
        }

        Commands::ExportReport { case_id, investigator } => {
            match export_report_core(case_id.clone(), investigator) {
                Ok(path) => println!("Report saved to: {}", path),
                Err(e) => {
                    eprintln!("Failed to export report: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}
