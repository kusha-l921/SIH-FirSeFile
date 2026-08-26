use clap::{Parser, Subcommand};
use firsefile_lib::{list_recovered_files_core, get_ledger_core, verify_chain_core, get_case_status_core, export_report_core};

#[derive(Parser)]
#[command(name = "recover")]
#[command(about = "FirSeFile forensic recovery CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Scan {
        image_path: String,
    },
    ListCase {
        case_id: String,
    },
    ShowFile {
        file_id: String,
    },
    VerifyChain {
        case_id: String,
    },
    ExportReport {
        case_id: String,
        #[arg(long, default_value = "Unknown")]
        investigator: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { image_path } => {
            println!("Scanning image: {}", image_path);
            println!("(placeholder - real scan will call backend once available)");
        }

        Commands::ListCase { case_id } => {
            let status = get_case_status_core();
            println!("Case: {}", case_id);
            println!("Filesystem: {}", status.filesystem);
            println!("Status: {}", status.status);
            println!("Files recovered: {}", status.files_recovered);
            println!("Fragments found: {}", status.fragments_found);
            println!(
                "Blocks processed: {} / {}",
                status.blocks_processed, status.total_blocks
            );
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
                    println!("File ID: {}", f.file_id);
                    println!("Filename: {}", f.filename);
                    println!("Type: {}", f.file_type);
                    println!("Size: {} bytes", f.size);
                    println!("Filesystem: {}", f.filesystem);
                    println!("Recovery method: {}", f.recovery_method);
                    println!("Confidence: {:?}", f.confidence);
                    println!("Source locations: {:?}", f.source_locations);
                    println!("SHA-256: {:?}", f.sha256);
                }
                None => {
                    eprintln!("No file found with id: {}", file_id);
                    std::process::exit(1);
                }
            }
        }

        Commands::VerifyChain { case_id } => {
            println!("Verifying chain for case: {}", case_id);
            let result = verify_chain_core();
            if result {
                println!("Chain Verified");
            } else {
                println!("Verification Failed");
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
