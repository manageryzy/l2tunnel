//! l2tunnel-windows entry-point scaffold; no network or device side effects.
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [arg] if arg == "--help" || arg == "-h" => {
            println!(
                "l2tunnel-windows [plan | --version]\nScaffold only; network runtime is not implemented."
            );
            ExitCode::SUCCESS
        }
        [arg] if arg == "--version" => {
            println!("l2tunnel-windows {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        [arg] if arg == "plan" => {
            println!("{}", l2tunnel::IMPLEMENTATION_STATUS);
            println!("{:#?}", l2tunnel::core::ModeConfig::default());
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("Runtime not implemented. Use 'plan' to inspect the contract defaults.");
            ExitCode::from(2)
        }
    }
}
