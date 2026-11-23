//! Android app-private executable driving the ordinary Common UDP client.
#[cfg(any(target_os = "android", target_os = "linux"))]
mod android;

fn main() -> std::process::ExitCode {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    match android::enter() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Android Common owner failed ({:?})", error.kind());
            std::process::ExitCode::FAILURE
        }
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    std::process::ExitCode::FAILURE
}
