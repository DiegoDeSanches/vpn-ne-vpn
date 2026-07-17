mod prototype_route;

#[cfg(target_os = "windows")]
mod windows_host;

#[cfg(target_os = "windows")]
#[tokio::main]
async fn main() -> std::process::ExitCode {
    match windows_host::run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("OnionRoute experimental daemon stopped: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn main() -> std::process::ExitCode {
    eprintln!("This experimental daemon host is available only on Windows.");
    std::process::ExitCode::FAILURE
}
