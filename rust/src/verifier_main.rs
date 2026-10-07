#![forbid(unsafe_code)]
use sentry_external_testing::attestation::{handle_request, MAX_REQUEST};
use std::io::{Read, Write};
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--package-quote") && args.len() == 5 {
        match sentry_external_testing::attestation::package_quote_files(
            std::path::Path::new(&args[2]),
            std::path::Path::new(&args[3]),
            std::path::Path::new(&args[4]),
        ) {
            Ok(bytes) => {
                if std::io::stdout().write_all(&bytes).is_err() {
                    std::process::exit(2);
                }
                return;
            }
            Err(e) => {
                eprintln!("Recorded: quote packaging refused: {e}");
                std::process::exit(2);
            }
        }
    }
    #[cfg(feature = "test-fixtures")]
    {
        if args.get(1).map(String::as_str) == Some("--fixture") {
            match args.get(2).map(String::as_str) {
                Some("stall") => {
                    std::thread::sleep(std::time::Duration::from_secs(30));
                    return;
                }
                Some("oversize") => {
                    let _ = std::io::stdout().write_all(&vec![b'x'; 8192]);
                    return;
                }
                Some("crash") => std::process::exit(7),
                Some("malformed") => {
                    let _ = std::io::stdout().write_all(b"not-json");
                    return;
                }
                _ => std::process::exit(2),
            }
        }
    }
    if args.len() != 1 {
        std::process::exit(2);
    }
    let mut data = Vec::new();
    if std::io::stdin()
        .take((MAX_REQUEST + 1) as u64)
        .read_to_end(&mut data)
        .is_err()
    {
        std::process::exit(2);
    }
    let response = handle_request(&data);
    let out = serde_json::to_vec(&response).expect("bounded response");
    if std::io::stdout().write_all(&out).is_err() {
        std::process::exit(2);
    }
}
