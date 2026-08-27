//! Re-embed the separately built web bundle when it changes.

use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let dist = manifest.join("..").join("web").join("dist");

    // `rust-embed` requires the directory at compile time.
    std::fs::create_dir_all(&dist).expect("create web/dist");
    let keep = dist.join(".keep");
    if !keep.exists() {
        let _ = std::fs::write(&keep, b"");
    }

    println!("cargo:rerun-if-changed={}", dist.display());

    let built = std::fs::read_dir(&dist)
        .map(|d| d.filter_map(Result::ok).any(|e| e.file_name() != ".keep"))
        .unwrap_or(false);
    if !built {
        println!(
            "cargo:warning=web/dist has no UI bundle — embedding the \"UI not built\" placeholder. \
             Build the front-end first (`mise run web` or `cd web && pnpm install && pnpm build`)."
        );
    }
}
