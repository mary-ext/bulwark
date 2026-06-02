//! Build the embedded web UI before compiling the server.
//!
//! The built bundle in `web/dist` is *not* committed. When `pnpm` and the
//! installed `web/node_modules` are present, this rebuilds the UI so a plain
//! `cargo build` embeds the current front-end. When they're absent (e.g. no
//! Node toolchain), it warns and leaves whatever is in `web/dist` — which may be
//! just the `.gitkeep`, in which case the server serves a "UI not built"
//! placeholder. It never fails the build over the UI.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let web = manifest.join("..").join("web");

    // Rebuild only when the front-end sources change.
    for p in [
        "src",
        "package.json",
        "index.html",
        "vite.config.ts",
        "tsconfig.json",
    ] {
        println!("cargo:rerun-if-changed={}", web.join(p).display());
    }

    if !web.join("node_modules").exists() {
        println!(
            "cargo:warning=web/node_modules not found — skipping UI build. \
             Run `pnpm install && pnpm build` in web/ to embed the web UI."
        );
        return;
    }

    match Command::new("pnpm").current_dir(&web).arg("build").status() {
        Ok(s) if s.success() => {}
        Ok(s) => println!("cargo:warning=`pnpm build` failed ({s}); using existing web/dist"),
        Err(e) => println!("cargo:warning=could not run pnpm ({e}); using existing web/dist"),
    }
}
