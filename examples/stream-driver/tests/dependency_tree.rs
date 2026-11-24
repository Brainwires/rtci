//! The no-built-in-runtime configuration: with `default-features = false` (and `peer`), the
//! crate's normal dependency tree holds no async runtime. Nothing reaches for tokio unless the
//! application asked for `runtime-tokio`: the driver uses only the `Runtime` it is given.

use std::process::Command;

/// Crates that are (or belong to) an async runtime's reactor or executor.
const RUNTIMES: [&str; 8] = [
    "tokio",
    "tokio-util",
    "mio",
    "smol",
    "async-io",
    "async-executor",
    "async-global-executor",
    "hickory-resolver",
];

#[test]
fn without_a_built_in_runtime_no_async_runtime_is_in_the_dependency_tree() {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
    let output = Command::new(cargo)
        .args([
            "tree",
            "--edges",
            "normal",
            "--no-default-features",
            "--features",
            "peer",
            "--manifest-path",
            manifest,
            "--package",
            "rtci-stream-driver",
            "--prefix",
            "none",
            "--format",
            "{p}",
        ])
        .output()
        .expect("cargo tree runs");
    assert!(
        output.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let tree = String::from_utf8_lossy(&output.stdout);
    assert!(
        tree.lines().any(|l| l.starts_with("rtci-stream-driver ")),
        "the tree names the crate itself: {tree}"
    );
    let found: Vec<&str> = tree
        .lines()
        .filter(|line| {
            let name = line.split_whitespace().next().unwrap_or_default();
            RUNTIMES.contains(&name)
        })
        .collect();
    assert!(
        found.is_empty(),
        "an async runtime in the tree without a built-in runtime feature: {found:?}"
    );
}
