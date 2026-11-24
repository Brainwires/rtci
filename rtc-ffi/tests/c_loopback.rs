//! Compiles `tests/c/loopback.c` against the static library and the checked-in header with the
//! platform's C compiler (the `cc` crate) and runs it: a C program that exchanges a data
//! channel message between two driven peer connections over loopback.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The static library, built for this test: `cargo test` builds the library as an rlib only,
/// so a nested `cargo build` of the crate (its own target directory, under the test's
/// temporary directory, so it never waits on the outer build's lock) makes the staticlib.
fn static_library() -> PathBuf {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let target_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("c-loopback-target");
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let status = Command::new(cargo)
        .args(["build", "--lib", "--manifest-path"])
        .arg(crate_dir.join("Cargo.toml"))
        .arg("--target-dir")
        .arg(&target_dir)
        .status()
        .expect("cargo runs");
    assert!(status.success(), "building the static library failed");
    let name = if cfg!(windows) {
        "rtc_ffi.lib"
    } else {
        "librtc_ffi.a"
    };
    let lib = target_dir.join("debug").join(name);
    assert!(lib.exists(), "no {}", lib.display());
    lib
}

/// What a program linking the static library needs from the system (as
/// `rustc --print native-static-libs` lists them for this crate's dependencies).
fn system_libraries() -> &'static [&'static str] {
    if cfg!(target_os = "macos") {
        &["-lc", "-lm"]
    } else if cfg!(windows) {
        &[
            "ws2_32.lib",
            "userenv.lib",
            "ntdll.lib",
            "bcrypt.lib",
            "advapi32.lib",
            "kernel32.lib",
            "iphlpapi.lib",
            "dbghelp.lib",
            "ole32.lib",
            "oleaut32.lib",
            "synchronization.lib",
        ]
    } else {
        &["-lpthread", "-ldl", "-lm", "-lrt", "-lutil"]
    }
}

#[test]
fn a_c_program_exchanges_a_data_channel_message_through_the_driven_layer() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source = crate_dir.join("tests/c/loopback.c");
    let include = crate_dir.join("include");
    let out_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("c-loopback");
    std::fs::create_dir_all(&out_dir).unwrap();
    let exe = out_dir.join(if cfg!(windows) {
        "loopback.exe"
    } else {
        "loopback"
    });
    let target = env!("RTC_FFI_TARGET");
    let compiler = cc::Build::new()
        .target(target)
        .host(target)
        .opt_level(0)
        .debug(false)
        .cargo_metadata(false)
        .try_get_compiler()
        .expect("a C compiler");
    let mut cc = compiler.to_command();
    if compiler.is_like_msvc() {
        cc.arg(format!("/I{}", include.display()))
            .arg(&source)
            .arg(static_library())
            .arg(format!("/Fe{}", exe.display()))
            .arg(format!("/Fo{}\\", out_dir.display()))
            .arg("/link")
            .args(system_libraries());
    } else {
        cc.arg("-std=c99")
            .arg("-Wall")
            .arg("-Werror")
            .arg("-I")
            .arg(&include)
            .arg(&source)
            .arg(static_library())
            .arg("-o")
            .arg(&exe)
            .args(system_libraries());
    }
    let built = cc.output().expect("the C compiler runs");
    assert!(
        built.status.success(),
        "compiling tests/c/loopback.c failed:\n{}{}",
        String::from_utf8_lossy(&built.stdout),
        String::from_utf8_lossy(&built.stderr)
    );
    let ran = Command::new(&exe).output().expect("the C program runs");
    // The C runtime writes "\n" as "\r\n" to a text-mode stdout on Windows (MSVC's CRT does for
    // a redirected stdout too): compare lines, not bytes.
    let stdout = String::from_utf8_lossy(&ran.stdout).replace("\r\n", "\n");
    println!("{stdout}{}", String::from_utf8_lossy(&ran.stderr));
    assert!(ran.status.success(), "the C program failed: {}", ran.status);
    assert!(stdout.contains("the echo came back"), "{stdout}");
    assert!(stdout.ends_with("ok\n"), "{stdout}");
}
