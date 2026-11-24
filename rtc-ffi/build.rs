//! Passes the target triple to the tests, which compile a C program against the library
//! (`tests/c_loopback.rs`) with the `cc` crate.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if let Ok(target) = std::env::var("TARGET") {
        println!("cargo:rustc-env=RTC_FFI_TARGET={target}");
    }
}
