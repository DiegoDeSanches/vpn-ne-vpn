use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=ONIONROUTE_CTOR_LIB_DIR");
    if env::var_os("CARGO_FEATURE_NATIVE").is_none() {
        return;
    }
    let directory = env::var_os("ONIONROUTE_CTOR_LIB_DIR")
        .map(PathBuf::from)
        .expect("ONIONROUTE_CTOR_LIB_DIR is required for the embedded C Tor feature");
    if !directory.is_dir() {
        panic!("ONIONROUTE_CTOR_LIB_DIR must name a directory containing libonionroute_tor.a");
    }
    if !directory.join("libonionroute_tor.a").is_file() {
        panic!("ONIONROUTE_CTOR_LIB_DIR does not contain libonionroute_tor.a");
    }
    println!("cargo:rustc-link-search=native={}", directory.display());
    println!("cargo:rustc-link-lib=static=onionroute_tor");
}
