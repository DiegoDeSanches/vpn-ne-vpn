use std::path::PathBuf;

fn main() {
    let api_root = PathBuf::from("api");
    let schema = api_root.join("onionroute/token/v1/token_service.proto");
    println!("cargo:rerun-if-changed={}", schema.display());

    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc is unavailable");
    std::env::set_var("PROTOC", protoc);
    prost_build::Config::new()
        .compile_protos(&[schema], &[api_root])
        .expect("token-service candidate protobuf must compile");
}
