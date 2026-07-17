fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc is available");
    std::env::set_var("PROTOC", protoc);
    let schema = "schema/onionroute/desktop/ipc/v1/ipc.proto";
    prost_build::Config::new()
        .compile_protos(&[schema], &["schema"])
        .expect("desktop IPC schema compiles");
    println!("cargo:rerun-if-changed={schema}");
}
