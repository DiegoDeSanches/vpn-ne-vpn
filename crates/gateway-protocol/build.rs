use std::env;
use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let repository = manifest.join("../..");
    let proto_root = repository.join("proto");
    let files = [
        proto_root.join("common/v1/common.proto"),
        proto_root.join("gateway/v1/types.proto"),
        proto_root.join("gateway/v1/handshake.proto"),
        proto_root.join("gateway/v1/stream.proto"),
        proto_root.join("gateway/v1/gateway.proto"),
    ];

    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc");
    env::set_var("PROTOC", protoc);

    let mut config = prost_build::Config::new();
    config.protoc_arg("--experimental_allow_proto3_optional");
    config
        .compile_protos(&files, &[proto_root])
        .expect("compile OnionRoute gateway protobuf schema");

    println!(
        "cargo:rerun-if-changed={}",
        repository.join("proto/common/v1/common.proto").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        repository.join("proto/gateway/v1").display()
    );
}
