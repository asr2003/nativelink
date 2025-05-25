use core::convert::TryFrom;

use nativelink_store::grpc_store::GrpcStore;
use nativelink_util::resource_info::{ResourceInfo, is_supported_digest_function};
use opentelemetry::context::Context;

const VALID_HASH: &str = "0123456789abcdef000000000000000000010000000000000123456789abcdef";

#[test]
fn test_is_supported_digest_function() {
    assert!(is_supported_digest_function("sha256"));
    assert!(is_supported_digest_function("sha512"));
    assert!(!is_supported_digest_function("crc32"));
}

#[test]
fn test_read_rejects_invalid_digest_function() {
    let resource_name = format!("instance/blobs/crc32/{}/100", VALID_HASH1);
    let info = ResourceInfo::new(resource_name, false).unwrap();
    let digest_func = info.digest_function.unwrap_or_else(|| "sha256".into());

    let result = GrpcStore::validate_digest_function(&digest_func, Some(resource_name));
    assert!(result.is_err(), "Expected error on invalid digest_function");
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("Unsupported digest_function"),
        "Unexpected error: {}",
        msg
    );
}

#[test]
fn test_has_with_results_rejects_invalid_digest_function_in_context() {
    let ctx = Context::current().with_value("sha3_256".to_string());
    let _guard = ctx.attach();

    let result = GrpcStore::validate_digest_function("sha3_256", None);
    assert!(result.is_err(), "Expected error from context digest check");
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("Unsupported digest_function"),
        "Unexpected error: {}",
        msg
    );
}
