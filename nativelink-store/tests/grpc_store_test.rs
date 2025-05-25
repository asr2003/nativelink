use core::convert::TryFrom;
use std::sync::Arc;

use nativelink_store::grpc_store::validate_digest_function;
use nativelink_util::digest_hasher::DigestHasherFunc;
use nativelink_util::resource_info::{ResourceInfo, is_supported_digest_function};
use opentelemetry::context::Context;

#[test]
fn test_is_supported_digest_function() {
    assert!(is_supported_digest_function("sha256"));
    assert!(is_supported_digest_function("sha512"));
    assert!(!is_supported_digest_function("md5"));
    assert!(!is_supported_digest_function("sha1"));
}

#[test]
fn test_read_rejects_invalid_digest_function() {
    let resource_name = "instance/blobs/boo/abc123/100";
    let info = ResourceInfo::new(resource_name, false).unwrap();
    let digest_func = info.digest_function.unwrap_or("sha256".to_string());

    let result = validate_digest_function(&digest_func, Some(resource_name));
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
    let digest_func = DigestHasherFunc::try_from("sha3_256").unwrap();
    let ctx = Context::current().with_value(digest_func);
    let _guard = ctx.attach();

    let result = validate_digest_function(&digest_func.to_string(), None);
    assert!(result.is_err(), "Expected error from context digest check");
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("Unsupported digest_function"),
        "Unexpected error: {}",
        msg
    );
}
