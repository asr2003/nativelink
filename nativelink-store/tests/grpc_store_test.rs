use std::sync::Arc;
use core::convert::TryFrom;

use nativelink_error::{Error, make_input_err};
use nativelink_util::digest_hasher::{DigestHasherFunc, default_digest_hasher_func};
use nativelink_util::resource_info::{ResourceInfo, is_supported_digest_function};
use opentelemetry::context::Context

/// A minimal mock that tests only digest logic.
struct MockGrpcStore {
    instance_name: String,
}

impl MockGrpcStore {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            instance_name: "instance".into(),
        })
    }

    fn check_read_digest(&self, resource_name: &str) -> Result<(), Error> {
        let info = ResourceInfo::new(resource_name, false)?;
        let digest_func = info.digest_function.as_deref().unwrap_or("sha256");
        if !is_supported_digest_function(digest_func) {
            return Err(make_input_err!(
                "Unsupported digest_function: {} in resource_name '{}'",
                digest_func,
                resource_name
            ));
        }
        Ok(())
    }

    fn check_has_with_results_digest(&self) -> Result<(), Error> {
        let digest_func = Context::current()
            .get::<DigestHasherFunc>()
            .map_or_else(default_digest_hasher_func, |v| *v)
            .to_string();

        if !is_supported_digest_function(&digest_func) {
            return Err(make_input_err!(
                "Unsupported digest_function: {}",
                digest_func
            ));
        }
        Ok(())
    }
}

#[test]
fn grpc_store_read_fails_on_unsupported_digest_function() {
    let store = MockGrpcStore::new();
    let resource_name = "instance/blobs/md5/abc123/100";
    let result = store.check_read_digest(resource_name);

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Unsupported digest_function"),
        "Expected digest rejection"
    );
}

#[test]
fn grpc_store_has_with_results_fails_on_unsupported_context_digest() {
    let store = MockGrpcStore::new();

    let digest_func = DigestHasherFunc::try_from("sha3_256").unwrap();
    let test_ctx = Context::current().with_value(digest_func);
    let _guard = test_ctx.attach();

    let result = store.check_has_with_results_digest();

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Unsupported digest_function"),
        "Expected context digest rejection"
    );
}

#[test]
fn grpc_store_is_supported_digest_function_check() {
    assert!(is_supported_digest_function("sha256"));
    assert!(is_supported_digest_function("sha512"));
    assert!(!is_supported_digest_function("md5"));
    assert!(!is_supported_digest_function("sha1"));
}