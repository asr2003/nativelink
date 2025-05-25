use core::time::Duration;
use std::sync::Arc;

use aws_smithy_runtime::client::http::test_util::StaticReplayClient;
use http::StatusCode;
use nativelink_config::stores::{EndpointConfig, GrpcSpec, Retry, StoreType};
use nativelink_error::{Error, ResultExt, make_input_err};
use nativelink_macro::nativelink_test;
use nativelink_proto::google::bytestream::ReadRequest;
use nativelink_store::grpc_store::GrpcStore;
use nativelink_util::common::DigestInfo;
use nativelink_util::digest_hasher::{DigestHasherFunc, default_digest_hasher_func};
use nativelink_util::resource_info::is_supported_digest_function;
use nativelink_util::store_trait::StoreKey;
use std::pin::Pin;

use opentelemetry::context::Context;

fn minimal_grpc_spec() -> GrpcSpec {
    GrpcSpec {
        instance_name: "instance".to_string(),
        store_type: StoreType::Cas,
        endpoints: vec![EndpointConfig {
            uri: "http://localhost:1234".to_string(),
            ..Default::default()
        }],
        retry: Retry {
            max_retries: 0,
            delay: 0.0,
            jitter: 0.0,
            ..Default::default()
        },
        connections_per_endpoint: 1,
        max_concurrent_requests: 1,
    }
}

#[nativelink_test]
async fn grpc_store_read_fails_on_unsupported_digest_function() -> Result<(), Error> {
    let spec = minimal_grpc_spec();
    let store = GrpcStore::new(&spec).await?;

    let request = ReadRequest {
        resource_name: "instance/blobs/md5/abc123/100".to_string(), // Unsupported digest
        ..Default::default()
    };

    let result = store.read(Request::new(request)).await;

    assert!(result.is_err());
    let err_msg = format!("{:?}", result);
    assert!(
        err_msg.contains("Unsupported digest_function: md5"),
        "Unexpected error message: {err_msg}"
    );

    Ok(())
}

#[nativelink_test]
async fn grpc_store_has_with_results_fails_on_unsupported_context_digest() -> Result<(), Error> {
    let spec = minimal_grpc_spec();
    let store = GrpcStore::new(&spec).await?;

    let digest = DigestInfo::try_new("abc123", 100)?;
    let mut results = vec![None];
    let key: StoreKey = digest.into();

    let test_ctx = Context::current().with_value(DigestHasherFunc::from_str("sha3_256").unwrap());
    let _guard = test_ctx.attach();

    let result = Pin::new(&store)
        .has_with_results(&[key], &mut results)
        .await;

    assert!(result.is_err());
    let err_msg = format!("{:?}", result);
    assert!(
        err_msg.contains("Unsupported digest_function"),
        "Unexpected error message: {err_msg}"
    );

    Ok(())
}

#[test]
fn grpc_store_is_supported_digest_function_check() {
    assert!(is_supported_digest_function("sha256"));
    assert!(is_supported_digest_function("sha512"));
    assert!(!is_supported_digest_function("md5"));
    assert!(!is_supported_digest_function("sha1"));
}
