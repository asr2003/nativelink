// Copyright 2024 The NativeLink Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::sync::Arc;
use tonic::Request;

use nativelink_store::GrpcStore;
use nativelink_config::stores::{GrpcSpec, StoreType, GrpcEndpoint, Retry};
use nativelink_proto::google::bytestream::ReadRequest;
use nativelink_util::resource_info::is_supported_digest_function;
use nativelink_util::store_trait::StoreDriver;

/// Build a minimal GrpcStore for testing.
async fn make_store() -> Arc<GrpcStore> {
    let spec = GrpcSpec {
        instance_name: "test".into(),
        store_type: StoreType::Cas,
        endpoints: vec![GrpcEndpoint {
            address: "http://127.0.0.1:0".into(),
            tls_config: None,
            concurrency_limit: None,
        }],
        retry: Retry {
            max_retries: 0,
            delay: 0.0,
            jitter: 0.0,
            retry_on_errors: None,
        },
        connections_per_endpoint: 1,
        max_concurrent_requests: 1,
    };
    GrpcStore::new(&spec).await.unwrap()
}

#[tokio::test]
async fn read_rejects_unsupported_md5() {
    let store = make_store().await;

    let bad_name = format!("{}/blobs/AAA/123?digest=md5", store.instance_name());
    let req = ReadRequest {
        resource_name: bad_name,
        read_offset: 0,
        read_limit: 0,
    };

    let res = store.read(Request::new(req)).await;
    assert!(res.is_err(), "expected Err, got {:?}", res.ok());
    let err = res.err().unwrap().to_string();
    assert!(
        err.contains("Unsupported digest_function: md5"),
        "got error = {}",
        err
    );
}

#[tokio::test]
async fn has_with_results_succeeds_by_default() {
    let store = make_store().await;
    let mut results = Vec::<Option<u64>>::new();

    store.has_with_results(&[], &mut results).await.unwrap();
}
