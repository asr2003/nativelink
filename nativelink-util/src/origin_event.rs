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

use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};

use futures::future::ready;
use futures::{Future, FutureExt, Stream, StreamExt};
use nativelink_proto::build::bazel::remote::execution::v2::{
    ActionResult, BatchReadBlobsRequest, BatchReadBlobsResponse, BatchUpdateBlobsRequest,
    BatchUpdateBlobsResponse, ExecuteRequest, FindMissingBlobsRequest, FindMissingBlobsResponse,
    GetActionResultRequest, GetCapabilitiesRequest, GetTreeRequest, GetTreeResponse,
    RequestMetadata, ServerCapabilities, UpdateActionResultRequest, WaitExecutionRequest,
};
use nativelink_proto::com::github::trace_machina::nativelink::events::{
    batch_read_blobs_response_override, batch_update_blobs_request_override, event, request_event,
    response_event, stream_event, BatchReadBlobsResponseOverride, BatchUpdateBlobsRequestOverride,
    Event, OriginEvent, RequestEvent, ResponseEvent, StreamEvent, WriteRequestOverride,
};
use nativelink_proto::google::bytestream::{
    QueryWriteStatusRequest, QueryWriteStatusResponse, ReadRequest, ReadResponse, WriteRequest,
    WriteResponse,
};
use nativelink_proto::google::longrunning::Operation;
use nativelink_proto::google::rpc::Status;
use rand::RngCore;
use tokio::sync::mpsc;
use tonic::{Response, Status as TonicStatus, Streaming};
use uuid::Uuid;

use crate::make_symbol;
use crate::origin_context::ActiveOriginContext;

const ORIGIN_EVENT_VERSION: u32 = 0;

static NODE_ID: OnceLock<[u8; 6]> = OnceLock::new();

/// Returns a unique node ID for this process.
pub fn get_node_id() -> &'static [u8; 6] {
    NODE_ID.get_or_init(|| {
        let mut rng = rand::thread_rng();
        let mut out = [0; 6];
        rng.fill_bytes(&mut out);
        out
    })
}

pub struct OriginEventCollector {
    sender: mpsc::Sender<OriginEvent>,
    identity: String,
    bazel_metadata: Option<RequestMetadata>,
}

impl OriginEventCollector {
    pub fn new(
        sender: mpsc::Sender<OriginEvent>,
        identity: String,
        bazel_metadata: Option<RequestMetadata>,
    ) -> Self {
        Self {
            sender,
            identity,
            bazel_metadata,
        }
    }

    async fn publish_origin_event(&self, event: Event, parent_event_id: Option<Uuid>) -> Uuid {
        let event_id = Uuid::now_v6(get_node_id());
        let parent_event_id =
            parent_event_id.map_or_else(String::new, |id| id.as_hyphenated().to_string());
        // Failing to send this event means that the receiver has been dropped.
        let _ = self
            .sender
            .send(OriginEvent {
                version: ORIGIN_EVENT_VERSION,
                event_id: event_id.as_hyphenated().to_string(),
                parent_event_id,
                bazel_request_metadata: self.bazel_metadata.clone(),
                identity: self.identity.clone(),
                event: Some(event),
            })
            .await;
        event_id
    }
}

make_symbol!(ORIGIN_EVENT_COLLECTOR, OriginEventCollector);

pub struct OriginEventContext<T> {
    inner: Option<OriginEventContextImpl>,
    _phantom: PhantomData<T>,
}

impl<T> Clone for OriginEventContext<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            _phantom: PhantomData,
        }
    }
}

impl OriginEventContext<()> {
    pub fn new<'a, T, U>(
        source_cb: impl Fn() -> &'a T,
    ) -> impl Future<Output = OriginEventContext<T>> + 'static
    where
        T: OriginEventSource<U> + 'static,
    {
        let Ok(Some(origin_event_collector)) =
            ActiveOriginContext::get_value(&ORIGIN_EVENT_COLLECTOR)
        else {
            return ready(OriginEventContext {
                inner: None,
                _phantom: PhantomData,
            })
            .left_future();
        };
        let event = source_cb().as_event();
        async move {
            let parent_event_id = origin_event_collector
                .publish_origin_event(event, None)
                .await;
            OriginEventContext {
                inner: Some(OriginEventContextImpl {
                    origin_event_collector,
                    parent_event_id,
                }),
                _phantom: PhantomData,
            }
        }
        .right_future()
    }
}
impl<U> OriginEventContext<U> {
    pub fn emit<'a, T, F>(
        &self,
        event_cb: F,
    ) -> impl Future<Output = ()> + Send + use<'_, 'a, T, F, U>
    where
        T: OriginEventSource<U> + 'a,
        F: Fn() -> &'a T,
    {
        let Some(inner) = &self.inner else {
            return ready(()).left_future();
        };
        let v = (event_cb)();
        v.publish(inner).right_future()
    }

    pub fn wrap_stream<'a, O, S>(&self, stream: S) -> Pin<Box<dyn Stream<Item = O> + Send + 'a>>
    where
        U: Send + 'a,
        O: OriginEventSource<U> + Send + 'a,
        S: Stream<Item = O> + Send + 'a,
    {
        if self.inner.is_none() {
            return Box::pin(stream);
        }
        let ctx = self.clone();
        Box::pin(stream.then(move |item| {
            let ctx = ctx.clone();
            async move {
                ctx.emit(|| &item).await;
                item
            }
        }))
    }
}

#[derive(Clone)]
pub struct OriginEventContextImpl {
    origin_event_collector: Arc<OriginEventCollector>,
    parent_event_id: Uuid,
}

pub trait OriginEventSource<Source>: Sized {
    fn as_event(&self) -> Event;

    fn publish<'a>(&self, ctx: &'a OriginEventContextImpl) -> impl Future<Output = ()> + Send + 'a {
        let event = self.as_event();
        ctx.origin_event_collector
            .publish_origin_event(event, Some(ctx.parent_event_id))
            // We don't need the Uuid here.
            .map(|_| ())
    }
}

impl<'a, T, U> OriginEventSource<U> for &'a Response<T>
where
    T: OriginEventSource<U> + 'a,
{
    #[inline]
    fn as_event(&self) -> Event {
        self.get_ref().as_event()
    }
}

impl<T, U> OriginEventSource<U> for Result<Response<T>, TonicStatus>
where
    T: OriginEventSource<U>,
    TonicStatus: OriginEventSource<U>,
{
    #[inline]
    fn as_event(&self) -> Event {
        match self {
            Ok(v) => v.as_event(),
            Err(v) => v.as_event(),
        }
    }
}

fn tonic_status_to_proto_status(tonic_status: &TonicStatus) -> Status {
    Status {
        code: tonic_status.code().into(),
        message: tonic_status.message().into(),
        details: Vec::new(),
    }
}

macro_rules! get_event_type {
    (Request, $variant:ident, $data:expr) => {
        event::Event::Request(RequestEvent {
            event: Some(request_event::Event::$variant($data)),
        })
    };
    (Response, $variant:ident, $data:expr) => {
        event::Event::Response(ResponseEvent {
            event: Some(response_event::Event::$variant($data)),
        })
    };
    (Stream, $variant:ident, $data:expr) => {
        event::Event::Stream(StreamEvent {
            event: Some(stream_event::Event::$variant($data)),
        })
    };
}

macro_rules! impl_as_event {
    (Stream, $origin:ident, $type:ident) => {
        impl_as_event! {Stream, $origin, $type, $type, {
            #[inline]
            |val: &$type| val.clone()
        }}
    };
    (Stream, $origin:ty, $type:ty, $variant:ident, $data_fn:tt) => {
        impl_as_event! {__inner, Stream, $origin, Result<$type, TonicStatus>, $variant, {
            #[inline]
            |val: &Result<$type, TonicStatus>| match val {
                Ok(v) => get_event_type!(Stream, $variant, $data_fn(v)),
                Err(e) => get_event_type!(Stream, Error, tonic_status_to_proto_status(e)),
            }
        }}
    };
    ($event_type:ident, $origin:ty, $type:ident) => {
        impl_as_event!(__inner, $event_type, $origin, $type, $type, {
            #[inline]
            |val: &$type| get_event_type!($event_type, $type, val.clone())
        });
    };
    ($event_type:ident, $origin:ty, $type:ty, $variant:ident) => {
        impl_as_event!(__inner, $event_type, $origin, $type, $variant, {
            #[inline]
            |val: &$type| get_event_type!($event_type, $variant, val.clone())
        });
    };
    ($event_type:ident, $origin:ty, $type:ty, $variant:ident, $data_fn:tt) => {
        impl_as_event! {__inner, $event_type, $origin, $type, $variant, $data_fn}
    };
    (__inner, $event_type:ident, $origin:ty, $type:ty, $variant:ident, $data_fn:tt) => {
        impl OriginEventSource<$origin> for $type {
            #[inline]
            fn as_event(&self) -> Event {
                Event {
                    event: Some($data_fn(self)),
                }
            }
        }
    };
}

impl<Origin> OriginEventSource<Origin> for TonicStatus {
    #[inline]
    fn as_event(&self) -> Event {
        Event {
            event: Some(get_event_type!(
                Response,
                Error,
                tonic_status_to_proto_status(self)
            )),
        }
    }
}

#[inline]
fn to_batch_update_blobs_request_override(val: &BatchUpdateBlobsRequest) -> event::Event {
    get_event_type!(
        Request,
        BatchUpdateBlobsRequest,
        BatchUpdateBlobsRequestOverride {
            instance_name: val.instance_name.clone(),
            requests: val
                .requests
                .iter()
                .map(|v| batch_update_blobs_request_override::Request {
                    digest: v.digest.clone(),
                    compressor: v.compressor,
                    data_len: u64::try_from(v.data.len()).unwrap_or_default(),
                })
                .collect(),
            digest_function: val.digest_function,
        }
    )
}

#[inline]
fn to_batch_read_blobs_response_override(val: &BatchReadBlobsResponse) -> event::Event {
    get_event_type!(
        Response,
        BatchReadBlobsResponse,
        BatchReadBlobsResponseOverride {
            responses: val
                .responses
                .iter()
                .map(|v| batch_read_blobs_response_override::Response {
                    digest: v.digest.clone(),
                    compressor: v.compressor,
                    status: v.status.clone(),
                    data_len: u64::try_from(v.data.len()).unwrap_or_default(),
                })
                .collect(),
        }
    )
}

#[inline]
fn to_empty<T>(_: T) -> event::Event {
    get_event_type!(Response, Empty, ())
}

// -- Requests --

impl_as_event! {Request, (), GetCapabilitiesRequest}
impl_as_event! {Request, (), GetActionResultRequest}
impl_as_event! {Request, (), UpdateActionResultRequest}
impl_as_event! {Request, (), FindMissingBlobsRequest}
impl_as_event! {Request, (), BatchReadBlobsRequest}
impl_as_event! {Request, (), BatchUpdateBlobsRequest, BatchUpdateBlobsRequest, to_batch_update_blobs_request_override}
impl_as_event! {Request, (), GetTreeRequest}
impl_as_event! {Request, (), ReadRequest}
impl_as_event! {Request, (), Streaming<WriteRequest>, WriteRequest, to_empty}
impl_as_event! {Request, (), QueryWriteStatusRequest}
impl_as_event! {Request, (), ExecuteRequest}
impl_as_event! {Request, (), WaitExecutionRequest}

// -- Responses --

impl_as_event! {Response, GetCapabilitiesRequest, ServerCapabilities}
impl_as_event! {Response, GetActionResultRequest, ActionResult}
impl_as_event! {Response, UpdateActionResultRequest, ActionResult}
impl_as_event! {Response, Streaming<WriteRequest>, WriteResponse}
impl_as_event! {Response, ReadRequest, Pin<Box<dyn Stream<Item = Result<ReadResponse, TonicStatus>> + Send + '_>>, Empty, to_empty}
impl_as_event! {Response, QueryWriteStatusRequest, QueryWriteStatusResponse}
impl_as_event! {Response, FindMissingBlobsRequest, FindMissingBlobsResponse}
impl_as_event! {Response, BatchUpdateBlobsRequest, BatchUpdateBlobsResponse}
impl_as_event! {Response, BatchReadBlobsRequest, BatchReadBlobsResponse, BatchReadBlobsResponseOverride, to_batch_read_blobs_response_override}
impl_as_event! {Response, GetTreeRequest, Pin<Box<dyn Stream<Item = Result<GetTreeResponse, TonicStatus>> + Send + '_>>, Empty, to_empty}
impl_as_event! {Response, ExecuteRequest, Pin<Box<dyn Stream<Item = Result<Operation, TonicStatus>> + Send + '_>>, Empty, to_empty}

// -- Streams --

impl_as_event! {Stream, ReadRequest, ReadResponse, DataLength, {
    |val: &ReadResponse| val.data.len() as u64
}}
impl_as_event! {Stream, Streaming<WriteRequest>, WriteRequest, WriteRequest, {
    |val: &WriteRequest| WriteRequestOverride {
        resource_name: val.resource_name.clone(),
        write_offset: val.write_offset,
        finish_write: val.finish_write,
        data_len: u64::try_from(val.data.len()).unwrap_or_default(),
    }
}}
impl_as_event! {Stream, GetTreeRequest, GetTreeResponse}
impl_as_event! {Stream, ExecuteRequest, Operation}
impl_as_event! {Stream, WaitExecutionRequest, Operation}
