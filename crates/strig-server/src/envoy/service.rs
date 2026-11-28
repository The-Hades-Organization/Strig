//! The tonic side: the `Authorization` service, written by hand over [`tonic::server::Grpc`].

use std::convert::Infallible;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_util::FutureExt;
use tonic::codegen::{Body, BoxFuture, Service, StdError, http};
use tonic::server::{Grpc, NamedService, UnaryService};
use tonic_prost::ProstCodec;

use super::EnvoyConfig;
use super::check::{Verdict, verdict};
use super::proto::{CheckRequest, CheckResponse};
use crate::server::AppState;

/// The fully qualified name of the service.
pub const SERVICE_NAME: &str = "envoy.service.auth.v3.Authorization";
const CHECK_PATH: &str = "/envoy.service.auth.v3.Authorization/Check";

/// The `envoy.service.auth.v3.Authorization` service over a [`DecisionServer`](crate::DecisionServer)'s
/// source. It is a tower service: `tonic::transport::Server::builder().add_service(service)`, or
/// [`EnvoyService::serve`] for the limits of the server in one call.
#[derive(Clone)]
pub struct EnvoyService {
    inner: Arc<Inner>,
}

struct Inner {
    state: AppState,
    config: Arc<EnvoyConfig>,
}

impl EnvoyService {
    pub(crate) fn new(state: AppState, config: EnvoyConfig) -> Self {
        if config.routes.is_empty() {
            tracing::warn!("the Envoy service has no routes: every request will be denied");
        }
        Self {
            inner: Arc::new(Inner {
                state,
                config: Arc::new(config),
            }),
        }
    }

    /// Serves this service on `listener` until `shutdown` completes, with the limits of the
    /// server: the deadline ceiling of the [`ServerConfig`](crate::ServerConfig) bounds each call,
    /// and the open streams per connection are capped by [`EnvoyConfig::with_max_concurrent_streams`].
    ///
    /// # Errors
    ///
    /// The transport error when the server stops for a reason other than `shutdown`.
    pub async fn serve(
        self,
        listener: tokio::net::TcpListener,
        shutdown: impl Future<Output = ()>,
    ) -> Result<(), tonic::transport::Error> {
        let max_timeout = self.inner.state.config.max_timeout;
        let streams = self.inner.config.max_concurrent_streams;
        tonic::transport::Server::builder()
            .timeout(max_timeout)
            .max_concurrent_streams(streams)
            .add_service(self)
            .serve_with_incoming_shutdown(tokio_stream::wrappers::TcpListenerStream::new(listener), shutdown)
            .await
    }

    async fn check(&self, request: CheckRequest) -> CheckResponse {
        let inner = &self.inner;
        let work = AssertUnwindSafe(self.decide(&request)).catch_unwind();
        let verdict = work.await.unwrap_or_else(|_panic| {
            tracing::error!("an Envoy check panicked");
            Verdict::Deny("unavailable")
        });
        crate::obs::envoy_checked(&verdict);
        verdict.into_response(inner.config.reasons)
    }

    #[cfg(feature = "tracing")]
    async fn decide(&self, request: &CheckRequest) -> Verdict {
        use tracing::Instrument;

        let span = tracing::info_span!("strig.server.envoy.check", outcome = tracing::field::Empty);
        let verdict = verdict(&self.inner.state, &self.inner.config, request)
            .instrument(span.clone())
            .await;
        span.record("outcome", verdict.outcome());
        verdict
    }

    #[cfg(not(feature = "tracing"))]
    async fn decide(&self, request: &CheckRequest) -> Verdict {
        verdict(&self.inner.state, &self.inner.config, request).await
    }
}

struct CheckSvc(EnvoyService);

impl UnaryService<CheckRequest> for CheckSvc {
    type Response = CheckResponse;
    type Future = BoxFuture<tonic::Response<CheckResponse>, tonic::Status>;

    fn call(&mut self, request: tonic::Request<CheckRequest>) -> Self::Future {
        let service = self.0.clone();
        Box::pin(async move { Ok(tonic::Response::new(service.check(request.into_inner()).await)) })
    }
}

impl<B> Service<http::Request<B>> for EnvoyService
where
    B: Body + Send + 'static,
    B::Error: Into<StdError> + Send + 'static,
{
    type Response = http::Response<tonic::body::Body>;
    type Error = Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        if request.uri().path() != CHECK_PATH {
            return Box::pin(async { Ok(tonic::Status::unimplemented("unknown method").into_http()) });
        }
        let limit = self.inner.state.config.max_body_bytes;
        let method = CheckSvc(self.clone());
        Box::pin(async move {
            let mut grpc = Grpc::new(ProstCodec::default()).max_decoding_message_size(limit);
            Ok(grpc.unary(method, request).await)
        })
    }
}

impl NamedService for EnvoyService {
    const NAME: &'static str = SERVICE_NAME;
}
