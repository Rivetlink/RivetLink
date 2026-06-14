//! Request ID middleware for distributed tracing.
//!
//! Generates a unique UUIDv7 for each request, adds it to the response headers,
//! and includes it in the tracing span so all logs for that request are correlated.

use axum::extract::Request;
use axum::response::Response;
use std::task::{Context, Poll};
use tower::Layer;
use tower::Service;
use uuid::Uuid;

/// Layer for adding request IDs to all requests.
#[derive(Clone, Debug)]
pub struct RequestIdLayer;

impl<S> Layer<S> for RequestIdLayer {
    type Service = RequestIdMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequestIdMiddleware { inner }
    }
}

/// Middleware service that injects request IDs into tracing spans and response headers.
#[derive(Clone, Debug)]
pub struct RequestIdMiddleware<S> {
    inner: S,
}

impl<S> Service<Request> for RequestIdMiddleware<S>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let inner = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, inner);

        let future = async move {
            let request_id = Uuid::now_v7();

            let request = request;
            let span = tracing::info_span!(
                "http_request",
                request_id = %request_id,
                method = %request.method(),
                uri = %request.uri(),
            );

            let _enter = span.enter();

            let mut response = inner.call(request).await?;

            if let Ok(header_val) = request_id.to_string().parse() {
                response.headers_mut().insert("x-request-id", header_val);
            }

            Ok(response)
        };

        Box::pin(future)
    }
}
