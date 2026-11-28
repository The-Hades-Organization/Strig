//! The part of `envoy.service.auth.v3` the adapter speaks, written as prost messages.
//!
//! Only the fields the adapter reads or writes are declared, with the field numbers of the Envoy
//! protos (`envoy/service/auth/v3/{external_auth,attribute_context}.proto`,
//! `envoy/config/core/v3/base.proto`, `envoy/type/v3/http_status.proto`, `google/rpc/status.proto`).
//! Protobuf skips what a message does not declare, so a newer Envoy that sends more still decodes.
//! Written by hand so the build needs no `protoc` and no code generation.

use std::collections::HashMap;

/// `google.rpc.Code.OK`.
pub const CODE_OK: i32 = 0;
/// `google.rpc.Code.PERMISSION_DENIED`.
pub const CODE_PERMISSION_DENIED: i32 = 7;
/// `envoy.type.v3.StatusCode.Forbidden`.
pub const HTTP_FORBIDDEN: i32 = 403;

#[derive(Clone, PartialEq, prost::Message)]
pub struct CheckRequest {
    #[prost(message, optional, tag = "1")]
    pub attributes: Option<AttributeContext>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct AttributeContext {
    #[prost(message, optional, tag = "4")]
    pub request: Option<Request>,
    #[prost(map = "string, string", tag = "10")]
    pub context_extensions: HashMap<String, String>,
    #[prost(message, optional, tag = "11")]
    pub metadata_context: Option<Metadata>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Request {
    #[prost(message, optional, tag = "2")]
    pub http: Option<HttpRequest>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct HttpRequest {
    #[prost(string, tag = "2")]
    pub method: String,
    #[prost(map = "string, string", tag = "3")]
    pub headers: HashMap<String, String>,
    #[prost(string, tag = "4")]
    pub path: String,
}

/// `envoy.config.core.v3.Metadata`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Metadata {
    #[prost(map = "string, message", tag = "1")]
    pub filter_metadata: HashMap<String, prost_types::Struct>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct CheckResponse {
    #[prost(message, optional, tag = "1")]
    pub status: Option<Status>,
    #[prost(oneof = "check_response::HttpResponse", tags = "2, 3")]
    pub http_response: Option<check_response::HttpResponse>,
}

pub mod check_response {
    use super::{DeniedHttpResponse, OkHttpResponse};

    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum HttpResponse {
        #[prost(message, tag = "2")]
        DeniedResponse(DeniedHttpResponse),
        #[prost(message, tag = "3")]
        OkResponse(OkHttpResponse),
    }
}

/// `google.rpc.Status`, without `details`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Status {
    #[prost(int32, tag = "1")]
    pub code: i32,
    #[prost(string, tag = "2")]
    pub message: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct DeniedHttpResponse {
    #[prost(message, optional, tag = "1")]
    pub status: Option<HttpStatus>,
    #[prost(message, repeated, tag = "2")]
    pub headers: Vec<HeaderValueOption>,
    #[prost(string, tag = "3")]
    pub body: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct HttpStatus {
    #[prost(int32, tag = "1")]
    pub code: i32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct OkHttpResponse {
    #[prost(message, repeated, tag = "2")]
    pub headers: Vec<HeaderValueOption>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct HeaderValueOption {
    #[prost(message, optional, tag = "1")]
    pub header: Option<HeaderValue>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct HeaderValue {
    #[prost(string, tag = "1")]
    pub key: String,
    #[prost(string, tag = "2")]
    pub value: String,
}

impl CheckResponse {
    pub(crate) fn allow() -> Self {
        Self {
            status: Some(Status {
                code: CODE_OK,
                message: String::new(),
            }),
            http_response: Some(check_response::HttpResponse::OkResponse(OkHttpResponse::default())),
        }
    }

    pub(crate) fn deny(reason: Option<&str>) -> Self {
        let headers = reason
            .map(|code| HeaderValueOption {
                header: Some(HeaderValue {
                    key: super::REASON_HEADER.to_string(),
                    value: code.to_string(),
                }),
            })
            .into_iter()
            .collect();
        Self {
            status: Some(Status {
                code: CODE_PERMISSION_DENIED,
                message: String::new(),
            }),
            http_response: Some(check_response::HttpResponse::DeniedResponse(DeniedHttpResponse {
                status: Some(HttpStatus { code: HTTP_FORBIDDEN }),
                headers,
                body: String::new(),
            })),
        }
    }
}
