use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fmt,
    sync::atomic::{AtomicU64, Ordering},
};
use thiserror::Error;

use crate::provider::ProviderError;

#[derive(Serialize, Deserialize, Debug, Clone, Error)]
/// A JSON-RPC 2.0 error
pub struct ErrorResponse {
    /// The error code
    pub code: i64,
    /// The error message
    pub message: String,
    /// Additional data
    pub data: Option<Value>,
}

impl fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(code: {}, message: {}, data: {:?})",
            self.code, self.message, self.data
        )
    }
}

impl From<ErrorResponse> for ProviderError {
    fn from(e: ErrorResponse) -> Self {
        ProviderError::RPCErrorResponse(e)
    }
}

#[derive(Serialize, Deserialize, Debug)]
/// A JSON-RPC request
pub struct Request<'a, T> {
    id: u64,
    jsonrpc: &'a str,
    method: &'a str,
    params: T,
}

impl<'a, T> Request<'a, T> {
    /// Creates a new JSON RPC request
    pub fn new(id: u64, method: &'a str, params: T) -> Self {
        Self {
            id,
            jsonrpc: "2.0",
            method,
            params,
        }
    }
}

// In case the node doesn't conform properly
static RPC2: &str = "2.0";
fn rpc_version() -> String {
    RPC2.to_owned()
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// A succesful response
pub struct Response<T> {
    id: u64,
    #[serde(default = "rpc_version")]
    jsonrpc: String,
    /// The response payload
    #[serde(flatten)]
    pub data: ResponseData<T>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
/// The two possible responses from the API
pub enum ResponseData<R> {
    /// Error Response
    Error {
        /// The Error
        error: ErrorResponse,
    },
    /// Succesful response
    Success {
        /// The response
        result: R,
    },
}

impl<R> ResponseData<R> {
    /// Consume response and return value
    pub fn into_result(self) -> Result<R, ErrorResponse> {
        match self {
            ResponseData::Success { result } => Ok(result),
            ResponseData::Error { error } => Err(error),
        }
    }
}

/// A JSON RPC transport
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait JsonRPCTransport: Default {
    /// Return a reference to the underlying AtomicU64 used for creating request IDs
    fn id(&self) -> &AtomicU64;

    /// Get the next request ID
    fn next_id(&self) -> u64 {
        self.id().fetch_add(1, Ordering::SeqCst)
    }

    /// Make a request, and receive a future with the response
    async fn request<T: Serialize + Send + Sync, R: for<'a> Deserialize<'a>>(
        &self,
        method: &str,
        params: T,
    ) -> Result<R, ProviderError>;
}

/*

    https://github.com/gakonst/ethers-rs

    Copyright (c) 2020 Georgios Konstantopoulos

    Permission is hereby granted, free of charge, to any
    person obtaining a copy of this software and associated
    documentation files (the "Software"), to deal in the
    Software without restriction, including without
    limitation the rights to use, copy, modify, merge,
    publish, distribute, sublicense, and/or sell copies of
    the Software, and to permit persons to whom the Software
    is furnished to do so, subject to the following
    conditions:

    The above copyright notice and this permission notice
    shall be included in all copies or substantial portions
    of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
    ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
    TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
    PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
    SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
    OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
    IN CONNECTION WITH THE SOFTWARE O THE USE OR OTHER
    DEALINGS IN THE SOFTWARE.R
*/
