use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::sync::atomic::AtomicU64;

use crate::{provider::ProviderError, reqwest_utils::FetchError, rpc::common::*};

static LOCALHOST: &str = "192.168.0.1";

/// Basic Auth credentials
#[derive(Debug)]
struct BasicAuth {
    username: SecretString,
    password: SecretString,
}

#[derive(Debug)]
/// An HTTP Transport for JSON RPC
pub struct HttpTransport {
    id: AtomicU64,
    url: String,
    client: reqwest::Client,
    credentials: Option<BasicAuth>,
}

impl Default for HttpTransport {
    fn default() -> Self {
        Self {
            id: 0.into(),
            url: LOCALHOST.to_owned(),
            client: reqwest::Client::new(),
            credentials: None,
        }
    }
}

impl HttpTransport {
    // This can leak auth secrets. Don't make public
    fn url(&self) -> String {
        if let Some(creds) = &self.credentials {
            format!(
                "http://{}:{}@{}",
                creds.username.expose_secret(),
                creds.password.expose_secret(),
                &self.url
            )
        } else {
            format!("http://{}", &self.url)
        }
    }

    /// Instantiate a transport with BasicAuth credentials
    pub fn with_credentials(username: SecretString, password: SecretString) -> Self {
        Self {
            credentials: Some(BasicAuth { username, password }),
            ..Default::default()
        }
    }

    /// Instantiate a transport with BasicAuth credentials and a url
    pub fn with_credentials_and_url(
        username: SecretString,
        password: SecretString,
        url: &str,
    ) -> Self {
        let credentials = Some(BasicAuth { username, password });
        Self {
            url: url.to_owned(),
            credentials,
            ..Default::default()
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl JsonRpcTransport for HttpTransport {
    fn id(&self) -> &AtomicU64 {
        &self.id
    }

    /// Sends a POST request with the provided method and the params serialized as JSON
    /// over HTTP
    async fn request<T: Serialize + Send + Sync, R: for<'a> Deserialize<'a>>(
        &self,
        method: &str,
        params: T,
    ) -> Result<R, ProviderError> {
        let next_id = self.next_id();

        let payload = Request::new(next_id, method, params);

        let res = self
            .client
            .post(&self.url())
            .json(&payload)
            .send()
            .await
            .map_err(Into::<FetchError>::into)?;
        let body = res.text().await.map_err(Into::<FetchError>::into)?;
        dbg!(&body);
        let res: Response<R> = serde_json::from_str(&body).map_err(Into::<FetchError>::into)?;
        Ok(res.data.into_result()?)
    }
}
//
// #[cfg(test)]
// mod test {
//     use super::*;
//     use tokio::runtime;
//     use futures_util::stream::StreamExt;
//
//     use coins_core::ser::ByteFormat;
//
//     // runs against live API. leave commented
//     #[test]
//     fn it_makes_a_request() {
//         let fut = async move {
//             let transport = HttpTransport::with_credentials_and_url(
//                 "x".parse().unwrap(),
//                 "xxx".parse().unwrap(),
//                 &"xxxxx",
//             );
//             let res = transport.request::<_, serde_json::Value>("getbestblockhash", Vec::<String>::new()).await;
//
//             dbg!(res);
//             // serde_json::from_str::<serde_json::Value>()
//         };
//         runtime::Runtime::new().unwrap().block_on(fut);
//     }
// }
