use std::time::Duration;

use futures_util::{Stream, StreamExt, stream};
use reqwest::{IntoUrl, Url};
use serde::{Deserialize, Serialize};
use tokio::time::{Instant, sleep, timeout_at};

use crate::transports::speculos::SpeculosError;

/// A physical button on a Nano device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Button {
    /// The left button.
    Left,
    /// The right button.
    Right,
    /// Both buttons together.
    Both,
}

impl Button {
    const fn path(self) -> &'static str {
        match self {
            Self::Left => "left",
            Self::Right => "right",
            Self::Both => "both",
        }
    }
}

/// What to do with a button or finger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Press and hold.
    Press,
    /// Release a held press.
    Release,
    /// Press, wait, then release.
    PressAndRelease {
        /// How long to hold. Speculos picks a default if `None`.
        delay: Option<Duration>,
    },
}

/// An event body as Speculos expects it.
#[derive(Serialize)]
struct ActionBody {
    action: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    delay: Option<f64>,
    #[serde(flatten)]
    at: Option<Point>,
}

#[derive(Serialize)]
struct Point {
    x: u16,
    y: u16,
}

impl ActionBody {
    const fn new(action: Action, at: Option<Point>) -> Self {
        match action {
            Action::Press => Self {
                action: "press",
                delay: None,
                at,
            },
            Action::Release => Self {
                action: "release",
                delay: None,
                at,
            },
            Action::PressAndRelease { delay } => Self {
                action: "press-and-release",
                delay: match delay {
                    Some(d) => Some(d.as_secs_f64()),
                    None => None,
                },
                at,
            },
        }
    }
}

/// A piece of text Speculos drew on the emulated screen, with its bounds.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ScreenEvent {
    /// The text drawn.
    pub text: String,
    /// Horizontal position of the left edge.
    pub x: u16,
    /// Vertical position of the top edge.
    pub y: u16,
    /// Width, or 0 if Speculos did not report one.
    #[serde(default)]
    pub w: u16,
    /// Height, or 0 if Speculos did not report one.
    #[serde(default)]
    pub h: u16,
}

impl ScreenEvent {
    /// The middle of the text's bounds, where a touchscreen tap selects it.
    pub const fn center(&self) -> (u16, u16) {
        (
            self.x.saturating_add(self.w / 2),
            self.y.saturating_add(self.h / 2),
        )
    }
}

#[derive(Deserialize)]
struct Events {
    events: Vec<ScreenEvent>,
}

/// A client for the HTTP control API of a Speculos emulator.
///
/// It presses buttons, reads what the app drew on screen and takes
/// screenshots. It is cheap to clone and shares its connection pool.
#[derive(Debug, Clone)]
pub struct SpeculosClient {
    http: reqwest::Client,
    base: Url,
    poll_interval: Duration,
}

impl SpeculosClient {
    /// How often [`wait_for_text`](Self::wait_for_text) polls the event log,
    /// unless set otherwise.
    pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(100);

    /// A client for the API at `base_url`, e.g. `http://127.0.0.1:5000`.
    pub fn new(base_url: impl IntoUrl) -> Result<Self, SpeculosError> {
        Ok(Self {
            // Speculos runs locally, so a proxy from the environment must not
            // capture the requests.
            http: reqwest::Client::builder().no_proxy().build()?,
            base: base_url.into_url()?,
            poll_interval: Self::DEFAULT_POLL_INTERVAL,
        })
    }

    /// Set how often [`wait_for_text`](Self::wait_for_text) polls the event
    /// log.
    pub const fn set_poll_interval(&mut self, interval: Duration) {
        self.poll_interval = interval
    }

    /// Set how often [`wait_for_text`](Self::wait_for_text) polls the event
    /// log.
    pub const fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// How often [`wait_for_text`](Self::wait_for_text) polls the event log.
    pub const fn poll_interval(&self) -> Duration {
        self.poll_interval
    }

    fn url(&self, path: &str) -> Url {
        let mut url = self.base.clone();
        url.set_path(path);
        url
    }

    async fn send(&self, req: reqwest::RequestBuilder) -> Result<reqwest::Response, SpeculosError> {
        Ok(req.send().await?.error_for_status()?)
    }

    /// Act on a button.
    pub async fn button(&self, button: Button, action: Action) -> Result<(), SpeculosError> {
        let url = self.url(&format!("/button/{}", button.path()));
        self.send(self.http.post(url).json(&ActionBody::new(action, None)))
            .await?;
        Ok(())
    }

    /// Act on the touchscreen at `(x, y)`.
    pub async fn finger(&self, x: u16, y: u16, action: Action) -> Result<(), SpeculosError> {
        let body = ActionBody::new(action, Some(Point { x, y }));
        self.send(self.http.post(self.url("/finger")).json(&body))
            .await?;
        Ok(())
    }

    async fn fetch_events(&self, current_only: bool) -> Result<Vec<ScreenEvent>, SpeculosError> {
        let mut url = self.url("/events");
        if current_only {
            url.set_query(Some("currentscreenonly=true"));
        }
        let body = self.send(self.http.get(url)).await?.bytes().await?;
        Ok(serde_json::from_slice::<Events>(&body)?.events)
    }

    /// Every screen event since the log was last cleared.
    pub async fn events(&self) -> Result<Vec<ScreenEvent>, SpeculosError> {
        self.fetch_events(false).await
    }

    /// The events of the screen currently displayed.
    pub async fn current_screen(&self) -> Result<Vec<ScreenEvent>, SpeculosError> {
        self.fetch_events(true).await
    }

    /// Clear the event log.
    pub async fn clear_events(&self) -> Result<(), SpeculosError> {
        self.send(self.http.delete(self.url("/events"))).await?;
        Ok(())
    }

    /// Poll the event log until an event's text contains `needle`, and return
    /// that event.
    ///
    /// This matches anything logged since the last
    /// [`clear_events`](Self::clear_events), including events from before the
    /// call, so clear the log before starting a step to avoid matching a stale
    /// screen. Fails with [`SpeculosError::TextNotFound`] once `timeout`
    /// passes.
    pub async fn wait_for_text(
        &self,
        needle: &str,
        timeout: Duration,
    ) -> Result<ScreenEvent, SpeculosError> {
        let deadline = Instant::now() + timeout;
        let poll = async {
            loop {
                let events = self.events().await?;
                if let Some(found) = events.into_iter().find(|e| e.text.contains(needle)) {
                    return Ok(found);
                }
                sleep(self.poll_interval).await;
            }
        };
        // The deadline also bounds a request that hangs.
        match timeout_at(deadline, poll).await {
            Ok(res) => res,
            Err(_) => Err(SpeculosError::TextNotFound {
                needle: needle.to_owned(),
                timeout,
            }),
        }
    }

    /// A screenshot of the emulated screen, as PNG bytes.
    pub async fn screenshot(&self) -> Result<Vec<u8>, SpeculosError> {
        let resp = self.send(self.http.get(self.url("/screenshot"))).await?;
        Ok(resp.bytes().await?.to_vec())
    }

    /// Subscribe to screen events, and stream them as they are drawn.
    ///
    /// Speculos sends only events drawn after it registers the subscription,
    /// and this returns once it has, so an action taken after this returns is
    /// seen by the stream. Speculos sends server-sent events: each event is a
    /// `data:` line holding its JSON.
    ///
    /// The stream ends when Speculos closes the connection, and yields an
    /// error, then ends, if the connection fails or a line is not an event.
    pub async fn event_stream(
        &self,
    ) -> Result<
        impl Stream<Item = Result<ScreenEvent, SpeculosError>> + Send + 'static,
        SpeculosError,
    > {
        let mut url = self.url("/events");
        url.set_query(Some("stream=true"));
        // Speculos registers the subscriber before it sends the headers.
        let resp = self.send(self.http.get(url)).await?;
        let state = StreamState {
            bytes: Some(resp.bytes_stream().map(|c| c.map(|b| b.to_vec())).boxed()),
            buf: Vec::new(),
        };
        Ok(stream::unfold(state, |mut st| async move {
            loop {
                let bytes = st.bytes.as_mut()?;
                // A complete line may already be buffered.
                if let Some(pos) = st.buf.iter().position(|b| *b == b'\n') {
                    let line: Vec<u8> = st.buf.drain(..=pos).collect();
                    if let Some(item) = parse_line(&line) {
                        if item.is_err() {
                            // A malformed line means the format is not understood.
                            st.bytes = None;
                        }
                        return Some((item, st));
                    }
                    continue;
                }
                match bytes.next().await {
                    Some(Ok(chunk)) => st.buf.extend_from_slice(&chunk),
                    Some(Err(e)) => {
                        st.bytes = None;
                        return Some((Err(e.into()), st));
                    }
                    None => {
                        st.bytes = None;
                        // A final line without a newline.
                        let line = std::mem::take(&mut st.buf);
                        return parse_line(&line).map(|item| (item, st));
                    }
                }
            }
        }))
    }
}

struct StreamState {
    bytes: Option<futures_util::stream::BoxStream<'static, reqwest::Result<Vec<u8>>>>,
    buf: Vec<u8>,
}

/// Parse one line of the event stream, or `None` for a line that carries no
/// event: a blank line, an SSE comment or an SSE field other than `data`.
fn parse_line(line: &[u8]) -> Option<Result<ScreenEvent, SpeculosError>> {
    let line = line.trim_ascii();
    if line.starts_with(b":")
        || [&b"event:"[..], b"id:", b"retry:"]
            .iter()
            .any(|field| line.starts_with(field))
    {
        return None;
    }
    let line = line.strip_prefix(b"data:").map_or(line, <[u8]>::trim_ascii);
    if line.is_empty() {
        return None;
    }
    Some(serde_json::from_slice(line).map_err(Into::into))
}

#[cfg(test)]
#[path = "../../../ai-tests/transports/speculos/client.rs"]
mod ai_tests;
