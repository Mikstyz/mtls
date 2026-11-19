use std::{
    io,
    net::IpAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use futures_util::{stream, StreamExt};
use tokio::{sync::mpsc, task::JoinHandle};
use uuid::Uuid;

use crate::State;

#[derive(Clone)]
pub(crate) struct ViewSink(mpsc::Sender<View>);

struct View {
    post: Uuid,
    media: Uuid,
    viewer: Uuid,
    day: u64,
}

pub struct ViewReporter(JoinHandle<()>);

impl ViewReporter {
    pub async fn drain(mut self) {
        if tokio::time::timeout(Duration::from_secs(3), &mut self.0)
            .await
            .is_err()
        {
            self.0.abort();
            let _ = self.0.await;
        }
    }
}

impl State {
    pub fn configure_view_reporting(
        &mut self,
        address: &str,
        secret: &str,
    ) -> io::Result<ViewReporter> {
        let base = reqwest::Url::parse(address).map_err(|_| invalid_settings())?;
        let loopback = base
            .host_str()
            .and_then(|host| host.trim_matches(['[', ']']).parse::<IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback());

        if base.scheme() != "http"
            || !loopback
            || !base.username().is_empty()
            || base.password().is_some()
            || base.path() != "/"
            || base.query().is_some()
            || base.fragment().is_some()
            || !(32..=128).contains(&secret.len())
            || !secret.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
            || secret.as_bytes() == self.secret
            || self.previous_secret.as_deref() == Some(secret.as_bytes())
        {
            return Err(invalid_settings());
        }

        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(2))
            .build()
            .map_err(io::Error::other)?;

        let secret = secret.to_owned();
        let (sender, receiver) = mpsc::channel(256);
        self.views = Some(ViewSink(sender));
        let task = tokio::spawn(async move {
            stream::unfold(receiver, |mut receiver| async {
                receiver.recv().await.map(|view| (view, receiver))
            })
            .for_each_concurrent(4, |view| deliver(&client, &base, &secret, view))
            .await;
        });

        Ok(ViewReporter(task))
    }
}

fn invalid_settings() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid content view settings")
}

impl ViewSink {
    pub(crate) fn record(&self, post: Uuid, media: Uuid, viewer: Uuid) {
        let Ok(elapsed) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            return;
        };
        let _ = self.0.try_send(View {
            post,
            media,
            viewer,
            day: elapsed.as_secs() / 86_400,
        });
    }
}

pub(crate) fn view_threshold(
    mime: &str,
    init_segment: bool,
    size: u64,
    length: u64,
) -> Option<u64> {
    match mime {
        "video/mp4" | "video/webm" if length >= (256 * 1024).min(size) => {
            Some((256 * 1024).min(size))
        }
        "video/iso.segment" | "video/mp2t" if !init_segment && length >= 256 * 1024 => {
            Some(256 * 1024)
        }
        mime if mime.starts_with("image/") && length == size => Some((64 * 1024).min(size)),
        _ => None,
    }
}

async fn deliver(client: &reqwest::Client, base: &reqwest::Url, secret: &str, view: View) {
    let View {
        post,
        media,
        viewer,
        day,
    } = view;
    let mut url = base.clone();
    url.set_path(&format!("/internal/posts/{post}/media/{media}/view"));

    for attempt in 0..2 {
        let response = client
            .post(url.clone())
            .header("x-internal-secret", secret)
            .header("x-viewer-id", viewer.to_string())
            .header("x-view-day", day.to_string())
            .send()
            .await;
        if response.is_ok_and(|response| !response.status().is_server_error()) {
            return;
        }
        if attempt == 0 {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}
