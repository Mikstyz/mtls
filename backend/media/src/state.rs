use cap_std::{ambient_authority, fs::Dir};
use std::{io, path::Path as FsPath, sync::Arc};
use tokio::sync::Semaphore;

use crate::views::ViewSink;

pub struct State {
    pub(crate) root: Arc<Dir>,
    pub(crate) secret: Vec<u8>,
    pub(crate) previous_secret: Option<Vec<u8>>,
    pub(crate) streams: Arc<Semaphore>,
    pub(crate) access: Option<AccessClient>,
    pub(crate) views: Option<ViewSink>,
}

pub(crate) struct AccessClient {
    pub(crate) client: reqwest::Client,
    pub(crate) base: reqwest::Url,
    pub(crate) cookie_name: String,
}

impl State {
    pub fn new(root: impl AsRef<FsPath>, secret: &str) -> io::Result<Self> {
        Self::with_limit(root, secret, 64)
    }

    pub fn with_limit(
        root: impl AsRef<FsPath>,
        secret: &str,
        max_streams: usize,
    ) -> io::Result<Self> {
        Self::with_secrets(root, secret, None, max_streams)
    }

    pub fn with_secrets(
        root: impl AsRef<FsPath>,
        secret: &str,
        previous_secret: Option<&str>,
        max_streams: usize,
    ) -> io::Result<Self> {
        if max_streams == 0 || max_streams > 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid stream limit",
            ));
        }

        let valid_secret = |value: &str| {
            (32..=128).contains(&value.len()) && value.bytes().all(|b| (0x21..=0x7e).contains(&b))
        };

        if !valid_secret(secret) || previous_secret.is_some_and(|previous| !valid_secret(previous))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid internal credential",
            ));
        }

        let root = Dir::open_ambient_dir(root, ambient_authority())?;

        Ok(Self {
            root: Arc::new(root),
            secret: secret.as_bytes().to_vec(),
            previous_secret: previous_secret.map(|value| value.as_bytes().to_vec()),
            streams: Arc::new(Semaphore::new(max_streams)),
            access: None,
            views: None,
        })
    }

    pub fn configure_user_access(&mut self, address: &str, cookie_name: &str) -> io::Result<()> {
        let base = reqwest::Url::parse(address)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid user service URL"))?;
        let host = base
            .host_str()
            .and_then(|host| host.parse::<std::net::IpAddr>().ok());

        if base.scheme() != "http"
            || !host.is_some_and(|ip| ip.is_loopback())
            || !base.username().is_empty()
            || base.password().is_some()
            || base.path() != "/"
            || base.query().is_some()
            || base.fragment().is_some()
            || !matches!(cookie_name, "mtls_session" | "__Host-mtls_session")
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid user access configuration",
            ));
        }

        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|_| io::Error::other("cannot initialize user service client"))?;

        self.access = Some(AccessClient {
            client,
            base,
            cookie_name: cookie_name.to_owned(),
        });
        Ok(())
    }
}
