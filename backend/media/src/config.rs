use serde::Deserialize;
use std::{
    fs::File,
    io::{self, Read},
    net::IpAddr,
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
pub(crate) struct Config {
    pub(crate) services: Services,
    pub(crate) media: StorageConfig,
    #[serde(default)]
    pub(crate) resources: Resources,
}

#[derive(Default, Deserialize)]
pub(crate) struct Resources {
    #[serde(default)]
    pub(crate) max_procs: usize,
    #[serde(default)]
    pub(crate) memory_limit_bytes: u64,
}

#[derive(Deserialize)]
pub(crate) struct StorageConfig {
    #[serde(rename = "type")]
    pub(crate) kind: String,
    pub(crate) directory: PathBuf,
}

#[derive(Deserialize)]
pub(crate) struct Services {
    pub(crate) media: MediaConfig,
}

#[derive(Deserialize)]
pub(crate) struct MediaConfig {
    pub(crate) host: IpAddr,
    pub(crate) port: u16,
    #[serde(skip)]
    pub(crate) directory: PathBuf,
    pub(crate) internal_secret: String,
    pub(crate) user: UserService,
    pub(crate) views: Option<ViewService>,
    #[serde(default)]
    pub(crate) internal_secret_previous: String,
    #[serde(default = "default_streams")]
    pub(crate) max_streams: usize,
    #[serde(default = "default_connections")]
    pub(crate) max_connections: usize,
    #[serde(default = "default_header_timeout")]
    pub(crate) header_timeout_seconds: u64,
}

#[derive(Deserialize)]
pub(crate) struct ViewService {
    pub(crate) url: String,
    pub(crate) secret: String,
}

#[derive(Deserialize)]
pub(crate) struct UserService {
    pub(crate) url: String,
    pub(crate) cookie_name: String,
}

fn default_streams() -> usize {
    64
}

fn default_connections() -> usize {
    128
}

fn default_header_timeout() -> u64 {
    5
}

pub(crate) fn load_config(path: &Path) -> io::Result<(MediaConfig, Resources)> {
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "configuration must be a regular file",
        ));
    }

    let mut data = String::new();
    file.take(1024 * 1024 + 1).read_to_string(&mut data)?;
    if data.len() > 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "configuration exceeds 1 MiB",
        ));
    }

    let config: Config = toml::from_str(&data)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid configuration"))?;
    let mut media = config.services.media;
    if config.media.kind != "dir" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "media service currently supports directory storage only",
        ));
    }

    media.directory = config.media.directory;

    if !media.host.is_loopback() || media.port == 0 || media.directory.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "media requires loopback, port and storage directory",
        ));
    }

    if media.directory.is_relative() {
        media.directory = path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(&media.directory);
    }

    if media.max_connections == 0
        || media.max_connections > 4096
        || media.header_timeout_seconds == 0
        || media.header_timeout_seconds > 60
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid connection or header timeout limit",
        ));
    }

    if config.resources.max_procs > 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid CPU worker count",
        ));
    }

    Ok((media, config.resources))
}
