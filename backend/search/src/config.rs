use serde::Deserialize;
use std::{
    env,
    fs::File,
    io::{self, Read},
    net::IpAddr,
    path::PathBuf,
};

#[derive(Deserialize)]
pub(crate) struct Config {
    pub(crate) database: SharedDatabase,
    pub(crate) services: Services,
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
pub(crate) struct SharedDatabase {
    pub(crate) driver: String,
    pub(crate) port: u16,
    pub(crate) user: String,
    #[serde(default)]
    pub(crate) password: String,
    #[serde(default)]
    pub(crate) sslmode: String,
}

#[derive(Deserialize)]
pub(crate) struct Services {
    pub(crate) search: SearchConfig,
}

#[derive(Deserialize)]
pub(crate) struct SearchConfig {
    pub(crate) host: IpAddr,
    pub(crate) port: u16,
    pub(crate) reader_secret: String,
    #[serde(default)]
    pub(crate) reader_secret_previous: String,
    pub(crate) writer_secret: String,
    #[serde(default)]
    pub(crate) writer_secret_previous: String,
    #[serde(default)]
    pub(crate) content_writer_secret: String,
    #[serde(default)]
    pub(crate) content_writer_secret_previous: String,
    #[serde(default = "default_max_connections")]
    pub(crate) max_connections: usize,
    #[serde(default = "default_db_requests")]
    pub(crate) max_db_requests: usize,
    #[serde(default = "default_header_timeout")]
    pub(crate) header_timeout_seconds: u64,
    #[serde(default = "default_request_timeout")]
    pub(crate) request_timeout_seconds: u64,
    pub(crate) database: Database,
}

fn default_max_connections() -> usize {
    128
}
fn default_db_requests() -> usize {
    8
}
fn default_header_timeout() -> u64 {
    5
}
fn default_request_timeout() -> u64 {
    10
}

#[derive(Deserialize)]
pub(crate) struct Database {
    pub(crate) host: IpAddr,
    pub(crate) name: String,
    pub(crate) sslmode: Option<String>,
}

pub(crate) fn load_config() -> io::Result<Config> {
    let mut args = env::args_os().skip(1);
    let path = match (args.next(), args.next(), args.next()) {
        (None, None, None) => PathBuf::from("config.toml"),
        (Some(flag), Some(path), None) if flag == "-config" => PathBuf::from(path),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "usage: mtls-search [-config path]",
            ))
        }
    };
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "config must be a regular file",
        ));
    }
    let mut data = String::new();
    file.take(1024 * 1024 + 1).read_to_string(&mut data)?;
    if data.len() > 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "config exceeds 1 MiB",
        ));
    }
    let config: Config = toml::from_str(&data)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid config"))?;
    let service = &config.services.search;
    let valid_secret =
        |s: &str| (32..=128).contains(&s.len()) && s.bytes().all(|b| (0x21..=0x7e).contains(&b));
    let sslmode = service
        .database
        .sslmode
        .as_deref()
        .unwrap_or(&config.database.sslmode);
    let secrets = [
        service.reader_secret.as_str(),
        service.writer_secret.as_str(),
        service.reader_secret_previous.as_str(),
        service.writer_secret_previous.as_str(),
        service.content_writer_secret.as_str(),
        service.content_writer_secret_previous.as_str(),
    ];
    let invalid_previous = secrets[2..]
        .iter()
        .any(|secret| !secret.is_empty() && !valid_secret(secret));
    let duplicate = secrets
        .iter()
        .enumerate()
        .any(|(index, secret)| !secret.is_empty() && secrets[index + 1..].contains(secret));
    if !service.host.is_loopback()
        || !service.database.host.is_loopback()
        || service.port == 0
        || !(1..=4096).contains(&service.max_connections)
        || !(1..=64).contains(&service.max_db_requests)
        || !(1..=60).contains(&service.header_timeout_seconds)
        || !(service.header_timeout_seconds..=120).contains(&service.request_timeout_seconds)
        || config.database.port == 0
        || config.resources.max_procs > 1024
        || config.database.driver != "postgres"
        || sslmode != "disable"
        || config.database.user.is_empty()
        || service.database.name.is_empty()
        || !valid_secret(&service.reader_secret)
        || !valid_secret(&service.writer_secret)
        || invalid_previous
        || (service.content_writer_secret.is_empty()
            && !service.content_writer_secret_previous.is_empty())
        || duplicate
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid search settings",
        ));
    }
    Ok(config)
}
