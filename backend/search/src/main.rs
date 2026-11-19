mod api;
mod config;
mod index;

use hyper::server::conn::http1;
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use std::{io, sync::Arc, time::Duration};
use tokio_postgres::NoTls;

use config::{load_config, Config};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config()?;
    let workers = if config.resources.max_procs == 0 {
        std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1)
    } else {
        config.resources.max_procs
    };

    if config.resources.memory_limit_bytes != 0 {
        eprintln!("search does not apply resources.memory_limit_bytes; enforce memory with a service cgroup");
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()?;
    runtime.block_on(run(config))
}

async fn run(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    let service = config.services.search;
    let mut dbconfig = tokio_postgres::Config::new();
    dbconfig
        .host(service.database.host.to_string())
        .port(config.database.port)
        .user(&config.database.user)
        .password(&config.database.password)
        .dbname(&service.database.name)
        .options("-c statement_timeout=3000 -c lock_timeout=1000")
        .connect_timeout(Duration::from_secs(5));
    let (db, connection) = dbconfig.connect(NoTls).await?;
    let dbtask = tokio::spawn(connection);
    // The lock lives on this database connection until the search process exits.
    let fence: i64 = 759_854_169_704_014_648;
    let locked: bool = db
        .query_one("SELECT pg_try_advisory_lock_shared($1)", &[&fence])
        .await?
        .try_get(0)?;

    if !locked {
        return Err(io::Error::other("search index rebuild is in progress").into());
    }

    db.simple_query("SELECT kind, id, source_version, deleted, search_text, document FROM search_documents LIMIT 0").await?;
    let floors: i64 = db
        .query_one(
            "SELECT count(*) FROM search_version_floors WHERE kind IN ('user', 'content')",
            &[],
        )
        .await?
        .try_get(0)?;

    if floors != 2 {
        return Err(io::Error::other("search version floors are missing").into());
    }

    let index = Arc::new(index::Index::new(db, service.max_db_requests));
    let credentials = api::Credentials {
        reader: service.reader_secret.into_bytes(),
        reader_previous: (!service.reader_secret_previous.is_empty())
            .then(|| service.reader_secret_previous.into_bytes()),
        writer: service.writer_secret.into_bytes(),
        writer_previous: (!service.writer_secret_previous.is_empty())
            .then(|| service.writer_secret_previous.into_bytes()),
        content_writer: (!service.content_writer_secret.is_empty())
            .then(|| service.content_writer_secret.into_bytes()),
        content_writer_previous: (!service.content_writer_secret_previous.is_empty())
            .then(|| service.content_writer_secret_previous.into_bytes()),
    };
    let router = api::router(index, credentials);
    let listener = tokio::net::TcpListener::bind((service.host, service.port)).await?;
    let connections = Arc::new(tokio::sync::Semaphore::new(service.max_connections));
    let (stop, _) = tokio::sync::watch::channel(false);
    let mut tasks = tokio::task::JoinSet::new();
    let signal = shutdown();
    tokio::pin!(signal);
    tokio::pin!(dbtask);

    loop {
        tokio::select! {
            _ = &mut signal => break,
            _ = &mut dbtask => return Err(io::Error::other("search database connection lost").into()),
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            accepted = listener.accept() => {
                let (socket, _) = accepted?;
                let permit = match connections.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => continue,
                };

                let mut stopped = stop.subscribe();
                let handler = TowerToHyperService::new(router.clone());
                let header_timeout = Duration::from_secs(service.header_timeout_seconds);
                let request_timeout = Duration::from_secs(service.request_timeout_seconds);

                tasks.spawn(async move {
                    let _permit = permit;
                    let mut builder = http1::Builder::new();
                    builder
                        .timer(TokioTimer::new())
                        .header_read_timeout(header_timeout)
                        .max_buf_size(16 * 1024)
                        .keep_alive(false);

                    let connection = builder.serve_connection(TokioIo::new(socket), handler);
                    tokio::pin!(connection);

                    tokio::select! {
                        _ = tokio::time::timeout(request_timeout, &mut connection) => {}
                        _ = stopped.changed() => {
                            connection.as_mut().graceful_shutdown();
                            let _ = connection.await;
                        }
                    }
                });
            }
        }
    }

    drop(listener);
    let _ = stop.send(true);
    if tokio::time::timeout(Duration::from_secs(15), async {
        while tasks.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        tasks.abort_all();
        return Err(io::Error::new(io::ErrorKind::TimedOut, "search shutdown timed out").into());
    }
    Ok(())
}

async fn shutdown() {
    #[cfg(unix)]
    if let Ok(mut terminate) =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }

        return;
    }
    let _ = tokio::signal::ctrl_c().await;
}
