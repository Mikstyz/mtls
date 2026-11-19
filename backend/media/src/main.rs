mod config;

use config::{load_config, MediaConfig};
use hyper::server::conn::http1;
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use std::{env, io, path::PathBuf, sync::Arc, time::Duration};

fn main() -> io::Result<()> {
    let mut args = env::args_os().skip(1);
    let path = match (args.next(), args.next(), args.next()) {
        (None, None, None) => PathBuf::from("config.toml"),
        (Some(flag), Some(path), None) if flag == "-config" => PathBuf::from(path),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "usage: mtls-media [-config path]",
            ))
        }
    };

    let (config, resources) = load_config(&path)?;
    let previous_secret = if config.internal_secret_previous.is_empty() {
        None
    } else {
        Some(config.internal_secret_previous.as_str())
    };
    let mut state = mtls_media::State::with_secrets(
        &config.directory,
        &config.internal_secret,
        previous_secret,
        config.max_streams,
    )?;
    state.configure_user_access(&config.user.url, &config.user.cookie_name)?;
    let workers = if resources.max_procs == 0 {
        std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1)
    } else {
        resources.max_procs
    };

    if resources.memory_limit_bytes != 0 {
        eprintln!("media does not apply resources.memory_limit_bytes; enforce memory with a service cgroup");
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .max_blocking_threads(config.max_streams + 4)
        .enable_all()
        .build()?;

    runtime.block_on(serve(config, state))
}

async fn serve(config: MediaConfig, mut state: mtls_media::State) -> io::Result<()> {
    let reporter = config
        .views
        .as_ref()
        .map(|views| state.configure_view_reporting(&views.url, &views.secret))
        .transpose()?;
    let state = Arc::new(state);
    let listener = tokio::net::TcpListener::bind((config.host, config.port)).await?;
    eprintln!("media listening on {}:{}", config.host, config.port);

    let connections = Arc::new(tokio::sync::Semaphore::new(config.max_connections));
    let (stop, _) = tokio::sync::watch::channel(false);
    let mut tasks = tokio::task::JoinSet::new();
    let app = mtls_media::router(state);
    let signal = shutdown();
    tokio::pin!(signal);

    loop {
        tokio::select! {
            _ = &mut signal => break,
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            accepted = listener.accept() => {
                let (socket, _) = accepted?;
                let permit = match connections.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => continue,
                };

                let mut stopped = stop.subscribe();
                let service = TowerToHyperService::new(app.clone());
                let timeout = Duration::from_secs(config.header_timeout_seconds);

                tasks.spawn(async move {
                    let _permit = permit;
                    let mut builder = http1::Builder::new();
                    builder
                        .timer(TokioTimer::new())
                        .header_read_timeout(timeout)
                        .max_buf_size(16 * 1024)
                        .keep_alive(false);

                    let connection = builder.serve_connection(TokioIo::new(socket), service);
                    tokio::pin!(connection);

                    tokio::select! {
                        _ = &mut connection => {}
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
    let drained = tokio::time::timeout(Duration::from_secs(15), async {
        while tasks.join_next().await.is_some() {}
    })
    .await;

    if drained.is_err() {
        tasks.abort_all();
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "media shutdown timed out",
        ));
    }

    drop(app);
    if let Some(reporter) = reporter {
        reporter.drain().await;
    }

    Ok(())
}

async fn shutdown() {
    #[cfg(unix)]
    {
        if let Ok(mut terminate) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
