use std::{io, sync::Arc};

use axum::{
    body::Body,
    extract::{Path, State as AppState},
    http::{header, HeaderMap, HeaderValue, Method, Response, StatusCode},
    routing::get,
    Router,
};
use futures_util::StreamExt;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::io::ReaderStream;
use uuid::Uuid;

use crate::{
    access,
    representation::{byte_range, file_type},
    state::State,
    storage, views,
};

pub fn router(state: Arc<State>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/internal/files/{id}/{name}", get(file))
        .route("/internal/posts/{post}/files/{id}/{name}", get(file))
        .route("/internal/posts/{post}/playback/{id}/{name}", get(playback))
        .with_state(state)
}

#[derive(Deserialize)]
struct FilePath {
    id: String,
    name: String,
    post: Option<String>,
}

async fn health() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn file(
    AppState(state): AppState<Arc<State>>,
    method: Method,
    headers: HeaderMap,
    Path(path): Path<FilePath>,
) -> Response<Body> {
    serve_file(state, method, headers, path, false).await
}

async fn playback(
    AppState(state): AppState<Arc<State>>,
    method: Method,
    headers: HeaderMap,
    Path(path): Path<FilePath>,
) -> Response<Body> {
    serve_file(state, method, headers, path, true).await
}

async fn serve_file(
    state: Arc<State>,
    method: Method,
    headers: HeaderMap,
    FilePath { id, name, post }: FilePath,
    count_view: bool,
) -> Response<Body> {
    if !access::authorized(&state, &headers) {
        return response(StatusCode::UNAUTHORIZED);
    }

    let id = match Uuid::parse_str(&id) {
        Ok(id) if !id.is_nil() => id,
        _ => return response(StatusCode::NOT_FOUND),
    };

    let post = match post.as_deref().map(Uuid::parse_str) {
        None => None,
        Some(Ok(post)) if !post.is_nil() => Some(post),
        _ => return response(StatusCode::NOT_FOUND),
    };

    let mime = match file_type(&name) {
        Some(mime) => mime,
        None => return response(StatusCode::NOT_FOUND),
    };

    let permit = match state.streams.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return response(StatusCode::SERVICE_UNAVAILABLE),
    };

    let viewer = match access::check(&state, &headers, id, post).await {
        Ok(viewer) => viewer,
        Err(status) => return response(status),
    };

    let init_segment = name.starts_with("init");
    let (file, size, permit) = match storage::open(state.root.clone(), id, name, permit).await {
        Ok(file) => file,
        Err(status) => return response(status),
    };

    // Range applies to GET; without validators an If-Range request must fall back to the full representation.
    let range = if method == Method::GET && !headers.contains_key(header::IF_RANGE) {
        headers.get(header::RANGE)
    } else {
        None
    };

    let (start, length, status) = match range {
        None => (0, size, StatusCode::OK),
        Some(value) => match value
            .to_str()
            .ok()
            .and_then(|range| byte_range(range, size))
        {
            Some((start, end)) => (start, end - start + 1, StatusCode::PARTIAL_CONTENT),
            None => {
                let mut res = response(StatusCode::RANGE_NOT_SATISFIABLE);
                if let Ok(value) = HeaderValue::from_str(&format!("bytes */{size}")) {
                    res.headers_mut().insert(header::CONTENT_RANGE, value);
                }
                return res;
            }
        },
    };

    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, mime)
        .header(header::CONTENT_LENGTH, length.to_string())
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::CACHE_CONTROL, "private, no-store")
        .header("x-content-type-options", "nosniff");

    if status == StatusCode::PARTIAL_CONTENT {
        builder = builder.header(
            header::CONTENT_RANGE,
            format!("bytes {start}-{}/{size}", start + length - 1),
        );
    }

    if method == Method::HEAD || length == 0 {
        return builder
            .body(Body::empty())
            .unwrap_or_else(|_| response(StatusCode::INTERNAL_SERVER_ERROR));
    }

    let mut file = tokio::fs::File::from_std(file);
    if file.seek(io::SeekFrom::Start(start)).await.is_err() {
        return response(StatusCode::INTERNAL_SERVER_ERROR);
    }

    let sink = count_view.then(|| state.views.clone()).flatten();
    let mut report = match (sink, post, viewer) {
        (Some(sink), Some(post), Some(viewer)) => {
            views::view_threshold(mime, init_segment, size, length)
                .map(|threshold| (sink, post, viewer, threshold))
        }
        _ => None,
    };
    let mut sent = 0;
    let stream = ReaderStream::with_capacity(file.take(length), 64 * 1024).map(move |chunk| {
        let _keep_permit = &permit;
        if let (Some((_, _, _, threshold)), Ok(bytes)) = (&report, &chunk) {
            sent += bytes.len() as u64;
            if sent >= *threshold {
                if let Some((sink, post, viewer, _)) = report.take() {
                    sink.record(post, id, viewer);
                }
            }
        }
        chunk
    });

    builder
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| response(StatusCode::INTERNAL_SERVER_ERROR))
}

fn response(status: StatusCode) -> Response<Body> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    response
}
