use std::{io, sync::Arc};

use axum::{
    body::Body,
    extract::{Path, State as AppState},
    http::{header, HeaderMap, HeaderValue, Method, Response, StatusCode},
    routing::get,
    Json, Router,
};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::io::ReaderStream;
use uuid::Uuid;

use crate::{
    access, hls,
    representation::{byte_range, file_type},
    state::State,
    storage, views,
};

pub fn router(state: Arc<State>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/internal/files/{id}/{name}", get(file))
        .route("/internal/cover-frames/{id}/{frame}", get(file))
        .route("/internal/profiles/{profile}/files/{id}/{name}", get(file))
        .route("/internal/posts/{cover_post}/cover/{id}/{name}", get(file))
        .route("/internal/posts/{post}/files/{id}/{name}", get(file))
        .route(
            "/internal/posts/{post}/playback/{id}",
            get(playback_variants),
        )
        .route("/internal/posts/{post}/playback/{id}/{name}", get(playback))
        .route(
            "/internal/moderation/cases/{review_case}/files/{id}/{name}",
            get(file),
        )
        .route(
            "/internal/moderation/profile-images/{profile_case}/files/{id}/{name}",
            get(file),
        )
        .with_state(state)
}

#[derive(Deserialize)]
struct FilePath {
    id: String,
    name: Option<String>,
    frame: Option<String>,
    post: Option<String>,
    cover_post: Option<String>,
    profile: Option<String>,
    review_case: Option<String>,
    profile_case: Option<String>,
}

fn is_cover_frame(name: &str) -> bool {
    matches!(name, "poster-25.jpg" | "poster-60.jpg")
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

#[derive(Serialize)]
struct PlaybackVariants {
    variants: Vec<&'static str>,
    automatic: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    adaptive: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_ms: Option<u64>,
}

async fn playback_variants(
    AppState(state): AppState<Arc<State>>,
    headers: HeaderMap,
    Path((post, asset)): Path<(String, String)>,
) -> Response<Body> {
    if !access::authorized(&state, &headers) {
        return response(StatusCode::UNAUTHORIZED);
    }

    let (Ok(post), Ok(asset)) = (Uuid::parse_str(&post), Uuid::parse_str(&asset)) else {
        return response(StatusCode::NOT_FOUND);
    };
    if post.is_nil() || asset.is_nil() {
        return response(StatusCode::NOT_FOUND);
    }

    let permit = match state.streams.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return response(StatusCode::SERVICE_UNAVAILABLE),
    };
    let decision = match access::check(&state, &headers, asset, Some(post), None, false, None).await
    {
        Ok(decision) => decision,
        Err(status) => return response(status),
    };
    let (variants, adaptive) =
        match storage::playback_variants(state.root.clone(), asset, permit).await {
            Ok(variants) => variants,
            Err(status) => return response(status),
        };

    let selection = if decision.prefer_original {
        storage::Selection::Original
    } else {
        storage::Selection::Reduced
    };
    let automatic = selection
        .candidates()
        .iter()
        .copied()
        .find(|name| variants.contains(name));

    use axum::response::IntoResponse;
    (
        [
            (header::CACHE_CONTROL, "private, no-store"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        Json(PlaybackVariants {
            variants,
            automatic,
            adaptive,
            duration_ms: decision.duration_ms,
        }),
    )
        .into_response()
}

async fn serve_file(
    state: Arc<State>,
    method: Method,
    headers: HeaderMap,
    FilePath {
        id,
        name,
        frame,
        post,
        cover_post,
        profile,
        review_case,
        profile_case,
    }: FilePath,
    count_view: bool,
) -> Response<Body> {
    if !access::authorized(&state, &headers) {
        return response(StatusCode::UNAUTHORIZED);
    }

    let id = match Uuid::parse_str(&id) {
        Ok(id) if !id.is_nil() => id,
        _ => return response(StatusCode::NOT_FOUND),
    };

    let (name, owner_frame) = match (name, frame) {
        (None, Some(name)) if is_cover_frame(&name) => (name, true),
        (Some(name), None) if !is_cover_frame(&name) => (name, false),
        _ => return response(StatusCode::NOT_FOUND),
    };

    let cover = cover_post.is_some();
    if cover && name != "preview" {
        return response(StatusCode::NOT_FOUND);
    }
    let post = match post.or(cover_post).as_deref().map(Uuid::parse_str) {
        None => None,
        Some(Ok(post)) if !post.is_nil() => Some(post),
        _ => return response(StatusCode::NOT_FOUND),
    };

    let profile = match profile.as_deref().map(Uuid::parse_str) {
        None => None,
        Some(Ok(profile))
            if !profile.is_nil()
                && matches!(name.as_str(), "preview" | "preview.jpg" | "preview.png") =>
        {
            Some(profile)
        }
        _ => return response(StatusCode::NOT_FOUND),
    };

    let review_case = match review_case.as_deref().map(Uuid::parse_str) {
        None => None,
        Some(Ok(id)) if !id.is_nil() => Some(id),
        _ => return response(StatusCode::NOT_FOUND),
    };

    let profile_case = match profile_case.as_deref().map(Uuid::parse_str) {
        None => None,
        Some(Ok(case)) if !case.is_nil() && name == "preview" => Some(case),
        _ => return response(StatusCode::NOT_FOUND),
    };

    let permit = match state.streams.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return response(StatusCode::SERVICE_UNAVAILABLE),
    };

    let access = if let Some(case) = profile_case {
        access::check_profile_moderation(&state, &headers, id, case).await
    } else if owner_frame {
        access::check_cover_frame(&state, &headers, id).await
    } else {
        access::check(&state, &headers, id, post, profile, cover, review_case).await
    };
    let decision = match access {
        Ok(decision) => decision,
        Err(status) => return response(status),
    };

    let resolve_auto = count_view && name == "auto";
    let selection = match name.as_str() {
        "preview" if cover => storage::Selection::PostCover(decision.cover_frame),
        "preview" if review_case.is_some() => storage::Selection::PostCover(None),
        "preview" if profile.is_some() || profile_case.is_some() => {
            storage::Selection::PhotoPreview
        }
        "auto" if count_view && decision.prefer_original => storage::Selection::Original,
        "auto" if count_view => storage::Selection::Reduced,
        "original" if count_view => storage::Selection::Original,
        _ if file_type(&name).is_some() => storage::Selection::Named(name),
        _ => return response(StatusCode::NOT_FOUND),
    };
    let (file, name, size, permit) =
        match storage::open(state.root.clone(), id, selection, permit).await {
            Ok(file) => file,
            Err(status) => return response(status),
        };

    // Bind subsequent byte ranges to a single representation, even if popularity changes.
    if resolve_auto {
        let mut redirect = response(StatusCode::TEMPORARY_REDIRECT);
        let Ok(location) = HeaderValue::from_str(&name) else {
            return response(StatusCode::INTERNAL_SERVER_ERROR);
        };
        redirect.headers_mut().insert(header::LOCATION, location);
        return redirect;
    }

    let Some(mime) = file_type(&name) else {
        return response(StatusCode::NOT_FOUND);
    };
    let init_segment = name.starts_with("init");

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
    let sink = count_view.then(|| state.views.clone()).flatten();
    let mut report = match (sink, post, decision.viewer) {
        (Some(sink), Some(post), Some(viewer)) => {
            let mut threshold = views::view_threshold(mime, init_segment, size, length);
            if threshold.is_none()
                && status == StatusCode::PARTIAL_CONTENT
                && matches!(
                    name.as_str(),
                    "720p.mp4" | "1080p.mp4" | "1440p.mp4" | "2160p.mp4"
                )
                && hls::is_complete_video_fragment(&mut file, start, length).await
            {
                threshold = Some(length);
            }
            threshold.map(|threshold| (sink, post, viewer, threshold))
        }
        _ => None,
    };
    if file.seek(io::SeekFrom::Start(start)).await.is_err() {
        return response(StatusCode::INTERNAL_SERVER_ERROR);
    }

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
