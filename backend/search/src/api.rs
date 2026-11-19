use std::sync::Arc;

use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware,
    routing::{get, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::index::{Document, Index, UpdateOutcome};

pub(crate) struct Credentials {
    pub(crate) reader: Vec<u8>,
    pub(crate) reader_previous: Option<Vec<u8>>,
    pub(crate) writer: Vec<u8>,
    pub(crate) writer_previous: Option<Vec<u8>>,
    pub(crate) content_writer: Option<Vec<u8>>,
    pub(crate) content_writer_previous: Option<Vec<u8>>,
}

struct App {
    index: Arc<Index>,
    credentials: Credentials,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchQuery {
    kind: String,
    q: String,
    limit: Option<i64>,
}

#[derive(Serialize)]
struct Candidate {
    id: Uuid,
}

pub(crate) fn router(index: Arc<Index>, credentials: Credentials) -> Router {
    let app = Arc::new(App { index, credentials });

    Router::new()
        .route("/health", get(health))
        .route("/internal/documents/{kind}/{id}", put(update_document))
        .route("/internal/search", get(search))
        .layer(DefaultBodyLimit::max(8192))
        .layer(middleware::map_response(
            |mut response: axum::response::Response| async move {
                response.headers_mut().insert(
                    header::CACHE_CONTROL,
                    HeaderValue::from_static("private, no-store"),
                );
                response
            },
        ))
        .with_state(app)
}

fn authorized(headers: &HeaderMap, secret: &[u8], previous: Option<&[u8]>) -> bool {
    let mut values = headers.get_all("x-internal-secret").iter();

    match (values.next(), values.next()) {
        (Some(value), None) => {
            let mut matches = value.as_bytes().ct_eq(secret);

            if let Some(previous) = previous {
                matches |= value.as_bytes().ct_eq(previous);
            }

            matches.into()
        }
        _ => false,
    }
}

fn authorized_writer(headers: &HeaderMap, kind: &str, credentials: &Credentials) -> bool {
    match kind {
        "user" => authorized(
            headers,
            &credentials.writer,
            credentials.writer_previous.as_deref(),
        ),
        "content" => credentials.content_writer.as_deref().is_some_and(|secret| {
            authorized(
                headers,
                secret,
                credentials.content_writer_previous.as_deref(),
            )
        }),
        _ => false,
    }
}

fn valid_kind(kind: &str) -> bool {
    matches!(kind, "user" | "content")
}

async fn health() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn update_document(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path((kind, id)): Path<(String, Uuid)>,
    Json(document): Json<Document>,
) -> StatusCode {
    let credentials = &app.credentials;

    if !authorized_writer(&headers, &kind, credentials) {
        return StatusCode::UNAUTHORIZED;
    }

    if !valid_kind(&kind)
        || id.is_nil()
        || document.version <= 0
        || document.text.len() > 4096
        || document.text.contains('\0')
        || (document.deleted && !document.text.is_empty())
    {
        return StatusCode::BAD_REQUEST;
    }

    match app.index.update(kind, id, document).await {
        Ok(UpdateOutcome::Applied) => StatusCode::NO_CONTENT,
        Ok(UpdateOutcome::Conflict) => StatusCode::CONFLICT,
        Ok(UpdateOutcome::Unavailable) | Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

async fn search(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<SearchQuery>,
) -> Result<Json<Vec<Candidate>>, StatusCode> {
    let credentials = &app.credentials;

    if !authorized(
        &headers,
        &credentials.reader,
        credentials.reader_previous.as_deref(),
    ) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let limit = query.limit.unwrap_or(20);

    if !valid_kind(&query.kind)
        || query.q.trim().is_empty()
        || query.q.len() > 256
        || query.q.contains('\0')
        || !(1..=50).contains(&limit)
    {
        return Err(StatusCode::BAD_REQUEST);
    }

    let ids = app
        .index
        .search(query.kind, query.q, limit)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

    Ok(Json(ids.into_iter().map(|id| Candidate { id }).collect()))
}
