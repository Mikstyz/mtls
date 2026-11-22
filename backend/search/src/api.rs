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

use crate::index::{Document, Index, RankPosition, UpdateOutcome};

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
    before_id: Option<Uuid>,
    before_rank: Option<f32>,
    snapshot: Option<i64>,
    prefix: Option<String>,
}

#[derive(Serialize)]
struct Candidate {
    id: Uuid,
}

#[derive(Serialize)]
struct PagePosition {
    id: Uuid,
    rank: f32,
    snapshot: i64,
}

#[derive(Serialize)]
struct SearchPage {
    candidates: Vec<Candidate>,
    next: Option<PagePosition>,
}

pub(crate) fn router(index: Arc<Index>, credentials: Credentials) -> Router {
    let app = Arc::new(App { index, credentials });

    Router::new()
        .route("/health", get(health))
        .route("/internal/documents/{kind}/{id}", put(update_document))
        .route("/internal/search", get(search))
        .route("/internal/search/page", get(search_page))
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

    if !query.is_valid(limit)
        || query.before_id.is_some()
        || query.before_rank.is_some()
        || query.snapshot.is_some()
        || query.prefix.is_some()
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

impl SearchQuery {
    fn is_valid(&self, limit: i64) -> bool {
        let (has_terms, prefix_len) = match self.prefix.as_deref() {
            None => (!self.q.trim().is_empty(), 0),
            Some(prefix) => (
                prefix.len() <= 64
                    && prefix.chars().count() >= 2
                    && prefix.chars().all(char::is_alphanumeric),
                prefix.len(),
            ),
        };

        valid_kind(&self.kind)
            && has_terms
            && self.q.len() + prefix_len <= 256
            && !self.q.contains('\0')
            && (1..=50).contains(&limit)
    }
}

async fn search_page(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<SearchQuery>,
) -> Result<Json<SearchPage>, StatusCode> {
    let credentials = &app.credentials;
    if !authorized(
        &headers,
        &credentials.reader,
        credentials.reader_previous.as_deref(),
    ) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let limit = query.limit.unwrap_or(20);
    if !query.is_valid(limit) {
        return Err(StatusCode::BAD_REQUEST);
    }

    if query.prefix.is_some()
        && (query.before_id.is_some() || query.before_rank.is_some() || query.snapshot.is_some())
    {
        return Err(StatusCode::BAD_REQUEST);
    }

    let before = match (query.before_id, query.before_rank, query.snapshot) {
        (None, None, None) => None,
        (Some(id), Some(rank), Some(snapshot))
            if !id.is_nil() && rank.is_finite() && rank >= 0.0 && snapshot > 0 =>
        {
            Some(RankPosition { id, rank, snapshot })
        }
        _ => return Err(StatusCode::BAD_REQUEST),
    };

    let mut rows = app
        .index
        .search_page(
            query.kind,
            query.q,
            query.prefix.unwrap_or_default(),
            limit + 1,
            before,
        )
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let next = if rows.len() > limit as usize {
        rows.truncate(limit as usize);
        rows.last().map(|row| PagePosition {
            id: row.id,
            rank: row.rank,
            snapshot: row.snapshot,
        })
    } else {
        None
    };

    Ok(Json(SearchPage {
        candidates: rows
            .into_iter()
            .map(|row| Candidate { id: row.id })
            .collect(),
        next,
    }))
}
