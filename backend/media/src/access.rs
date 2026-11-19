use axum::http::{header, HeaderMap, StatusCode};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::state::State;

pub(crate) fn authorized(state: &State, headers: &HeaderMap) -> bool {
    let mut credentials = headers.get_all("x-internal-secret").iter();

    match (credentials.next(), credentials.next()) {
        (Some(value), None) => {
            let mut valid = value.as_bytes().ct_eq(&state.secret);

            if let Some(previous) = &state.previous_secret {
                valid |= value.as_bytes().ct_eq(previous);
            }

            valid.into()
        }
        _ => false,
    }
}

pub(crate) async fn check(
    state: &State,
    headers: &HeaderMap,
    id: Uuid,
    post: Option<Uuid>,
) -> Result<Option<Uuid>, StatusCode> {
    let access = state
        .access
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let cookie = session_cookie(headers, &access.cookie_name).ok_or(StatusCode::UNAUTHORIZED)?;
    let mut url = access.base.clone();
    let path = match post {
        Some(post) => format!("/api/users/media/{id}/posts/{post}/access"),
        None => format!("/api/users/media/{id}/access"),
    };
    url.set_path(&path);

    match access
        .client
        .get(url)
        .header(header::COOKIE, cookie)
        .send()
        .await
    {
        Ok(response) if response.status() == StatusCode::NO_CONTENT => {
            let mut viewers = response.headers().get_all("x-viewer-id").iter();
            match (viewers.next(), viewers.next()) {
                (Some(value), None) => Ok(value
                    .to_str()
                    .ok()
                    .and_then(|value| Uuid::parse_str(value).ok())
                    .filter(|id| !id.is_nil())),
                _ => Ok(None),
            }
        }
        Ok(response) if response.status() == StatusCode::UNAUTHORIZED => {
            Err(StatusCode::UNAUTHORIZED)
        }
        Ok(response) if response.status() == StatusCode::NOT_FOUND => Err(StatusCode::NOT_FOUND),
        _ => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}

fn session_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let mut found = None;
    for header_value in headers.get_all(header::COOKIE).iter() {
        let value = header_value.to_str().ok()?;
        for item in value.split(';') {
            let (key, token) = match item.trim().split_once('=') {
                Some(pair) => pair,
                None => continue,
            };
            if key != name {
                continue;
            }
            if found.is_some()
                || token.len() != 43
                || !token
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            {
                return None;
            }
            found = Some(format!("{name}={token}"));
        }
    }
    found
}
