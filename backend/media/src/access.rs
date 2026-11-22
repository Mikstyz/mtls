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

#[derive(Clone, Copy)]
pub(crate) enum CoverFrame {
    Quarter,
    ThreeFifths,
}

pub(crate) struct Decision {
    pub viewer: Option<Uuid>,
    pub prefer_original: bool,
    pub duration_ms: Option<u64>,
    pub cover_frame: Option<CoverFrame>,
}

pub(crate) async fn check(
    state: &State,
    headers: &HeaderMap,
    id: Uuid,
    post: Option<Uuid>,
    profile: Option<Uuid>,
    cover: bool,
    review_case: Option<Uuid>,
) -> Result<Decision, StatusCode> {
    let path = if let Some(case) = review_case {
        format!("/api/users/media/{id}/moderation/{case}/access")
    } else {
        match (post, profile) {
            (Some(post), None) if cover => format!("/api/users/media/{id}/covers/{post}/access"),
            (Some(post), None) => format!("/api/users/media/{id}/posts/{post}/access"),
            (None, Some(owner)) => format!("/api/users/{owner}/profile/media/{id}/access"),
            (None, None) => format!("/api/users/media/{id}/access"),
            (Some(_), Some(_)) => return Err(StatusCode::NOT_FOUND),
        }
    };
    check_path(state, headers, &path, false).await
}

pub(crate) async fn check_cover_frame(
    state: &State,
    headers: &HeaderMap,
    id: Uuid,
) -> Result<Decision, StatusCode> {
    check_path(
        state,
        headers,
        &format!("/api/users/media/{id}/ownership"),
        true,
    )
    .await
}

pub(crate) async fn check_profile_moderation(
    state: &State,
    headers: &HeaderMap,
    id: Uuid,
    case: Uuid,
) -> Result<Decision, StatusCode> {
    check_path(
        state,
        headers,
        &format!("/api/users/media/{id}/profile-moderation/{case}/access"),
        false,
    )
    .await
}

async fn check_path(
    state: &State,
    headers: &HeaderMap,
    path: &str,
    require_video: bool,
) -> Result<Decision, StatusCode> {
    let access = state
        .access
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let cookie = session_cookie(headers, &access.cookie_name).ok_or(StatusCode::UNAUTHORIZED)?;
    let mut url = access.base.clone();
    url.set_path(path);

    match access
        .client
        .get(url)
        .header(header::COOKIE, cookie)
        .send()
        .await
    {
        Ok(response) if response.status() == StatusCode::NO_CONTENT => {
            if require_video {
                let mut kinds = response.headers().get_all("x-media-kind").iter();
                if !matches!((kinds.next(), kinds.next()), (Some(kind), None) if kind == "video") {
                    return Err(StatusCode::NOT_FOUND);
                }
            }

            let mut viewers = response.headers().get_all("x-viewer-id").iter();
            let viewer = match (viewers.next(), viewers.next()) {
                (Some(value), None) => value
                    .to_str()
                    .ok()
                    .and_then(|value| Uuid::parse_str(value).ok())
                    .filter(|id| !id.is_nil()),
                _ => None,
            };
            let mut popularity = response.headers().get_all("x-playback-popular").iter();
            let popular =
                matches!((popularity.next(), popularity.next()), (Some(v), None) if v == "1");
            let mut quality = response.headers().get_all("x-playback-quality").iter();
            let prefer_original = match (quality.next(), quality.next()) {
                (Some(value), None) if value == "original" => true,
                (Some(value), None) if value == "reduced" => false,
                (None, None) => popular,
                (Some(value), None) if value == "auto" => popular,
                _ => return Err(StatusCode::SERVICE_UNAVAILABLE),
            };
            let mut durations = response.headers().get_all("x-media-duration-ms").iter();
            let duration_ms = match (durations.next(), durations.next()) {
                (None, None) => None,
                (Some(value), None) => Some(
                    value
                        .to_str()
                        .ok()
                        .and_then(|s| s.parse::<u64>().ok())
                        .filter(|ms| (1..=86_400_000).contains(ms))
                        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?,
                ),
                _ => return Err(StatusCode::SERVICE_UNAVAILABLE),
            };
            let mut cover = response.headers().get_all("x-cover-frame").iter();
            let cover_frame = match (cover.next(), cover.next()) {
                (None, None) => None,
                (Some(value), None) if value == "poster-25.jpg" => Some(CoverFrame::Quarter),
                (Some(value), None) if value == "poster-60.jpg" => Some(CoverFrame::ThreeFifths),
                _ => return Err(StatusCode::SERVICE_UNAVAILABLE),
            };
            Ok(Decision {
                cover_frame,
                viewer,
                prefer_original,
                duration_ms,
            })
        }
        Ok(response) if response.status() == StatusCode::UNAUTHORIZED => {
            Err(StatusCode::UNAUTHORIZED)
        }
        Ok(response) if response.status() == StatusCode::FORBIDDEN => Err(StatusCode::FORBIDDEN),
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
