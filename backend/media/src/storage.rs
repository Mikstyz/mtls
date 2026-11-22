use std::{fs::File, io, sync::Arc};

use axum::http::StatusCode;
use cap_std::fs::{Dir, OpenOptions, OpenOptionsExt};
use tokio::sync::OwnedSemaphorePermit;
use uuid::Uuid;

use crate::access::CoverFrame;

pub(crate) enum Selection {
    Named(String),
    Original,
    Reduced,
    PhotoPreview,
    PostCover(Option<CoverFrame>),
}

impl Selection {
    pub(crate) fn candidates(&self) -> &'static [&'static str] {
        match self {
            Self::PostCover(Some(CoverFrame::Quarter)) => &["poster-25.jpg", "poster.jpg"],
            Self::PostCover(Some(CoverFrame::ThreeFifths)) => &["poster-60.jpg", "poster.jpg"],
            Self::PostCover(None) => &["poster.jpg", "preview.jpg", "preview.png"],
            Self::PhotoPreview => &["preview.jpg", "preview.png"],
            Self::Original => &["original.mp4", "original.jpg", "original.png"],
            Self::Reduced => &[
                "preview.jpg",
                "preview.png",
                "720p.mp4",
                "1080p.mp4",
                "1440p.mp4",
                "2160p.mp4",
            ],
            Self::Named(_) => &[],
        }
    }
}

pub(crate) async fn open(
    root: Arc<Dir>,
    id: Uuid,
    selection: Selection,
    permit: OwnedSemaphorePermit,
) -> Result<(File, String, u64, OwnedSemaphorePermit), StatusCode> {
    let opened = tokio::task::spawn_blocking(move || {
        let dir = asset_dir(&root, id)?;
        let options = file_options();

        let (file, name) = match selection {
            Selection::Named(name) => (dir.open_with(&name, &options)?, name),
            _ => {
                let mut selected = None;
                for &name in selection.candidates() {
                    match dir.open_with(name, &options) {
                        Ok(file) => {
                            selected = Some((file, name.to_owned()));
                            break;
                        }
                        Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
                        Err(err) => return Err(err),
                    }
                }
                selected.ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?
            }
        };
        let metadata = file.metadata()?;

        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a regular file",
            ));
        }

        Ok::<_, io::Error>((file.into_std(), name, metadata.len(), permit))
    })
    .await;

    storage_result(opened)
}

pub(crate) async fn playback_variants(
    root: Arc<Dir>,
    id: Uuid,
    permit: OwnedSemaphorePermit,
) -> Result<(Vec<&'static str>, Option<&'static str>), StatusCode> {
    let opened = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let dir = asset_dir(&root, id)?;
        let options = file_options();
        let mut names = Vec::new();

        for selection in [Selection::Original, Selection::Reduced] {
            for &name in selection.candidates() {
                match dir.open_with(name, &options) {
                    Ok(file) if file.metadata()?.is_file() => names.push(name),
                    Ok(_) => return Err(io::Error::from(io::ErrorKind::InvalidInput)),
                    Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
                    Err(err) => return Err(err),
                }
            }
        }

        if names.is_empty() {
            return Err(io::Error::from(io::ErrorKind::NotFound));
        }
        let adaptive = match dir.open_with("adaptive.m3u8", &options) {
            Ok(file) if file.metadata()?.is_file() => Some("adaptive.m3u8"),
            Ok(_) => return Err(io::Error::from(io::ErrorKind::InvalidInput)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => None,
            Err(err) => return Err(err),
        };
        Ok((names, adaptive))
    })
    .await;
    storage_result(opened)
}

fn asset_dir(root: &Dir, id: Uuid) -> io::Result<Dir> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    root.open_with(id.to_string(), &options)
        .map(|file| Dir::from_std_file(file.into_std()))
}

fn file_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    options
}

fn storage_result<T>(
    opened: Result<io::Result<T>, tokio::task::JoinError>,
) -> Result<T, StatusCode> {
    match opened {
        Ok(Ok(file)) => Ok(file),
        Ok(Err(err))
            if matches!(
                err.kind(),
                io::ErrorKind::NotFound
                    | io::ErrorKind::PermissionDenied
                    | io::ErrorKind::InvalidInput
            ) || matches!(err.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)) =>
        {
            Err(StatusCode::NOT_FOUND)
        }
        _ => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}
