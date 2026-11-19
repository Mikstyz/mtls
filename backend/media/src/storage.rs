use std::{fs::File, io, sync::Arc};

use axum::http::StatusCode;
use cap_std::fs::{Dir, OpenOptions, OpenOptionsExt};
use tokio::sync::OwnedSemaphorePermit;
use uuid::Uuid;

pub(crate) async fn open(
    root: Arc<Dir>,
    id: Uuid,
    name: String,
    permit: OwnedSemaphorePermit,
) -> Result<(File, u64, OwnedSemaphorePermit), StatusCode> {
    let opened = tokio::task::spawn_blocking(move || {
        let mut dir_options = OpenOptions::new();
        dir_options
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK);

        let dir = root.open_with(id.to_string(), &dir_options)?;
        let dir = Dir::from_std_file(dir.into_std());
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);

        let file = dir.open_with(name, &options)?;
        let metadata = file.metadata()?;

        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a regular file",
            ));
        }

        Ok::<_, io::Error>((file.into_std(), metadata.len(), permit))
    })
    .await;

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
