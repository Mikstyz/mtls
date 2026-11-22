use std::io::SeekFrom;

use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt},
};

const INDEX_SIZE: usize = 52;
const BOX_HEADER_SIZE: usize = 8;

// The processing worker emits an SIDX for the video track before every
// moof/mdat pair, with an additional SIDX between them when audio is present.
pub(crate) async fn is_complete_video_fragment(file: &mut File, start: u64, length: u64) -> bool {
    let Some(offset) = start.checked_sub((2 * INDEX_SIZE) as u64) else {
        return false;
    };
    if length < (2 * BOX_HEADER_SIZE) as u64 {
        return false;
    }

    let mut prefix = [0; 2 * INDEX_SIZE + BOX_HEADER_SIZE];
    if file.seek(SeekFrom::Start(offset)).await.is_err()
        || file.read_exact(&mut prefix).await.is_err()
    {
        return false;
    }

    let video_only = &prefix[INDEX_SIZE..2 * INDEX_SIZE];
    let video_with_audio = &prefix[..INDEX_SIZE];
    if !matches_video_index(video_only, 0, length)
        && !matches_video_index(video_with_audio, INDEX_SIZE as u64, length)
    {
        return false;
    }

    let header = &prefix[2 * INDEX_SIZE..];
    let moof_size = u64::from(read_u32(header));
    if &header[4..] != b"moof"
        || moof_size < BOX_HEADER_SIZE as u64
        || moof_size > length - BOX_HEADER_SIZE as u64
    {
        return false;
    }

    let mut mdat = [0; BOX_HEADER_SIZE];
    file.seek(SeekFrom::Start(start + moof_size)).await.is_ok()
        && file.read_exact(&mut mdat).await.is_ok()
        && &mdat[4..] == b"mdat"
        && u64::from(read_u32(&mdat)) == length - moof_size
}

fn matches_video_index(index: &[u8], next_index_size: u64, length: u64) -> bool {
    read_u32(index) as usize == INDEX_SIZE
        && &index[4..8] == b"sidx"
        && read_u32(&index[8..]) == 1 << 24
        && read_u32(&index[12..]) == 1
        && read_u32(&index[16..]) != 0
        && u64::from_be_bytes(index[28..36].try_into().expect("eight-byte SIDX offset"))
            == next_index_size
        && read_u32(&index[36..]) == 1
        && u64::from(read_u32(&index[40..])) == length
        && read_u32(&index[44..]) != 0
        && read_u32(&index[48..]) >> 31 == 1
}

fn read_u32(data: &[u8]) -> u32 {
    u32::from_be_bytes(data[..4].try_into().expect("four-byte MP4 field"))
}
