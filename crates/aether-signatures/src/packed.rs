//! An on-disk SHA-256 index for large, reviewed hash collections.
//! A prefix table bounds the search to one bucket without mapping the index.
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::FileExt;
use std::path::Path;
#[cfg(not(unix))]
use std::sync::Mutex;

const MAGIC: &[u8; 8] = b"AVSHA256";
const BUCKETS: usize = 1 << 16;
const HEADER_BYTES: u64 = 8 + (BUCKETS as u64 + 1) * 8;
const DIGEST_BYTES: u64 = 32;
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

pub struct PackedHashDb {
    #[cfg(unix)]
    file: File,
    #[cfg(not(unix))]
    file: Mutex<File>,
    offsets: Vec<u64>,
}

impl PackedHashDb {
    pub fn open(path: &Path) -> io::Result<Self> {
        let mut file = BufReader::new(File::open(path)?);
        let len = file.get_ref().metadata()?.len();
        let mut tag = [0; 8];
        file.read_exact(&mut tag)?;
        if &tag != MAGIC || len < HEADER_BYTES || !(len - HEADER_BYTES).is_multiple_of(DIGEST_BYTES)
        {
            return Err(invalid("invalid packed SHA-256 index header"));
        }
        let count = (len - HEADER_BYTES) / DIGEST_BYTES;
        let mut offsets = Vec::with_capacity(BUCKETS + 1);
        for _ in 0..=BUCKETS {
            let mut encoded = [0; 8];
            file.read_exact(&mut encoded)?;
            offsets.push(u64::from_le_bytes(encoded));
        }
        if offsets.first() != Some(&0)
            || offsets.last() != Some(&count)
            || offsets.windows(2).any(|pair| pair[0] > pair[1])
        {
            return Err(invalid("invalid packed SHA-256 index offsets"));
        }
        let file = file.into_inner();
        Ok(Self {
            #[cfg(unix)]
            file,
            #[cfg(not(unix))]
            file: Mutex::new(file),
            offsets,
        })
    }

    pub fn len(&self) -> u64 {
        self.offsets[BUCKETS]
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn contains(&self, hex_sha256: &str) -> io::Result<bool> {
        let Some(target) = decode(hex_sha256) else {
            return Ok(false);
        };
        let b = bucket(&target);
        let (mut lo, mut hi) = (self.offsets[b], self.offsets[b + 1]);
        if lo == hi {
            return Ok(false);
        }
        #[cfg(unix)]
        let read_digest = |offset, digest: &mut [u8; 32]| self.file.read_exact_at(digest, offset);
        #[cfg(not(unix))]
        let mut read_digest = {
            let mut file = self
                .file
                .lock()
                .map_err(|_| io::Error::other("packed index lock poisoned"))?;
            move |offset, digest: &mut [u8; 32]| {
                file.seek(SeekFrom::Start(offset))?;
                file.read_exact(digest)
            }
        };
        let mut digest = [0; 32];
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            read_digest(HEADER_BYTES + mid * DIGEST_BYTES, &mut digest)?;
            match digest.cmp(&target) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Equal => return Ok(true),
                std::cmp::Ordering::Greater => hi = mid,
            }
        }
        Ok(false)
    }
}

/// Write hashes from a sorted text list with one SHA-256 per line. A label
/// after the digest is allowed. The caller owns output staging and publication.
pub fn write_index(input: impl BufRead, mut output: impl Write + Seek) -> io::Result<u64> {
    let mut offsets = vec![0u64; BUCKETS + 1];
    output.write_all(MAGIC)?;
    for _ in &offsets {
        output.write_all(&[0; 8])?;
    }
    let (mut count, mut boundary, mut last) = (0u64, 0usize, None);
    let mut input = input;
    let mut line = String::new();
    let mut number = 0;
    loop {
        line.clear();
        if input.by_ref().take(4097).read_line(&mut line)? == 0 {
            break;
        }
        number += 1;
        if line.len() > 4096 {
            return Err(invalid(format!("line {number}: exceeds 4096 bytes")));
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let text = line.split_whitespace().next().unwrap_or_default();
        let Some(digest) = decode(text) else {
            return Err(invalid(format!("line {number}: invalid SHA-256")));
        };
        if last.is_some_and(|prev| prev >= digest) {
            return Err(invalid(format!(
                "line {number}: hashes must be sorted and unique"
            )));
        }
        while boundary <= bucket(&digest) {
            offsets[boundary] = count;
            boundary += 1;
        }
        output.write_all(&digest)?;
        last = Some(digest);
        count += 1;
    }
    if count == 0 {
        return Err(invalid("refusing to publish an empty signature index"));
    }
    offsets[boundary..].fill(count);
    output.seek(SeekFrom::Start(8))?;
    for offset in offsets {
        output.write_all(&offset.to_le_bytes())?;
    }
    output.flush()?;
    Ok(count)
}

fn decode(text: &str) -> Option<[u8; 32]> {
    let mut digest = [0; 32];
    hex::decode_to_slice(text, &mut digest).ok()?;
    if digest == [0; 32] || text.eq_ignore_ascii_case(EMPTY_SHA256) {
        return None;
    }
    Some(digest)
}

fn bucket(digest: &[u8; 32]) -> usize {
    u16::from_be_bytes([digest[0], digest[1]]) as usize
}

fn invalid(reason: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufWriter, Cursor};

    #[test]
    fn searches_buckets_and_rejects_duplicates() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let low = "1".repeat(64);
        let high = "f".repeat(64);
        let input = format!("{low} Known.Low\n{high} Known.High\n");
        write_index(Cursor::new(input), BufWriter::new(file.reopen().unwrap())).unwrap();
        let db = PackedHashDb::open(file.path()).unwrap();
        assert_eq!(db.len(), 2);
        assert!(db.contains(&low).unwrap());
        assert!(db.contains(&high.to_uppercase()).unwrap());
        assert!(!db.contains(&"e".repeat(64)).unwrap());
        let duplicate = format!("{low}\n{low}\n");
        assert!(write_index(Cursor::new(duplicate), Cursor::new(Vec::new())).is_err());
    }

    #[test]
    fn concurrent_reads_find_hits_and_misses_in_one_bucket() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let values = (1..=128).map(|i| format!("{:064x}\n", i * 2));
        let input: String = values.collect();
        write_index(Cursor::new(input), BufWriter::new(file.reopen().unwrap())).unwrap();
        let db = PackedHashDb::open(file.path()).unwrap();

        std::thread::scope(|scope| {
            for lane in 0..8 {
                let db = &db;
                scope.spawn(move || {
                    for i in (lane + 1..=128).step_by(8) {
                        assert!(db.contains(&format!("{:064x}", i * 2)).unwrap());
                        assert!(!db.contains(&format!("{:064x}", i * 2 + 1)).unwrap());
                    }
                });
            }
        });
    }
}
