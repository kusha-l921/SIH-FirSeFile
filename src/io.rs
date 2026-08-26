use crate::error::{Error, Result};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

#[cfg(unix)]
const O_NOATIME: i32 = 0o1000000;

pub trait ImageRead {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()>;
}

fn check_bounds(image_len: u64, offset: u64, requested: usize) -> Result<()> {
    match offset.checked_add(requested as u64) {
        Some(end) if end <= image_len => Ok(()),
        _ => Err(Error::OutOfBounds {
            offset,
            requested,
            image_len,
        }),
    }
}

fn open_read_only(path: &Path) -> std::io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(O_NOATIME)
            .open(path)
        {
            Ok(file) => Ok(file),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                std::fs::OpenOptions::new().read(true).open(path)
            }
            Err(e) => Err(e),
        }
    }
    #[cfg(not(unix))]
    {
        std::fs::File::open(path)
    }
}

#[derive(Debug)]
pub struct FileImage {
    file: File,
    image_len: u64,
}

impl FileImage {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let file = open_read_only(path.as_ref())?;
        let image_len = file.metadata()?.len();
        Ok(Self { file, image_len })
    }

    pub fn len(&self) -> u64 {
        self.image_len
    }

    pub fn is_empty(&self) -> bool {
        self.image_len == 0
    }
}

impl ImageRead for FileImage {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_bounds(self.image_len, offset, buf.len())?;
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.read_exact(buf)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct MemImage<'a> {
    data: &'a [u8],
}

impl<'a> MemImage<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn len(&self) -> u64 {
        self.data.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl ImageRead for MemImage<'_> {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_bounds(self.data.len() as u64, offset, buf.len())?;
        let start = offset as usize;
        buf.copy_from_slice(&self.data[start..start + buf.len()]);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    static TMP_COUNTER: AtomicU32 = AtomicU32::new(0);

    fn temp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "xre-m1-{}-{}-{}.img",
            tag,
            std::process::id(),
            TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 % 251) as u8).collect()
    }

    #[test]
    fn file_image_round_trip_reads() {
        let path = temp_path("roundtrip");
        let data = pattern(5000);
        std::fs::write(&path, &data).unwrap();

        let mut img = FileImage::open(&path).unwrap();
        assert_eq!(img.len(), 5000);
        assert!(!img.is_empty());

        for &(off, chunk) in &[(0u64, 2000usize), (2000, 2500), (4500, 500)] {
            let mut buf = vec![0u8; chunk];
            img.read_at(off, &mut buf).unwrap();
            assert_eq!(buf, data[off as usize..off as usize + chunk]);
        }

        drop(img);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn file_image_read_beyond_eof_errors() {
        let path = temp_path("eof");
        std::fs::write(&path, b"0123456789").unwrap();
        let mut img = FileImage::open(&path).unwrap();

        let err = img.read_at(10, &mut [0u8; 1]).unwrap_err();
        assert!(matches!(err, Error::OutOfBounds { image_len: 10, .. }));

        let err = img.read_at(9, &mut [0u8; 2]).unwrap_err();
        assert!(matches!(err, Error::OutOfBounds { offset: 9, .. }));

        let err = img.read_at(u64::MAX, &mut []).unwrap_err();
        assert!(matches!(err, Error::OutOfBounds { .. }));

        img.read_at(9, &mut [0u8; 1]).unwrap();
        img.read_at(10, &mut []).unwrap();

        drop(img);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn file_image_open_missing_file_is_io_error() {
        let missing = temp_path("missing");
        let err = FileImage::open(&missing).unwrap_err();
        assert!(matches!(err, Error::Io(_)));
    }

    #[test]
    fn mem_image_slice_reads() {
        let data = b"hello world";
        let mut img = MemImage::new(data);

        assert_eq!(img.len(), 11);
        let mut buf = [0u8; 5];
        img.read_at(6, &mut buf).unwrap();
        assert_eq!(&buf, b"world");

        let mut whole = vec![0u8; 11];
        img.read_at(0, &mut whole).unwrap();
        assert_eq!(&whole, data);
    }

    #[test]
    fn mem_image_bounds_and_overflow() {
        let mut img = MemImage::new(b"abcde");

        assert!(img.read_at(5, &mut [0u8; 1]).is_err());
        assert!(img.read_at(3, &mut [0u8; 3]).is_err());
        assert!(img.read_at(u64::MAX, &mut [0u8; 1]).is_err());

        img.read_at(5, &mut []).unwrap();
        img.read_at(2, &mut [0u8; 3]).unwrap();
    }

    #[test]
    fn mem_image_empty() {
        let mut img = MemImage::new(b"");
        assert!(img.is_empty());
        img.read_at(0, &mut []).unwrap();
        assert!(img.read_at(0, &mut [0u8; 1]).is_err());
    }

    #[test]
    fn source_defines_no_write_capable_path() {
        let production = include_str!("io.rs").split("#[cfg(test)]").next().unwrap();
        for token in [
            "write(",
            "write_all",
            "io::Write",
            "truncate(",
            "append(",
            "set_len",
        ] {
            assert!(
                !production.contains(token),
                "forbidden write-capable token {token:?} found in production section"
            );
        }
        assert!(production.contains(".read(true)"));
    }
}
