use std::fmt;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    Io(std::io::Error),
    Unsupported {
        structure: &'static str,
    },
    OutOfBounds {
        offset: u64,
        requested: usize,
        image_len: u64,
    },
    Truncated {
        needed: usize,
        available: usize,
    },
    Malformed {
        structure: &'static str,
        reason: &'static str,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "image i/o error: {e}"),
            Error::Unsupported { structure } => write!(f, "unsupported structure: {structure}"),
            Error::OutOfBounds {
                offset,
                requested,
                image_len,
            } => write!(
                f,
                "read out of bounds: offset {offset} + {requested} bytes exceeds image length {image_len}"
            ),
            Error::Truncated { needed, available } => {
                write!(f, "buffer truncated: need {needed} bytes, have {available}")
            }
            Error::Malformed { structure, reason } => {
                write!(f, "malformed {structure}: {reason}")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Unsupported { .. }
            | Error::OutOfBounds { .. }
            | Error::Truncated { .. }
            | Error::Malformed { .. } => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Error::Io(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn displays_io_error_with_source() {
        let err = Error::Io(std::io::Error::other("boom"));
        assert!(err.to_string().contains("boom"));
        assert!(std::error::Error::source(&err).is_some());
    }

    #[test]
    fn displays_unsupported_without_source() {
        let err = Error::Unsupported {
            structure: "rmapbt",
        };
        assert!(err.to_string().contains("rmapbt"));
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn converts_from_io_error() {
        let err: Error = std::io::Error::other("disk").into();
        assert!(matches!(err, Error::Io(_)));
    }

    #[test]
    fn displays_out_of_bounds_details() {
        let err = Error::OutOfBounds {
            offset: 10,
            requested: 4,
            image_len: 12,
        };
        assert!(err.to_string().contains("offset 10 + 4"));
        assert!(err.to_string().contains("image length 12"));
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn displays_truncated_details() {
        let err = Error::Truncated {
            needed: 8,
            available: 3,
        };
        assert!(err.to_string().contains("need 8 bytes"));
        assert!(err.to_string().contains("have 3"));
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn displays_malformed_details() {
        let err = Error::Malformed {
            structure: "superblock",
            reason: "bad magic",
        };
        assert!(err.to_string().contains("malformed superblock"));
        assert!(err.to_string().contains("bad magic"));
        assert!(std::error::Error::source(&err).is_none());
    }
}
