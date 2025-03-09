use std::error::Error as StdError;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::result::Result as StdResult;

pub type Result<T> = StdResult<T, Error>;

/// Error type for ocrypt
#[derive(Clone, Debug)]
pub enum Error {
    StdError(String),
    SizeError,
}

impl Error {
    pub fn new<T, E>(err: E) -> Self
    where
        E: Display,
    {
        Error::StdError(err.to_string())
    }

    pub fn from<T, E>(err: E) -> Result<T>
    where
        E: Display,
    {
        Err(Error::StdError(err.to_string()))
    }
}

impl<T> From<Error> for Result<T> {
    fn from(val: Error) -> Self {
        Err(val)
    }
}

impl Display for Error {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        write!(
            formatter,
            "ocrypt error: {:?} ({})",
            self,
            match self {
                Error::StdError(err) => err,
                _ => "no details",
            }
        )
    }
}

impl StdError for Error {}
