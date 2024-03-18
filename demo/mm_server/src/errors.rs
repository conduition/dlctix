use crate::global_state::Stage;

use std::{
    error::Error,
    fmt::{self, Debug, Display, Formatter},
};

#[derive(Debug)]
pub(crate) struct WrongStageError(pub(crate) Stage);
impl Display for WrongStageError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "server is in {:?} stage, cannot accept new players",
            self.0
        )
    }
}
impl Error for WrongStageError {}

#[derive(Debug)]
pub(crate) struct InvalidInputError<T: Display + Debug>(pub(crate) T);

impl<T: Display + Debug> Display for InvalidInputError<T> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "invalid input from client: {}", self.0)
    }
}
impl<T: Display + Debug> Error for InvalidInputError<T> {}
