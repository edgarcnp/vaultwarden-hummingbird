//! Small shared helpers with no single owner module.

pub mod log;
pub mod net;
mod staged;

pub use staged::StagedFile;
