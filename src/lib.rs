#![forbid(unsafe_code)]

pub type Result<T> = anyhow::Result<T>;

#[cfg(feature = "uploader")]
pub mod uploader;

#[cfg(feature = "notify")]
pub mod notify;
