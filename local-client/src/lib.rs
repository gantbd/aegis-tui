//! Compatibility facade for Aegis's owner-maintained local client.
#![forbid(unsafe_code)]

pub use aegis_local_client::{
    ClientErrorV1 as ClientError, LimitsV1, UnixPort as LocalPort, connect,
};
