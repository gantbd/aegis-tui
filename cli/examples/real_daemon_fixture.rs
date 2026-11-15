#![cfg(unix)]
#![forbid(unsafe_code)]

use std::{convert::Infallible, os::unix::net::UnixStream, path::PathBuf, time::Duration};

use aegis_authority::{EngineId, Limits, PrincipalId, SessionId};
use aegis_local_daemon::unix::{Authenticator, Daemon};
use aegis_service::{AuthenticatedSessionV1, Service, ServiceLimitsV1};

struct Authentication;
impl Authenticator for Authentication {
    type Error = Infallible;
    fn authenticate(&mut self, _: &UnixStream) -> Result<AuthenticatedSessionV1, Self::Error> {
        Ok(AuthenticatedSessionV1 {
            principal: PrincipalId::new([2; 16]),
            session: SessionId::new([3; 16]),
            administrator: true,
        })
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1).map(PathBuf::from);
    let directory = args.next().ok_or("authority directory required")?;
    let socket = args.next().ok_or("socket path required")?;
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    let authority_id = EngineId::new([1; 16]);
    let authority = aegis_local::create_new(directory, authority_id, Limits::default())
        .map_err(|error| std::io::Error::other(format!("authority failed: {error:?}")))?;
    let service = Service::new(authority, authority_id, ServiceLimitsV1::default())
        .ok_or_else(|| std::io::Error::other("service configuration refused"))?;
    let mut daemon = Daemon::bind_new(
        socket,
        service,
        Authentication,
        aegis_wire::LimitsV1::default(),
        Duration::from_secs(5),
        8,
    )?;
    daemon
        .serve_next()
        .map_err(|error| std::io::Error::other(format!("daemon failed: {error:?}")))?;
    Ok(())
}
