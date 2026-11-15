#![cfg(unix)]
#![forbid(unsafe_code)]

use std::{convert::Infallible, os::unix::net::UnixStream, path::PathBuf, time::Duration};

use aegis_authority::{EngineId, Limits, PrincipalId, SessionId};
use aegis_local_daemon::unix::{Authenticator, Daemon};
use aegis_protocol::{ActionV1, CommandV1, EngineNamespaceV1, OutcomeV1, ReplyV1, ScopeV1};
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
    let mut service = Service::new(authority, authority_id, ServiceLimitsV1::default())
        .ok_or_else(|| std::io::Error::other("service configuration refused"))?;
    let seed_session = service
        .open_session(AuthenticatedSessionV1 {
            principal: PrincipalId::new([2; 16]),
            session: SessionId::new([4; 16]),
            administrator: true,
        })
        .map_err(|error| std::io::Error::other(format!("seed session refused: {error:?}")))?;
    for index in 0..6_u8 {
        let resource = [index; 16];
        let ReplyV1::Accepted(OutcomeV1::GrantIssued(grant)) = service
            .execute(
                seed_session,
                CommandV1::Issue {
                    expected_epoch: 0,
                    now: 1,
                    expires_at: 100 + u64::from(index),
                    scopes: vec![ScopeV1 {
                        engine: EngineNamespaceV1::Hermes,
                        resource,
                        actions: 1 << ActionV1::Observe as u8,
                    }],
                },
            )
            .map_err(|error| std::io::Error::other(format!("grant seed failed: {error:?}")))?
        else {
            return Err("grant seed was refused".into());
        };
        let ReplyV1::Accepted(OutcomeV1::Authorized(_)) = service
            .execute(
                seed_session,
                CommandV1::Authorize {
                    grant: grant.handle,
                    now: 2,
                    engine: EngineNamespaceV1::Hermes,
                    resource,
                    action: ActionV1::Observe,
                },
            )
            .map_err(|error| std::io::Error::other(format!("decision seed failed: {error:?}")))?
        else {
            return Err("decision seed was refused".into());
        };
    }
    let mut daemon = Daemon::bind_new(
        socket,
        service,
        Authentication,
        aegis_wire::LimitsV1::default(),
        Duration::from_secs(5),
        32,
    )?;
    daemon
        .serve_next()
        .map_err(|error| std::io::Error::other(format!("daemon failed: {error:?}")))?;
    Ok(())
}
