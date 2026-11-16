//! Peer-owned guards for authority-bearing Aegis administration.
//!
//! The guard performs exactly one mutation attempt. It never retries a
//! transport failure because the service may already have committed the
//! revocation.
#![forbid(unsafe_code)]

use aegis_client::{AdminClient, AuthorityClient, ClientError, ReadOnlyClient, ServicePort};
use aegis_protocol::{
    ActionV1, DecisionSummaryV1, EngineNamespaceV1, OutcomeV1, RefusalV1, ReplyV1, ScopeV1,
    SessionHandleV1,
};

pub const CAPABILITY: &str = "authority.revoke-epoch.v1";
pub const JOURNEY_CAPABILITY: &str = "authority.attenuate-authorize-once.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevokeEpoch {
    pub expected_epoch: u64,
}

impl RevokeEpoch {
    pub fn confirmation(self) -> String {
        format!("REVOKE AEGIS EPOCH {}", self.expected_epoch)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum RevokeError<E> {
    ConfirmationMismatch { required: String },
    EpochExhausted,
    ObservationTransport(E),
    ObservationRefused(RefusalV1),
    InvalidObservation,
    StaleEpoch { expected: u64, actual: u64 },
    MutationTransport(E),
    MutationRefused(RefusalV1),
    InvalidMutationReply,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityJourney {
    pub expected_epoch: u64,
    pub now: u64,
    pub parent_expires_at: u64,
    pub child_expires_at: u64,
    pub engine: EngineNamespaceV1,
    pub resource: [u8; 16],
    pub action: ActionV1,
}

impl AuthorityJourney {
    pub fn confirmation(self) -> String {
        format!(
            "AUTHORIZE AEGIS EPOCH {} {} {} {} UNTIL {}",
            self.expected_epoch,
            engine_name(self.engine),
            hex_resource(self.resource),
            action_name(self.action),
            self.child_expires_at
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityJourneyResult {
    pub epoch: u64,
    pub expires_at: u64,
    pub engine: EngineNamespaceV1,
    pub action: ActionV1,
}

#[derive(Debug, Eq, PartialEq)]
pub enum JourneyPhase {
    Issue,
    Attenuate,
    Authorize,
}

#[derive(Debug, Eq, PartialEq)]
pub enum JourneyError<E> {
    ConfirmationMismatch {
        required: String,
    },
    InvalidBounds,
    ObservationTransport(E),
    ObservationRefused(RefusalV1),
    InvalidObservation,
    StaleEpoch {
        expected: u64,
        actual: u64,
    },
    Transport {
        phase: JourneyPhase,
        error: E,
    },
    Refused {
        phase: JourneyPhase,
        refusal: RefusalV1,
    },
    InvalidReply {
        phase: JourneyPhase,
    },
}

/// Performs a bounded issue → attenuation → authorization journey on one
/// authenticated connection. Both grant handles remain private to this call
/// and die with the connection; only redacted authorization evidence escapes.
pub fn attenuate_authorize_once<P: ServicePort>(
    session: SessionHandleV1,
    port: P,
    request: AuthorityJourney,
    confirmation: &str,
) -> Result<AuthorityJourneyResult, JourneyError<P::Error>> {
    let required = request.confirmation();
    if confirmation != required {
        return Err(JourneyError::ConfirmationMismatch { required });
    }
    if request.now >= request.child_expires_at
        || request.child_expires_at > request.parent_expires_at
    {
        return Err(JourneyError::InvalidBounds);
    }

    let mut observer =
        ReadOnlyClient::new(session, port, 1).map_err(|_| JourneyError::InvalidObservation)?;
    let actual = match observer.status() {
        Ok(ReplyV1::Accepted(OutcomeV1::Status(status))) => status.epoch,
        Ok(ReplyV1::Refused(refusal)) => return Err(JourneyError::ObservationRefused(refusal)),
        Ok(_) | Err(ClientError::Limit) => return Err(JourneyError::InvalidObservation),
        Err(ClientError::Transport(error)) => {
            return Err(JourneyError::ObservationTransport(error));
        }
    };
    if actual != request.expected_epoch {
        return Err(JourneyError::StaleEpoch {
            expected: request.expected_epoch,
            actual,
        });
    }

    let requested_action = 1_u8 << request.action as u8;
    let parent_scope = ScopeV1 {
        engine: request.engine,
        resource: request.resource,
        actions: requested_action | (1_u8 << ActionV1::Delegate as u8),
    };
    let child_scope = ScopeV1 {
        actions: requested_action,
        ..parent_scope
    };
    let mut authority = AuthorityClient::new(session, observer.into_port());
    let parent = grant_reply(
        JourneyPhase::Issue,
        authority.issue(
            request.expected_epoch,
            request.now,
            request.parent_expires_at,
            vec![parent_scope],
        ),
    )?;
    let child = grant_reply(
        JourneyPhase::Attenuate,
        authority.attenuate(
            parent.handle,
            request.expected_epoch,
            request.now,
            request.child_expires_at,
            vec![child_scope],
        ),
    )?;
    let decision = decision_reply(
        JourneyPhase::Authorize,
        authority.authorize(
            child.handle,
            request.now,
            request.engine,
            request.resource,
            request.action,
        ),
    )?;
    Ok(AuthorityJourneyResult {
        epoch: decision.epoch,
        expires_at: decision.expires_at,
        engine: decision.engine,
        action: decision.action,
    })
}

fn grant_reply<E>(
    phase: JourneyPhase,
    reply: Result<ReplyV1, E>,
) -> Result<aegis_protocol::GrantSummaryV1, JourneyError<E>> {
    match reply {
        Ok(ReplyV1::Accepted(OutcomeV1::GrantIssued(grant))) => Ok(grant),
        Ok(ReplyV1::Refused(refusal)) => Err(JourneyError::Refused { phase, refusal }),
        Ok(_) => Err(JourneyError::InvalidReply { phase }),
        Err(error) => Err(JourneyError::Transport { phase, error }),
    }
}

fn decision_reply<E>(
    phase: JourneyPhase,
    reply: Result<ReplyV1, E>,
) -> Result<DecisionSummaryV1, JourneyError<E>> {
    match reply {
        Ok(ReplyV1::Accepted(OutcomeV1::Authorized(decision))) => Ok(decision),
        Ok(ReplyV1::Refused(refusal)) => Err(JourneyError::Refused { phase, refusal }),
        Ok(_) => Err(JourneyError::InvalidReply { phase }),
        Err(error) => Err(JourneyError::Transport { phase, error }),
    }
}

pub const fn engine_name(value: EngineNamespaceV1) -> &'static str {
    match value {
        EngineNamespaceV1::Agora => "agora",
        EngineNamespaceV1::Chronos => "chronos",
        EngineNamespaceV1::Vellum => "vellum",
        EngineNamespaceV1::Moira => "moira",
        EngineNamespaceV1::Hermes => "hermes",
        EngineNamespaceV1::Daimon => "daimon",
        EngineNamespaceV1::Aegis => "aegis",
    }
}

pub const fn action_name(value: ActionV1) -> &'static str {
    match value {
        ActionV1::Observe => "observe",
        ActionV1::Submit => "submit",
        ActionV1::Modify => "modify",
        ActionV1::Execute => "execute",
        ActionV1::Delegate => "delegate",
        ActionV1::Administer => "administer",
    }
}

pub fn parse_engine(value: &str) -> Option<EngineNamespaceV1> {
    Some(match value {
        "agora" => EngineNamespaceV1::Agora,
        "chronos" => EngineNamespaceV1::Chronos,
        "vellum" => EngineNamespaceV1::Vellum,
        "moira" => EngineNamespaceV1::Moira,
        "hermes" => EngineNamespaceV1::Hermes,
        "daimon" => EngineNamespaceV1::Daimon,
        "aegis" => EngineNamespaceV1::Aegis,
        _ => return None,
    })
}

pub fn parse_action(value: &str) -> Option<ActionV1> {
    Some(match value {
        "observe" => ActionV1::Observe,
        "submit" => ActionV1::Submit,
        "modify" => ActionV1::Modify,
        "execute" => ActionV1::Execute,
        "delegate" => ActionV1::Delegate,
        "administer" => ActionV1::Administer,
        _ => return None,
    })
}

pub fn parse_resource(value: &str) -> Option<[u8; 16]> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut resource = [0_u8; 16];
    for (index, output) in resource.iter_mut().enumerate() {
        *output = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(resource)
}

fn hex_resource(resource: [u8; 16]) -> String {
    resource.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Confirms the exact epoch, observes it through the read-only facade, and
/// submits one revocation through the administrative facade on the same
/// authenticated session and connection.
pub fn revoke_epoch<P: ServicePort>(
    session: SessionHandleV1,
    port: P,
    request: RevokeEpoch,
    confirmation: &str,
) -> Result<u64, RevokeError<P::Error>> {
    let required = request.confirmation();
    if confirmation != required {
        return Err(RevokeError::ConfirmationMismatch { required });
    }
    let expected_result = request
        .expected_epoch
        .checked_add(1)
        .ok_or(RevokeError::EpochExhausted)?;

    let mut observer = ReadOnlyClient::new(session, port, 1).map_err(|error| match error {
        ClientError::Limit => RevokeError::InvalidObservation,
        ClientError::Transport(error) => RevokeError::ObservationTransport(error),
    })?;
    let actual = match observer.status() {
        Ok(ReplyV1::Accepted(OutcomeV1::Status(status))) => status.epoch,
        Ok(ReplyV1::Refused(refusal)) => return Err(RevokeError::ObservationRefused(refusal)),
        Ok(_) => return Err(RevokeError::InvalidObservation),
        Err(ClientError::Limit) => return Err(RevokeError::InvalidObservation),
        Err(ClientError::Transport(error)) => {
            return Err(RevokeError::ObservationTransport(error));
        }
    };
    if actual != request.expected_epoch {
        return Err(RevokeError::StaleEpoch {
            expected: request.expected_epoch,
            actual,
        });
    }

    let mut admin = AdminClient::new(session, observer.into_port());
    match admin.revoke_epoch(request.expected_epoch) {
        Ok(ReplyV1::Accepted(OutcomeV1::EpochRevoked { epoch })) if epoch == expected_result => {
            Ok(epoch)
        }
        Ok(ReplyV1::Refused(refusal)) => Err(RevokeError::MutationRefused(refusal)),
        Ok(_) => Err(RevokeError::InvalidMutationReply),
        Err(error) => Err(RevokeError::MutationTransport(error)),
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::VecDeque, rc::Rc};

    use aegis_protocol::{
        AuthorityStatusV1, CommandV1, DecisionHandleV1, GrantHandleV1, GrantSummaryV1,
    };

    use super::*;

    struct Port {
        replies: VecDeque<Result<ReplyV1, &'static str>>,
        commands: Rc<RefCell<Vec<CommandV1>>>,
    }

    impl ServicePort for Port {
        type Error = &'static str;

        fn execute(
            &mut self,
            _session: SessionHandleV1,
            command: CommandV1,
        ) -> Result<ReplyV1, Self::Error> {
            self.commands.borrow_mut().push(command);
            self.replies.pop_front().expect("scripted reply")
        }
    }

    fn status(epoch: u64) -> ReplyV1 {
        ReplyV1::Accepted(OutcomeV1::Status(AuthorityStatusV1 {
            epoch,
            active_grants: 0,
            retained_decisions: 0,
        }))
    }

    #[test]
    fn exact_current_epoch_performs_one_revocation() {
        let commands = Rc::new(RefCell::new(Vec::new()));
        let port = Port {
            replies: VecDeque::from([
                Ok(status(7)),
                Ok(ReplyV1::Accepted(OutcomeV1::EpochRevoked { epoch: 8 })),
            ]),
            commands: Rc::clone(&commands),
        };
        assert_eq!(
            revoke_epoch(
                SessionHandleV1(3),
                port,
                RevokeEpoch { expected_epoch: 7 },
                "REVOKE AEGIS EPOCH 7",
            ),
            Ok(8)
        );
        assert_eq!(
            commands.borrow().as_slice(),
            [
                CommandV1::Status,
                CommandV1::RevokeEpoch { expected_epoch: 7 }
            ]
        );
    }

    #[test]
    fn mismatch_never_observes_or_mutates() {
        let commands = Rc::new(RefCell::new(Vec::new()));
        let error = revoke_epoch(
            SessionHandleV1(3),
            Port {
                replies: VecDeque::new(),
                commands: Rc::clone(&commands),
            },
            RevokeEpoch { expected_epoch: 7 },
            "revoke epoch 7",
        )
        .unwrap_err();
        assert_eq!(
            error,
            RevokeError::ConfirmationMismatch {
                required: "REVOKE AEGIS EPOCH 7".into()
            }
        );
        assert!(commands.borrow().is_empty());
    }

    #[test]
    fn stale_epoch_refuses_before_mutation() {
        let commands = Rc::new(RefCell::new(Vec::new()));
        let error = revoke_epoch(
            SessionHandleV1(3),
            Port {
                replies: VecDeque::from([Ok(status(8))]),
                commands: Rc::clone(&commands),
            },
            RevokeEpoch { expected_epoch: 7 },
            "REVOKE AEGIS EPOCH 7",
        )
        .unwrap_err();
        assert_eq!(
            error,
            RevokeError::StaleEpoch {
                expected: 7,
                actual: 8
            }
        );
        assert_eq!(commands.borrow().as_slice(), [CommandV1::Status]);
    }

    #[test]
    fn mutation_transport_uncertainty_is_returned_without_retry() {
        let commands = Rc::new(RefCell::new(Vec::new()));
        let error = revoke_epoch(
            SessionHandleV1(3),
            Port {
                replies: VecDeque::from([Ok(status(7)), Err("outcome_unknown")]),
                commands: Rc::clone(&commands),
            },
            RevokeEpoch { expected_epoch: 7 },
            "REVOKE AEGIS EPOCH 7",
        )
        .unwrap_err();
        assert_eq!(error, RevokeError::MutationTransport("outcome_unknown"));
        assert_eq!(
            commands.borrow().as_slice(),
            [
                CommandV1::Status,
                CommandV1::RevokeEpoch { expected_epoch: 7 }
            ]
        );
    }

    fn journey() -> AuthorityJourney {
        AuthorityJourney {
            expected_epoch: 7,
            now: 10,
            parent_expires_at: 30,
            child_expires_at: 20,
            engine: EngineNamespaceV1::Hermes,
            resource: [0xab; 16],
            action: ActionV1::Observe,
        }
    }

    fn grant(handle: u64, parent: Option<u64>, expires_at: u64) -> ReplyV1 {
        ReplyV1::Accepted(OutcomeV1::GrantIssued(GrantSummaryV1 {
            handle: GrantHandleV1(handle),
            parent: parent.map(GrantHandleV1),
            epoch: 7,
            expires_at,
            scope_count: 1,
            delegation_depth: u8::from(parent.is_some()),
        }))
    }

    #[test]
    fn exact_journey_keeps_handles_internal_and_authorizes_child() {
        let commands = Rc::new(RefCell::new(Vec::new()));
        let request = journey();
        let port = Port {
            replies: VecDeque::from([
                Ok(status(7)),
                Ok(grant(41, None, 30)),
                Ok(grant(42, Some(41), 20)),
                Ok(ReplyV1::Accepted(OutcomeV1::Authorized(
                    DecisionSummaryV1 {
                        handle: DecisionHandleV1(9),
                        epoch: 7,
                        expires_at: 20,
                        engine: EngineNamespaceV1::Hermes,
                        action: ActionV1::Observe,
                    },
                ))),
            ]),
            commands: Rc::clone(&commands),
        };
        assert_eq!(
            attenuate_authorize_once(SessionHandleV1(3), port, request, &request.confirmation()),
            Ok(AuthorityJourneyResult {
                epoch: 7,
                expires_at: 20,
                engine: EngineNamespaceV1::Hermes,
                action: ActionV1::Observe,
            })
        );
        let commands = commands.borrow();
        assert_eq!(commands.len(), 4);
        assert!(matches!(commands[0], CommandV1::Status));
        assert!(matches!(commands[1], CommandV1::Issue { .. }));
        assert!(matches!(
            commands[2],
            CommandV1::Attenuate {
                parent: GrantHandleV1(41),
                ..
            }
        ));
        assert!(matches!(
            commands[3],
            CommandV1::Authorize {
                grant: GrantHandleV1(42),
                ..
            }
        ));
    }

    #[test]
    fn journey_confirmation_and_bounds_refuse_before_connection_use() {
        let commands = Rc::new(RefCell::new(Vec::new()));
        let request = journey();
        let error = attenuate_authorize_once(
            SessionHandleV1(3),
            Port {
                replies: VecDeque::new(),
                commands: Rc::clone(&commands),
            },
            request,
            "authorize",
        )
        .unwrap_err();
        assert!(matches!(error, JourneyError::ConfirmationMismatch { .. }));

        let invalid = AuthorityJourney {
            child_expires_at: 31,
            ..request
        };
        assert_eq!(
            attenuate_authorize_once(
                SessionHandleV1(3),
                Port {
                    replies: VecDeque::new(),
                    commands: Rc::clone(&commands)
                },
                invalid,
                &invalid.confirmation(),
            ),
            Err(JourneyError::InvalidBounds)
        );
        assert!(commands.borrow().is_empty());
    }

    #[test]
    fn attenuation_transport_uncertainty_is_not_retried_or_authorized() {
        let commands = Rc::new(RefCell::new(Vec::new()));
        let request = journey();
        let error = attenuate_authorize_once(
            SessionHandleV1(3),
            Port {
                replies: VecDeque::from([
                    Ok(status(7)),
                    Ok(grant(41, None, 30)),
                    Err("outcome_unknown"),
                ]),
                commands: Rc::clone(&commands),
            },
            request,
            &request.confirmation(),
        )
        .unwrap_err();
        assert_eq!(
            error,
            JourneyError::Transport {
                phase: JourneyPhase::Attenuate,
                error: "outcome_unknown",
            }
        );
        assert_eq!(commands.borrow().len(), 3);
    }
}
