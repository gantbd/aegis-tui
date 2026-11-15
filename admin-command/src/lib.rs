//! Peer-owned guards for authority-bearing Aegis administration.
//!
//! The guard performs exactly one mutation attempt. It never retries a
//! transport failure because the service may already have committed the
//! revocation.
#![forbid(unsafe_code)]

use aegis_client::{AdminClient, ClientError, ReadOnlyClient, ServicePort};
use aegis_protocol::{OutcomeV1, RefusalV1, ReplyV1, SessionHandleV1};

pub const CAPABILITY: &str = "authority.revoke-epoch.v1";

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

    use aegis_protocol::{AuthorityStatusV1, CommandV1};

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
}
