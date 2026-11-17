use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use aegis_client::ServicePort;
use aegis_protocol::{AuthorityStatusV1, CommandV1, OutcomeV1, ReplyV1, SessionHandleV1};
use aegis_tui::{Lifecycle, RevokeEpochComponent, RevokeEpochDisposition, RevokeEpochInput};
use ratatui::{Terminal, backend::TestBackend};

struct Port {
    commands: Arc<Mutex<Vec<CommandV1>>>,
    replies: VecDeque<Result<ReplyV1, &'static str>>,
}

impl ServicePort for Port {
    type Error = &'static str;

    fn execute(
        &mut self,
        session: SessionHandleV1,
        command: CommandV1,
    ) -> Result<ReplyV1, Self::Error> {
        assert_eq!(session, SessionHandleV1(4));
        self.commands.lock().unwrap().push(command);
        self.replies.pop_front().expect("fixture reply")
    }
}

fn component(
    replies: VecDeque<Result<ReplyV1, &'static str>>,
) -> (RevokeEpochComponent, Arc<Mutex<Vec<CommandV1>>>) {
    let commands = Arc::new(Mutex::new(Vec::new()));
    let worker_commands = Arc::clone(&commands);
    (
        RevokeEpochComponent::new_with_connector(
            move || -> Result<_, &'static str> {
                Ok((
                    SessionHandleV1(4),
                    Port {
                        commands: worker_commands,
                        replies,
                    },
                ))
            },
            7,
        ),
        commands,
    )
}

fn status(epoch: u64) -> ReplyV1 {
    ReplyV1::Accepted(OutcomeV1::Status(AuthorityStatusV1 {
        epoch,
        active_grants: 2,
        retained_decisions: 3,
    }))
}

fn settle(component: &mut RevokeEpochComponent) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while component.disposition() == RevokeEpochDisposition::Pending {
        component.poll();
        assert!(Instant::now() < deadline, "revocation did not settle");
        thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn exact_epoch_requires_arm_and_submits_once() {
    let (mut component, commands) = component(VecDeque::from([
        Ok(status(7)),
        Ok(ReplyV1::Accepted(OutcomeV1::EpochRevoked { epoch: 8 })),
    ]));
    component.update(RevokeEpochInput::Confirm, true);
    assert!(commands.lock().unwrap().is_empty());
    component.update(RevokeEpochInput::Arm, true);
    component.update(RevokeEpochInput::Confirm, true);
    settle(&mut component);
    assert_eq!(
        component.disposition(),
        RevokeEpochDisposition::Applied { epoch: 8 }
    );
    assert_eq!(
        *commands.lock().unwrap(),
        vec![
            CommandV1::Status,
            CommandV1::RevokeEpoch { expected_epoch: 7 }
        ]
    );

    let mut terminal = Terminal::new(TestBackend::new(100, 16)).unwrap();
    terminal
        .draw(|frame| component.draw_in(frame, frame.area(), true))
        .unwrap();
    let rendered = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert!(rendered.contains("GLOBAL AUTHORITY INVALIDATION"));
    assert!(rendered.contains("REVOKE AEGIS EPOCH 7"));
}

#[test]
fn uncertain_mutation_is_fenced_and_cannot_be_dismissed_or_retried() {
    let (mut component, commands) =
        component(VecDeque::from([Ok(status(7)), Err("outcome_unknown")]));
    component.update(RevokeEpochInput::Arm, true);
    component.update(RevokeEpochInput::Confirm, true);
    settle(&mut component);
    assert_eq!(
        component.disposition(),
        RevokeEpochDisposition::OutcomeUnknown
    );
    assert_eq!(
        component.update(RevokeEpochInput::Close, true),
        Lifecycle::Running
    );
    component.update(RevokeEpochInput::Arm, true);
    component.update(RevokeEpochInput::Confirm, true);
    assert_eq!(commands.lock().unwrap().len(), 2);
}
