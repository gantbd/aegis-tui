//! Structured, bounded Ratatui administration over Aegis's managed session.

use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, sync_channel};

use aegis_admin_command::{
    AttenuateGrantV1, AuthorizeGrantV1, IssueGrantV1, ManagedErrorV1, ManagedGrantV1,
    ManagedLimitsV1, ManagedSessionStateV1, ManagedSessionV1, OperationIdV1, action_name,
    engine_name, parse_action, parse_engine, parse_resource,
};
use aegis_client::ServicePort;
use aegis_protocol::{ScopeV1, SessionHandleV1};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    text::Line,
    widgets::{Block, Borders, Paragraph, Wrap},
};

use crate::Lifecycle;

const MAX_COMMAND_BYTES: usize = 4096;
const MAX_RETAINED_RESULTS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedAuthorityInput {
    Insert(char),
    Backspace,
    Prepare,
    Arm,
    Confirm,
    Edit,
    Close,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedAuthorityDisposition {
    Connecting,
    Editing,
    Proposed,
    Armed,
    Pending,
    Applied,
    Refused,
    Fenced,
    Failed,
}

#[derive(Clone, Debug)]
enum Prepared {
    Issue(IssueGrantV1),
    Attenuate(AttenuateGrantV1),
    Authorize(AuthorizeGrantV1),
}

impl Prepared {
    fn confirmation(&self) -> String {
        match self {
            Self::Issue(value) => value.confirmation(),
            Self::Attenuate(value) => value.confirmation(),
            Self::Authorize(value) => value.confirmation(),
        }
    }

    fn verb(&self) -> &'static str {
        match self {
            Self::Issue(_) => "issue",
            Self::Attenuate(_) => "attenuate",
            Self::Authorize(_) => "authorize",
        }
    }
}

enum WorkerRequest {
    Execute(Prepared),
    Close,
}

enum WorkerReply {
    Ready,
    ConnectionFailed,
    Settled {
        disposition: ManagedAuthorityDisposition,
        notice: &'static str,
        retained: Vec<ManagedGrantV1>,
        decision: Option<String>,
    },
    Closed,
}

pub struct ManagedAuthorityComponent {
    requests: SyncSender<WorkerRequest>,
    replies: Receiver<WorkerReply>,
    command: String,
    prepared: Option<Prepared>,
    retained: Vec<ManagedGrantV1>,
    results: Vec<String>,
    disposition: ManagedAuthorityDisposition,
    notice: String,
}

impl ManagedAuthorityComponent {
    pub fn new_with_connector<P, F, E>(connector: F) -> Self
    where
        P: ServicePort + Send + 'static,
        P::Error: Send + 'static,
        F: FnOnce() -> Result<(SessionHandleV1, P), E> + Send + 'static,
        E: Send + 'static,
    {
        let (request_tx, request_rx) = sync_channel(1);
        let (reply_tx, reply_rx) = sync_channel(1);
        std::thread::spawn(move || {
            let Ok((session, port)) = connector() else {
                let _ = reply_tx.send(WorkerReply::ConnectionFailed);
                return;
            };
            let Ok(mut manager) = ManagedSessionV1::new(
                session,
                port,
                ManagedLimitsV1 {
                    max_grants: 8,
                    max_scopes_per_grant: 16,
                },
            ) else {
                let _ = reply_tx.send(WorkerReply::ConnectionFailed);
                return;
            };
            if reply_tx.send(WorkerReply::Ready).is_err() {
                return;
            }
            while let Ok(request) = request_rx.recv() {
                if matches!(request, WorkerRequest::Close) {
                    let _ = reply_tx.send(WorkerReply::Closed);
                    return;
                }
                let WorkerRequest::Execute(prepared) = request else {
                    unreachable!()
                };
                let confirmation = prepared.confirmation();
                let (result, decision) = match prepared {
                    Prepared::Issue(value) => {
                        (manager.issue(value, &confirmation).map(|_| ()), None)
                    }
                    Prepared::Attenuate(value) => {
                        (manager.attenuate(value, &confirmation).map(|_| ()), None)
                    }
                    Prepared::Authorize(value) => match manager.authorize(value, &confirmation) {
                        Ok(decision) => (
                            Ok(()),
                            Some(format!(
                                "authorized {} {} until {}",
                                engine_name(decision.engine),
                                action_name(decision.action),
                                decision.expires_at
                            )),
                        ),
                        Err(error) => (Err(error), None),
                    },
                };
                let (disposition, notice) = classify(result, manager.state());
                let terminal = disposition == ManagedAuthorityDisposition::Fenced;
                if reply_tx
                    .send(WorkerReply::Settled {
                        disposition,
                        notice,
                        retained: manager.retained(),
                        decision,
                    })
                    .is_err()
                    || terminal
                {
                    return;
                }
            }
        });
        Self {
            requests: request_tx,
            replies: reply_rx,
            command: String::new(),
            prepared: None,
            retained: Vec::new(),
            results: Vec::new(),
            disposition: ManagedAuthorityDisposition::Connecting,
            notice: "Opening one bounded Aegis administration session".into(),
        }
    }

    pub fn poll(&mut self) {
        loop {
            match self.replies.try_recv() {
                Ok(WorkerReply::Ready) => {
                    self.disposition = ManagedAuthorityDisposition::Editing;
                    self.notice =
                        "Aegis session ready; enter issue, attenuate, or authorize".into();
                }
                Ok(WorkerReply::ConnectionFailed) => {
                    self.disposition = ManagedAuthorityDisposition::Failed;
                    self.notice = "Aegis administration connection refused".into();
                }
                Ok(WorkerReply::Settled {
                    disposition,
                    notice,
                    retained,
                    decision,
                }) => {
                    self.disposition = disposition;
                    self.notice = notice.into();
                    self.retained = retained;
                    if let Some(decision) = decision {
                        self.push_result(decision);
                    }
                    if disposition == ManagedAuthorityDisposition::Applied {
                        self.push_result(format!(
                            "{} settled; {} retained grant(s)",
                            self.prepared.as_ref().map_or("command", Prepared::verb),
                            self.retained.len()
                        ));
                    }
                    self.prepared = None;
                    self.command.clear();
                }
                Ok(WorkerReply::Closed) => {
                    self.disposition = ManagedAuthorityDisposition::Failed;
                    self.notice =
                        "Aegis administration session closed; retained grants destroyed".into();
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    if self.disposition == ManagedAuthorityDisposition::Pending {
                        self.disposition = ManagedAuthorityDisposition::Fenced;
                        self.notice =
                            "Aegis administration worker ended after dispatch; session fenced"
                                .into();
                    }
                    break;
                }
            }
        }
    }

    pub fn update(&mut self, input: ManagedAuthorityInput, focused: bool) -> Lifecycle {
        if !focused {
            return Lifecycle::Running;
        }
        if input == ManagedAuthorityInput::Close {
            if self.disposition == ManagedAuthorityDisposition::Pending {
                self.notice = "Pending authority work must settle before closing".into();
                return Lifecycle::Running;
            }
            let _ = self.requests.try_send(WorkerRequest::Close);
            return Lifecycle::CloseRequested;
        }
        match (self.disposition, input) {
            (ManagedAuthorityDisposition::Editing, ManagedAuthorityInput::Insert(value))
                if !value.is_control() =>
            {
                if self.command.len() + value.len_utf8() <= MAX_COMMAND_BYTES {
                    self.command.push(value);
                } else {
                    self.notice = "Aegis command reached the 4096-byte bound".into();
                }
            }
            (ManagedAuthorityDisposition::Editing, ManagedAuthorityInput::Backspace) => {
                self.command.pop();
            }
            (ManagedAuthorityDisposition::Editing, ManagedAuthorityInput::Prepare) => {
                match parse_command(&self.command) {
                    Ok(prepared) => {
                        self.prepared = Some(prepared);
                        self.disposition = ManagedAuthorityDisposition::Proposed;
                        self.notice = "Exact owner confirmation prepared; c arms".into();
                    }
                    Err(error) => self.notice = error.into(),
                }
            }
            (ManagedAuthorityDisposition::Proposed, ManagedAuthorityInput::Arm) => {
                self.disposition = ManagedAuthorityDisposition::Armed;
                self.notice = "ARMED: Enter submits exactly once on this private session".into();
            }
            (ManagedAuthorityDisposition::Armed, ManagedAuthorityInput::Confirm) => {
                if let Some(prepared) = self.prepared.clone()
                    && self
                        .requests
                        .try_send(WorkerRequest::Execute(prepared))
                        .is_ok()
                {
                    self.disposition = ManagedAuthorityDisposition::Pending;
                    self.notice = "Aegis managed command pending; no retry is permitted".into();
                } else {
                    self.disposition = ManagedAuthorityDisposition::Failed;
                    self.notice =
                        "Aegis administration worker unavailable before submission".into();
                }
            }
            (_, ManagedAuthorityInput::Edit)
                if !matches!(
                    self.disposition,
                    ManagedAuthorityDisposition::Connecting
                        | ManagedAuthorityDisposition::Pending
                        | ManagedAuthorityDisposition::Fenced
                ) =>
            {
                self.prepared = None;
                self.disposition = ManagedAuthorityDisposition::Editing;
                self.notice = "Edit the bounded administration command".into();
            }
            _ => {}
        }
        Lifecycle::Running
    }

    pub fn draw_in(&self, frame: &mut Frame<'_>, area: Rect, focused: bool) {
        let [body, footer] =
            Layout::vertical([Constraint::Min(1), Constraint::Length(2)]).areas(area);
        let title = if focused {
            " Aegis managed administration • focused "
        } else {
            " Aegis managed administration "
        };
        let mut lines = vec![
            Line::from("grammar:"),
            Line::from("issue OP EPOCH NOW EXPIRES ENGINE:RESOURCE:ACTION+ACTION[;...]"),
            Line::from("attenuate OP PARENT EPOCH NOW EXPIRES ENGINE:RESOURCE:ACTIONS[;...]"),
            Line::from("authorize OP NOW ENGINE RESOURCE ACTION"),
            Line::from(format!("command: {}", self.command)),
            Line::from(format!("state: {:?}", self.disposition)),
        ];
        if let Some(prepared) = &self.prepared {
            lines.push(Line::from(format!(
                "exact confirmation: {}",
                prepared.confirmation()
            )));
        }
        lines.push(Line::from(format!(
            "retained grants: {} / 8",
            self.retained.len()
        )));
        for grant in &self.retained {
            lines.push(Line::from(format!(
                "op {} · parent {} · epoch {} · expiry {} · scopes {} · depth {}",
                hex(grant.operation.into_bytes()),
                grant
                    .parent
                    .map_or_else(|| "root".into(), |value| hex(value.into_bytes())),
                grant.epoch,
                grant.expires_at,
                grant.scope_count,
                grant.delegation_depth
            )));
        }
        lines.extend(self.results.iter().map(|value| Line::from(value.as_str())));
        frame.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .block(Block::default().borders(Borders::ALL).title(title)),
            body,
        );
        frame.render_widget(
            Paragraph::new(format!(
                "{} • Enter prepare/confirm • c arm • e edit • Esc close",
                self.notice
            )),
            footer,
        );
    }

    pub const fn disposition(&self) -> ManagedAuthorityDisposition {
        self.disposition
    }

    pub fn notice(&self) -> &str {
        &self.notice
    }

    fn push_result(&mut self, value: String) {
        if self.results.len() == MAX_RETAINED_RESULTS {
            self.results.remove(0);
        }
        self.results.push(value);
    }
}

fn classify<E>(
    result: Result<(), ManagedErrorV1<E>>,
    state: ManagedSessionStateV1,
) -> (ManagedAuthorityDisposition, &'static str) {
    if state == ManagedSessionStateV1::Fenced {
        return (
            ManagedAuthorityDisposition::Fenced,
            "Aegis managed session fenced; reconnect and deliberately rebuild authority",
        );
    }
    match result {
        Ok(()) => (
            ManagedAuthorityDisposition::Applied,
            "Aegis command applied",
        ),
        Err(ManagedErrorV1::ConfirmationMismatch { .. }) => (
            ManagedAuthorityDisposition::Refused,
            "Aegis confirmation refused before submission",
        ),
        Err(ManagedErrorV1::OperationExists) => (
            ManagedAuthorityDisposition::Refused,
            "Aegis operation name already exists",
        ),
        Err(ManagedErrorV1::OperationMissing) => (
            ManagedAuthorityDisposition::Refused,
            "Aegis parent or authorization operation is not retained",
        ),
        Err(ManagedErrorV1::Capacity) => (
            ManagedAuthorityDisposition::Refused,
            "Aegis retained-grant capacity reached",
        ),
        Err(ManagedErrorV1::StaleEpoch { .. }) => (
            ManagedAuthorityDisposition::Refused,
            "Aegis epoch changed; inspect current authority before rebuilding",
        ),
        Err(ManagedErrorV1::Refused { .. }) => (
            ManagedAuthorityDisposition::Refused,
            "Aegis owner refused the managed command",
        ),
        Err(ManagedErrorV1::InvalidRequest | ManagedErrorV1::InvalidLimits) => (
            ManagedAuthorityDisposition::Refused,
            "Aegis managed request is invalid",
        ),
        Err(
            ManagedErrorV1::SessionFenced
            | ManagedErrorV1::Transport { .. }
            | ManagedErrorV1::InvalidReply { .. },
        ) => (
            ManagedAuthorityDisposition::Fenced,
            "Aegis managed outcome is uncertain; session fenced without retry",
        ),
    }
}

fn parse_command(value: &str) -> Result<Prepared, &'static str> {
    let parts = value.split_ascii_whitespace().collect::<Vec<_>>();
    match parts.as_slice() {
        ["issue", operation, epoch, now, expires, scopes] => Ok(Prepared::Issue(IssueGrantV1 {
            operation: parse_operation(operation)?,
            expected_epoch: number(epoch)?,
            now: number(now)?,
            expires_at: number(expires)?,
            scopes: parse_scopes(scopes)?,
        })),
        ["attenuate", operation, parent, epoch, now, expires, scopes] => {
            Ok(Prepared::Attenuate(AttenuateGrantV1 {
                operation: parse_operation(operation)?,
                parent: parse_operation(parent)?,
                expected_epoch: number(epoch)?,
                now: number(now)?,
                expires_at: number(expires)?,
                scopes: parse_scopes(scopes)?,
            }))
        }
        ["authorize", operation, now, engine, resource, action] => {
            Ok(Prepared::Authorize(AuthorizeGrantV1 {
                operation: parse_operation(operation)?,
                now: number(now)?,
                engine: parse_engine(engine).ok_or("unknown Aegis engine")?,
                resource: parse_resource(resource)
                    .ok_or("resource must be 32 lowercase hex digits")?,
                action: parse_action(action).ok_or("unknown Aegis action")?,
            }))
        }
        _ => Err("Use issue, attenuate, or authorize with the exact displayed grammar"),
    }
}

fn parse_operation(value: &str) -> Result<OperationIdV1, &'static str> {
    parse_resource(value)
        .map(OperationIdV1::new)
        .ok_or("operation names must be 32 lowercase hex digits")
}

fn number(value: &str) -> Result<u64, &'static str> {
    value.parse().map_err(|_| "epoch/time values must be u64")
}

fn parse_scopes(value: &str) -> Result<Vec<ScopeV1>, &'static str> {
    let scopes = value
        .split(';')
        .map(|value| {
            let parts = value.split(':').collect::<Vec<_>>();
            let [engine, resource, actions] = parts.as_slice() else {
                return Err("scope syntax is ENGINE:RESOURCE:ACTION+ACTION");
            };
            let engine = parse_engine(engine).ok_or("unknown scope engine")?;
            let resource =
                parse_resource(resource).ok_or("scope resource must be 32 lowercase hex digits")?;
            let mut bits = 0_u8;
            for value in actions.split('+') {
                let action = parse_action(value).ok_or("unknown scope action")?;
                bits |= 1 << action as u8;
            }
            if bits == 0 {
                return Err("scope requires at least one action");
            }
            Ok(ScopeV1 {
                engine,
                resource,
                actions: bits,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if scopes.is_empty() || scopes.len() > 16 {
        return Err("issue and attenuation require 1–16 scopes");
    }
    Ok(scopes)
}

fn hex(bytes: [u8; 16]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use aegis_admin_command::action_name;

    use super::*;

    #[test]
    fn grammar_accepts_bounded_multi_scope_issue_and_exact_authorize() {
        let operation = "01010101010101010101010101010101";
        let resource = "07070707070707070707070707070707";
        let issue = parse_command(&format!(
            "issue {operation} 4 5 30 hermes:{resource}:observe+delegate;moira:{resource}:administer"
        ))
        .unwrap();
        let Prepared::Issue(issue) = issue else {
            panic!("issue grammar changed variant")
        };
        assert_eq!(issue.scopes.len(), 2);
        assert!(issue.confirmation().contains("SCOPES hermes:"));
        assert!(issue.confirmation().contains(",moira:"));

        let authorize = parse_command(&format!(
            "authorize {operation} 7 hermes {resource} observe"
        ))
        .unwrap();
        let Prepared::Authorize(authorize) = authorize else {
            panic!("authorize grammar changed variant")
        };
        assert_eq!(action_name(authorize.action), "observe");
    }

    #[test]
    fn grammar_refuses_free_form_or_unbounded_authority_material() {
        assert!(parse_command("issue not-an-operation 4 5 30 hermes:x:observe").is_err());
        assert!(parse_command("authorize 00 7 hermes 00 observe").is_err());
        let scopes = (0..17)
            .map(|_| "hermes:07070707070707070707070707070707:observe")
            .collect::<Vec<_>>()
            .join(";");
        assert!(
            parse_command(&format!(
                "issue 01010101010101010101010101010101 4 5 30 {scopes}"
            ))
            .is_err()
        );
    }
}
