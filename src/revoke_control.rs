//! Exact, one-shot authority epoch revocation workflow.

use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, sync_channel};

use aegis_admin_command::{RevokeEpoch, RevokeError, revoke_epoch};
use aegis_client::ServicePort;
use aegis_protocol::SessionHandleV1;
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};

use crate::Lifecycle;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevokeEpochInput {
    Arm,
    Confirm,
    Close,
}

pub fn translate_revoke_epoch_key(key: KeyEvent) -> Option<RevokeEpochInput> {
    if key.kind != KeyEventKind::Press || key.modifiers != KeyModifiers::NONE {
        return None;
    }
    match key.code {
        KeyCode::Char('c') => Some(RevokeEpochInput::Arm),
        KeyCode::Enter => Some(RevokeEpochInput::Confirm),
        KeyCode::Esc => Some(RevokeEpochInput::Close),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevokeEpochDisposition {
    Proposed,
    Armed,
    Pending,
    Applied { epoch: u64 },
    Refused,
    Failed,
    OutcomeUnknown,
}

struct WorkerReply {
    disposition: RevokeEpochDisposition,
    notice: String,
}

pub struct RevokeEpochComponent {
    submit: SyncSender<()>,
    replies: Receiver<WorkerReply>,
    request: RevokeEpoch,
    disposition: RevokeEpochDisposition,
    notice: String,
}

impl RevokeEpochComponent {
    /// Connection establishment, exact re-observation, and the single mutation
    /// attempt all run on the worker after confirmation.
    pub fn new_with_connector<P, F, C>(connector: F, expected_epoch: u64) -> Self
    where
        P: ServicePort + Send + 'static,
        P::Error: std::fmt::Debug + Send + 'static,
        F: FnOnce() -> Result<(SessionHandleV1, P), C> + Send + 'static,
        C: std::fmt::Debug + Send + 'static,
    {
        let request = RevokeEpoch { expected_epoch };
        let (submit_tx, submit_rx) = sync_channel(1);
        let (reply_tx, reply_rx) = sync_channel(1);
        std::thread::spawn(move || {
            if submit_rx.recv().is_err() {
                return;
            }
            let reply = match connector() {
                Ok((session, port)) => {
                    let confirmation = request.confirmation();
                    classify(revoke_epoch(session, port, request, &confirmation))
                }
                Err(error) => WorkerReply {
                    disposition: RevokeEpochDisposition::Failed,
                    notice: format!(
                        "Aegis control connection refused before submission: {error:?}"
                    ),
                },
            };
            let _ = reply_tx.send(reply);
        });
        Self {
            submit: submit_tx,
            replies: reply_rx,
            request,
            disposition: RevokeEpochDisposition::Proposed,
            notice: "Review the global epoch revocation; c arms, Enter submits once".into(),
        }
    }

    pub fn poll(&mut self) {
        match self.replies.try_recv() {
            Ok(reply) => {
                self.disposition = reply.disposition;
                self.notice = reply.notice;
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected)
                if self.disposition == RevokeEpochDisposition::Pending =>
            {
                self.disposition = RevokeEpochDisposition::OutcomeUnknown;
                self.notice =
                    "Aegis control worker disconnected after confirmation; outcome unknown".into();
            }
            Err(TryRecvError::Disconnected) => {}
        }
    }

    pub fn update(&mut self, input: RevokeEpochInput, focused: bool) -> Lifecycle {
        if !focused {
            return Lifecycle::Running;
        }
        if input == RevokeEpochInput::Close {
            if matches!(
                self.disposition,
                RevokeEpochDisposition::Pending | RevokeEpochDisposition::OutcomeUnknown
            ) {
                self.notice =
                    "Epoch revocation is unresolved; inspect current authority state before exit"
                        .into();
                return Lifecycle::Running;
            }
            return Lifecycle::CloseRequested;
        }
        match (self.disposition, input) {
            (RevokeEpochDisposition::Proposed, RevokeEpochInput::Arm) => {
                self.disposition = RevokeEpochDisposition::Armed;
                self.notice = "ARMED: Enter revokes the complete current authority epoch".into();
            }
            (RevokeEpochDisposition::Armed, RevokeEpochInput::Confirm) => {
                if self.submit.try_send(()).is_ok() {
                    self.disposition = RevokeEpochDisposition::Pending;
                    self.notice = "Aegis epoch revocation pending; no retry is permitted".into();
                } else {
                    self.disposition = RevokeEpochDisposition::Failed;
                    self.notice = "Aegis control worker unavailable before submission".into();
                }
            }
            (RevokeEpochDisposition::Armed, _) => {
                self.disposition = RevokeEpochDisposition::Proposed;
                self.notice = "Epoch revocation disarmed".into();
            }
            _ => {}
        }
        Lifecycle::Running
    }

    pub fn draw_in(&self, frame: &mut Frame<'_>, area: Rect, focused: bool) {
        let [body, footer] =
            Layout::vertical([Constraint::Min(1), Constraint::Length(2)]).areas(area);
        let title = if focused {
            " Aegis epoch revocation • focused "
        } else {
            " Aegis epoch revocation "
        };
        let warning = Style::default().fg(Color::Red).add_modifier(Modifier::BOLD);
        let lines = vec![
            Line::styled("GLOBAL AUTHORITY INVALIDATION", warning),
            Line::from(format!("current epoch: {}", self.request.expected_epoch)),
            Line::from(format!(
                "exact confirmation: {}",
                self.request.confirmation()
            )),
            Line::from("Effect: every grant in this epoch becomes invalid."),
            Line::from(vec![
                Span::styled("No retry", warning),
                Span::raw(" after uncertain delivery; refresh Aegis to reconcile."),
            ]),
            Line::from(format!("state: {:?}", self.disposition)),
        ];
        frame.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .block(Block::default().borders(Borders::ALL).title(title)),
            body,
        );
        frame.render_widget(
            Paragraph::new(format!(
                "{} • c arm • Enter confirm • Esc close",
                self.notice
            )),
            footer,
        );
    }

    pub const fn disposition(&self) -> RevokeEpochDisposition {
        self.disposition
    }

    pub fn notice(&self) -> &str {
        &self.notice
    }
}

fn classify<E: std::fmt::Debug>(result: Result<u64, RevokeError<E>>) -> WorkerReply {
    match result {
        Ok(epoch) => WorkerReply {
            disposition: RevokeEpochDisposition::Applied { epoch },
            notice: format!("Aegis authority epoch revoked; durable epoch is now {epoch}"),
        },
        Err(RevokeError::MutationTransport(error)) => WorkerReply {
            disposition: RevokeEpochDisposition::OutcomeUnknown,
            notice: format!("Aegis revocation outcome unknown after mutation dispatch: {error:?}"),
        },
        Err(error @ RevokeError::StaleEpoch { .. })
        | Err(error @ RevokeError::ObservationRefused(_))
        | Err(error @ RevokeError::MutationRefused(_)) => WorkerReply {
            disposition: RevokeEpochDisposition::Refused,
            notice: format!("Aegis revocation refused: {error:?}"),
        },
        Err(error) => WorkerReply {
            disposition: RevokeEpochDisposition::Failed,
            notice: format!("Aegis revocation failed before a valid receipt: {error:?}"),
        },
    }
}
