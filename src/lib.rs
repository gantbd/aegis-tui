//! Composable, read-only Ratatui presentation over Aegis's public client.
#![forbid(unsafe_code)]

use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, sync_channel};

use aegis_client::{ReadOnlyClient, ServicePort};
use aegis_protocol::{
    AuthorityStatusV1, DecisionSummaryV1, GrantSummaryV1, OutcomeV1, ReplyV1, SessionHandleV1,
};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    text::Line,
    widgets::{Block, Borders, Paragraph},
};

pub const PAGE_LIMIT: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityManifest {
    pub schema: u8,
    pub peer: &'static str,
    pub interactive: &'static [&'static str],
    pub headless: &'static [&'static str],
}

pub const CAPABILITIES: CapabilityManifest = CapabilityManifest {
    schema: 1,
    peer: "aegis",
    interactive: &["authority.observe.v1"],
    headless: &["authority.observe.v1"],
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Input {
    Refresh,
    Close,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Lifecycle {
    Running,
    CloseRequested,
}

pub fn translate_key(key: KeyEvent) -> Option<Input> {
    if key.kind != KeyEventKind::Press || key.modifiers != KeyModifiers::NONE {
        return None;
    }
    match key.code {
        KeyCode::Char('r') => Some(Input::Refresh),
        KeyCode::Char('q') => Some(Input::Close),
        _ => None,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Observation {
    pub status: AuthorityStatusV1,
    pub grants: Vec<GrantSummaryV1>,
    pub more_grants: bool,
    pub decisions: Vec<DecisionSummaryV1>,
    pub more_decisions: bool,
}

struct WorkerReply(Result<Observation, String>);

pub struct Component {
    refresh: SyncSender<()>,
    replies: Receiver<WorkerReply>,
    pending: bool,
    observation: Option<Observation>,
    notice: String,
}

impl Component {
    pub fn new<P>(session: SessionHandleV1, port: P) -> Self
    where
        P: ServicePort + Send + 'static,
        P::Error: Send + 'static,
    {
        let (tx, rx) = sync_channel(1);
        let (reply_tx, reply_rx) = sync_channel(1);
        std::thread::spawn(move || {
            let Ok(mut client) = ReadOnlyClient::new(session, port, PAGE_LIMIT) else {
                return;
            };
            while rx.recv().is_ok() {
                if reply_tx.send(WorkerReply(observe(&mut client))).is_err() {
                    break;
                }
            }
        });
        let mut component = Self {
            refresh: tx,
            replies: reply_rx,
            pending: false,
            observation: None,
            notice: "Aegis ready; refresh queued".into(),
        };
        component.offer();
        component
    }

    pub fn poll(&mut self) {
        loop {
            match self.replies.try_recv() {
                Ok(WorkerReply(Ok(value))) => {
                    self.pending = false;
                    self.observation = Some(value);
                    self.notice = "Current authority observation".into();
                }
                Ok(WorkerReply(Err(status))) => {
                    self.pending = false;
                    self.notice = status;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.pending = false;
                    self.notice = "Aegis worker unavailable".into();
                    break;
                }
            }
        }
    }

    pub fn update(&mut self, input: Input, focused: bool) -> Lifecycle {
        if !focused {
            return Lifecycle::Running;
        }
        match input {
            Input::Close => Lifecycle::CloseRequested,
            Input::Refresh => {
                self.offer();
                Lifecycle::Running
            }
        }
    }

    pub fn draw_in(&self, frame: &mut Frame<'_>, area: Rect, focused: bool) {
        let [body, footer] =
            Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).areas(area);
        let title = if focused {
            " Aegis • focused "
        } else {
            " Aegis "
        };
        let lines = self.observation.as_ref().map_or_else(
            || vec![Line::from("No current authority observation")],
            |value| {
                let mut lines = vec![
                    Line::from(format!("epoch: {}", value.status.epoch)),
                    Line::from(format!("active grants: {}", value.status.active_grants)),
                    Line::from(format!(
                        "retained decisions: {}",
                        value.status.retained_decisions
                    )),
                    Line::from(format!(
                        "bounded page: {} grant(s){}; {} decision(s){}",
                        value.grants.len(),
                        if value.more_grants { "+" } else { "" },
                        value.decisions.len(),
                        if value.more_decisions { "+" } else { "" }
                    )),
                ];
                for grant in &value.grants {
                    lines.push(Line::from(format!(
                        "grant #{} epoch {} scopes {} depth {} expires {}",
                        grant.handle.0,
                        grant.epoch,
                        grant.scope_count,
                        grant.delegation_depth,
                        grant.expires_at
                    )));
                }
                for decision in &value.decisions {
                    lines.push(Line::from(format!(
                        "decision #{} epoch {} {:?}/{:?} expires {}",
                        decision.handle.0,
                        decision.epoch,
                        decision.engine,
                        decision.action,
                        decision.expires_at
                    )));
                }
                lines
            },
        );
        frame.render_widget(
            Paragraph::new(lines).block(Block::default().title(title).borders(Borders::ALL)),
            body,
        );
        frame.render_widget(Paragraph::new(self.notice.as_str()), footer);
    }

    fn offer(&mut self) {
        if self.pending {
            self.notice = "Aegis refresh already pending".into();
        } else if self.refresh.try_send(()).is_ok() {
            self.pending = true;
            self.notice = "Aegis refresh pending".into();
        } else {
            self.notice = "Aegis worker unavailable".into();
        }
    }
}

pub fn observe<P: ServicePort>(client: &mut ReadOnlyClient<P>) -> Result<Observation, String> {
    let status = match client.status().map_err(|_| "Aegis status unavailable")? {
        ReplyV1::Accepted(OutcomeV1::Status(value)) => value,
        ReplyV1::Refused(value) => return Err(format!("Aegis refused: {value:?}")),
        _ => return Err("Invalid Aegis status reply".into()),
    };
    let (grants, more_grants) = match client
        .grant_page(None, PAGE_LIMIT)
        .map_err(|_| "Aegis grant page unavailable")?
    {
        ReplyV1::Accepted(OutcomeV1::GrantPage {
            entries,
            next_after,
        }) => (entries, next_after.is_some()),
        ReplyV1::Refused(value) => return Err(format!("Aegis refused: {value:?}")),
        _ => return Err("Invalid Aegis grant page reply".into()),
    };
    let (decisions, more_decisions) = match client
        .decision_page(None, PAGE_LIMIT)
        .map_err(|_| "Aegis decision page unavailable")?
    {
        ReplyV1::Accepted(OutcomeV1::DecisionPage {
            entries,
            next_after,
        }) => (entries, next_after.is_some()),
        ReplyV1::Refused(value) => return Err(format!("Aegis refused: {value:?}")),
        _ => return Err("Invalid Aegis decision page reply".into()),
    };
    Ok(Observation {
        status,
        grants,
        more_grants,
        decisions,
        more_decisions,
    })
}
