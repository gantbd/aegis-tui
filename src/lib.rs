//! Composable, read-only Ratatui presentation over Aegis's public client.
#![forbid(unsafe_code)]

use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, sync_channel};

use aegis_client::{ReadOnlyClient, ServicePort};
use aegis_protocol::{
    AuthorityStatusV1, DecisionHandleV1, DecisionSummaryV1, GrantHandleV1, GrantSummaryV1,
    OutcomeV1, ReplyV1, SessionHandleV1,
};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    text::Line,
    widgets::{Block, Borders, Paragraph},
};

pub const PAGE_LIMIT: usize = 4;

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
    NextPage,
    PreviousPage,
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
        KeyCode::Char('n') => Some(Input::NextPage),
        KeyCode::Char('p') => Some(Input::PreviousPage),
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
    pub next_grants: Option<GrantHandleV1>,
    pub next_decisions: Option<DecisionHandleV1>,
}

#[derive(Clone, Copy)]
enum PageCursor<T> {
    Start,
    After(T),
    Exhausted,
}

#[derive(Clone, Copy)]
struct Request {
    grants: PageCursor<GrantHandleV1>,
    decisions: PageCursor<DecisionHandleV1>,
}

struct WorkerReply(Result<Observation, String>);

pub struct Component {
    refresh: SyncSender<Request>,
    replies: Receiver<WorkerReply>,
    pending: bool,
    observation: Option<Observation>,
    page: Request,
    history: Vec<Request>,
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
            while let Ok(request) = rx.recv() {
                if reply_tx
                    .send(WorkerReply(observe_page(&mut client, request)))
                    .is_err()
                {
                    break;
                }
            }
        });
        let mut component = Self {
            refresh: tx,
            replies: reply_rx,
            pending: false,
            observation: None,
            page: Request {
                grants: PageCursor::Start,
                decisions: PageCursor::Start,
            },
            history: Vec::new(),
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
            Input::NextPage => {
                if let Some(observation) = &self.observation {
                    if observation.next_grants.is_none() && observation.next_decisions.is_none() {
                        self.notice = "Last authority page".into();
                    } else if !self.pending {
                        let next = Request {
                            grants: observation
                                .next_grants
                                .map_or(PageCursor::Exhausted, PageCursor::After),
                            decisions: observation
                                .next_decisions
                                .map_or(PageCursor::Exhausted, PageCursor::After),
                        };
                        self.history.push(self.page);
                        self.page = next;
                        self.offer();
                    }
                }
                Lifecycle::Running
            }
            Input::PreviousPage => {
                if self.pending {
                    self.notice = "Aegis refresh already pending".into();
                } else if let Some(previous) = self.history.pop() {
                    self.page = previous;
                    self.offer();
                } else {
                    self.notice = "First authority page".into();
                }
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
                    Line::from(format!(
                        "page: {} (n next / p previous)",
                        self.history.len() + 1
                    )),
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
        } else if self.refresh.try_send(self.page).is_ok() {
            self.pending = true;
            self.notice = "Aegis refresh pending".into();
        } else {
            self.notice = "Aegis worker unavailable".into();
        }
    }
}

pub fn observe<P: ServicePort>(client: &mut ReadOnlyClient<P>) -> Result<Observation, String> {
    observe_page(
        client,
        Request {
            grants: PageCursor::Start,
            decisions: PageCursor::Start,
        },
    )
}

fn observe_page<P: ServicePort>(
    client: &mut ReadOnlyClient<P>,
    request: Request,
) -> Result<Observation, String> {
    let status = match client.status().map_err(|_| "Aegis status unavailable")? {
        ReplyV1::Accepted(OutcomeV1::Status(value)) => value,
        ReplyV1::Refused(value) => return Err(format!("Aegis refused: {value:?}")),
        _ => return Err("Invalid Aegis status reply".into()),
    };
    let (grants, next_grants) = match request.grants {
        PageCursor::Exhausted => (Vec::new(), None),
        PageCursor::Start | PageCursor::After(_) => match client
            .grant_page(
                match request.grants {
                    PageCursor::After(after) => Some(after),
                    _ => None,
                },
                PAGE_LIMIT,
            )
            .map_err(|_| "Aegis grant page unavailable")?
        {
            ReplyV1::Accepted(OutcomeV1::GrantPage {
                entries,
                next_after,
            }) => (entries, next_after),
            ReplyV1::Refused(value) => return Err(format!("Aegis refused: {value:?}")),
            _ => return Err("Invalid Aegis grant page reply".into()),
        },
    };
    let (decisions, next_decisions) = match request.decisions {
        PageCursor::Exhausted => (Vec::new(), None),
        PageCursor::Start | PageCursor::After(_) => match client
            .decision_page(
                match request.decisions {
                    PageCursor::After(after) => Some(after),
                    _ => None,
                },
                PAGE_LIMIT,
            )
            .map_err(|_| "Aegis decision page unavailable")?
        {
            ReplyV1::Accepted(OutcomeV1::DecisionPage {
                entries,
                next_after,
            }) => (entries, next_after),
            ReplyV1::Refused(value) => return Err(format!("Aegis refused: {value:?}")),
            _ => return Err("Invalid Aegis decision page reply".into()),
        },
    };
    Ok(Observation {
        status,
        grants,
        more_grants: next_grants.is_some(),
        decisions,
        more_decisions: next_decisions.is_some(),
        next_grants,
        next_decisions,
    })
}
