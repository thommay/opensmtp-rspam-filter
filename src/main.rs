use email::Header;
use serde::de::Error;
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use slog::{debug, info, o, Drain};
use slog_syslog::Facility;
use std::collections::HashMap;
use std::error::Error as StdError;
use std::fmt;

type BoxResult<T> = Result<T, Box<StdError>>;

fn main() -> BoxResult<()> {
    let drain = slog_syslog::unix_3164(Facility::LOG_MAIL)?.fuse();
    // let decorator = slog_term::TermDecorator::new().build();
    // let drain = slog_term::CompactFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    let _log = slog::Logger::root(drain, o!());

    let mut controller = Controller {
        callbacks: HashMap::new(),
        sessions: HashMap::new(),
        logger: _log.new(o!("module"=>"controller")),
    };

    controller.add_callback(Register::Report, "link-connect", link_connect_cb);
    controller.add_callback(Register::Report, "link-identify", link_identify_cb);
    controller.add_callback(Register::Report, "tx-begin", tx_begin_cb);
    controller.add_callback(Register::Report, "tx-mail", tx_mail_cb);
    controller.add_callback(Register::Report, "tx-rcpt", tx_rcpt_cb);
    controller.add_callback(Register::Report, "tx-data", tx_data_cb);
    controller.add_callback(Register::Report, "tx-commit", tx_cleanup_cb);
    controller.add_callback(Register::Report, "tx-rollback", tx_cleanup_cb);

    controller.add_callback(Register::Filter, "commit", filter_commit_cb);
    controller.add_callback(Register::Filter, "data-line", filter_data_cb);

    controller.add_callback(Register::Report, "link-disconnect", |ctrl, _, _, id, _| {
        ctrl.sessions.remove(&id);
        debug!(
            ctrl.logger,
            "Currently tracking {} sessions",
            ctrl.sessions.len()
        );
    });

    println!("register|ready");
    info!(_log, "opensmtp rspam filter ready to start");
    loop {
        let mut buffer = String::new();
        std::io::stdin()
            .read_line(&mut buffer)
            .expect("Failed to read line");
        for line in buffer.split_terminator("\n") {
            let event = parse_event(line.into());
            if let Ok(e) = event {
                controller.run_event_callback(e);
            } else {
                info!(_log, "unrecognised event");
            }
        }
    }
}

fn tx_begin_cb(
    ctrl: &mut Controller,
    _: String,
    _: Option<String>,
    id: String,
    args: Option<Vec<String>>,
) {
    if let Some(args) = args {
        let tx_id = &args[0];
        if let Some(ses) = ctrl.sessions.get_mut(&id) {
            ses.control.insert("queue-id", tx_id.to_string());
        }
    }
}

fn tx_cleanup_cb(
    ctrl: &mut Controller,
    _: String,
    _: Option<String>,
    id: String,
    _: Option<Vec<String>>,
) {
    debug!(ctrl.logger, "Starting new session: {}", id);
    if let Some(ses) = ctrl.sessions.get_mut(&id) {
        ses.control = HashMap::new();
    }
}

fn tx_mail_cb(
    ctrl: &mut Controller,
    _: String,
    _: Option<String>,
    id: String,
    args: Option<Vec<String>>,
) {
    if let Some(args) = args {
        let from = &args[1];
        let status = &args[2];
        if status == "ok" {
            if let Some(ses) = ctrl.sessions.get_mut(&id) {
                ses.control.insert("from", from.to_string());
            }
        }
    }
}

fn tx_rcpt_cb(
    ctrl: &mut Controller,
    _: String,
    _: Option<String>,
    id: String,
    args: Option<Vec<String>>,
) {
    if let Some(args) = args {
        let rcpt = &args[1];
        let status = &args[2];
        if status == "ok" {
            if let Some(ses) = ctrl.sessions.get_mut(&id) {
                ses.control.insert("rcpt", rcpt.to_string());
            }
        }
    }
}

fn tx_data_cb(
    ctrl: &mut Controller,
    _: String,
    _: Option<String>,
    id: String,
    args: Option<Vec<String>>,
) {
    if let Some(args) = args {
        let status = &args[1];
        if status == "ok" {
            if let Some(ses) = ctrl.sessions.get_mut(&id) {
                ses.payload = vec![];
            }
        }
    }
}

fn link_identify_cb(
    ctrl: &mut Controller,
    _: String,
    _: Option<String>,
    id: String,
    args: Option<Vec<String>>,
) {
    if let Some(args) = args {
        let helo = &args[0];
        if let Some(ses) = ctrl.sessions.get_mut(&id) {
            ses.control.insert("helo", helo.to_string());
        }
    }
}

fn link_connect_cb(
    ctrl: &mut Controller,
    _: String,
    _: Option<String>,
    id: String,
    args: Option<Vec<String>>,
) {
    let mut ses = Session {
        control: HashMap::new(),
        session_id: id.clone(),
        payload: vec![],
        reason: String::new(),
        logger: ctrl.logger.new(o!("module"=>"session", "id"=>id.clone())),
    };
    ses.control.insert("pass", String::from("all"));
    if let Some(args) = args {
        let rdns = &args[0];
        let laddr: Vec<&str> = args[2].split(":").collect();
        if laddr[0] != "local" {
            if laddr[0] == "IPv6" {
                if let Some((_, elements)) = laddr.split_first() {
                    if let Some((_, addr)) = elements.split_last() {
                        ses.control.insert("ip", addr.join(":"));
                    }
                }
            } else {
                ses.control.insert("ip", laddr[0].into());
            }
        }
        if !rdns.is_empty() {
            ses.control.insert("hostname", rdns.to_string());
        }
    }
    debug!(
        ctrl.logger,
        "Creating fresh session {:?} with id: {}", ses, id
    );
    ctrl.sessions.insert(id, ses);
}

fn filter_data_cb(
    ctrl: &mut Controller,
    _: String,
    token: Option<String>,
    id: String,
    args: Option<Vec<String>>,
) {
    if let Some(args) = args {
        let line = &args[0];
        if let Some(ses) = ctrl.sessions.get_mut(&id) {
            match ses.add_data_line(line).expect("Failed to add line") {
                Data::Complete => {
                    debug!(ctrl.logger, "submitting {} to RSpamd", id);
                    match ses.submit_to_rspamd() {
                        Ok(json) => {
                            debug!(ctrl.logger, "Got response {:?} from rspam", &json);
                            ses.respond(json, &token.unwrap())
                                .expect("Failed to deal with response from RSpam");
                        }
                        Err(e) => info!(ctrl.logger, "Failed to submit to rspamd: {:?}", e),
                    }
                }
                _ => {
                    return;
                }
            }
        }
    }
}

fn filter_commit_cb(
    ctrl: &mut Controller,
    _: String,
    token: Option<String>,
    id: String,
    _: Option<Vec<String>>,
) {
    if let Some(ses) = ctrl.sessions.get_mut(&id) {
        if !ses.reason.is_empty() {
            let reason = &ses.reason;
            reject(token, id, reason.to_string());
        } else {
            proceed(token, id);
        }
    }
}

fn reject(tok: Option<String>, id: String, res: String) {
    println!(
        "filter-result|{}|{}|reject|{}",
        tok.expect("Failed to extract token"),
        id,
        res,
    )
}

fn proceed(tok: Option<String>, id: String) {
    println!(
        "filter-result|{}|{}|proceed",
        tok.expect("Failed to extract token"),
        id,
    )
}

fn dataline(token: &str, id: &str, line: &str) {
    println!("filter-dataline|{}|{}|{}", token, id, line)
}

fn parse_event(b: String) -> BoxResult<Event> {
    let mut fields: Vec<&str> = b.trim().split('|').collect();
    let kind = fields[0];
    match kind {
        "report" => Ok(Event {
            kind: kind.into(),
            version: fields[1].into(),
            timestamp: fields[2].into(),
            subsystem: fields[3].into(),
            event: fields[4].into(),
            session_id: fields[5].into(),
            data: None,
            token: None,
        }),
        "filter" => {
            let mut e = Event {
                kind: kind.into(),
                version: fields[1].into(),
                timestamp: fields[2].into(),
                subsystem: fields[3].into(),
                event: fields[4].into(),
                session_id: fields[5].into(),
                token: Some(fields[6].into()),
                data: None,
            };
            if fields.len() > 7 {
                e.data = Some(fields.drain(7..).map(String::from).collect());
            }
            Ok(e)
        }
        _ => Err(std::io::Error::new(std::io::ErrorKind::Other, "unrecognised event").into()),
    }
}

struct Controller<'a> {
    callbacks: HashMap<
        &'a str,
        Box<fn(&mut Controller, String, Option<String>, String, Option<Vec<String>>)>,
    >,
    sessions: HashMap<String, Session<'a>>,
    logger: slog::Logger,
}

impl<'a> fmt::Debug for Controller<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Controller: Current sessions: {:?}", self.sessions)
    }
}

impl<'a> Controller<'a> {
    fn add_callback(
        &mut self,
        event: Register,
        name: &'a str,
        f: fn(&mut Controller, String, Option<String>, String, Option<Vec<String>>),
    ) {
        match event {
            Register::Event => println!("register|report|smtp-in|*"),
            Register::Report => println!("register|report|smtp-in|{}", name),
            Register::Filter => println!("register|filter|smtp-in|{}", name),
        }
        self.callbacks.insert(name, Box::new(f));
    }

    fn run_event_callback(&mut self, event: Event) {
        let name: &str = event.event.as_ref();
        if let Some(c) = self.callbacks.get(name) {
            c(
                self,
                event.timestamp,
                event.token,
                event.session_id,
                event.data,
            );
        }
    }
}

#[derive(Debug)]
struct Session<'b> {
    control: HashMap<&'b str, String>,
    session_id: String,
    payload: Vec<String>,
    reason: String,
    logger: slog::Logger,
}

impl<'b> Session<'b> {
    pub fn add_data_line(&mut self, line: &str) -> BoxResult<Data> {
        match line {
            "." => Ok(Data::Complete),
            _ => {
                self.payload.push(line.into());
                Ok(Data::Ongoing)
            }
        }
    }

    fn parse_message(&self) -> BoxResult<email::MimeMessage> {
        let raw = self.payload.join("\n");
        debug!(self.logger, "Parsing {:?}", &raw);
        let message = email::MimeMessage::parse(&raw)?;
        Ok(message)
    }

    fn submit_to_rspamd(&self) -> BoxResult<Rspam> {
        let mut headers = reqwest::header::HeaderMap::new();
        debug!(self.logger, "Setting headers");
        for (k, v) in self.control.iter() {
            let name = reqwest::header::HeaderName::from_bytes(k.as_bytes())?;
            headers.insert(name, v.parse()?);
        }
        debug!(self.logger, "Parsing message");
        let message = self.parse_message()?;
        debug!(self.logger, "Creating http client");
        let client = reqwest::Client::new();
        debug!(self.logger, "Ready to submit to RSpamd");
        let result = client
            .post("http://localhost:11333/checkv2")
            .headers(headers)
            .body(message.as_string())
            .send()?
            .json()?;
        debug!(self.logger, "Succesfully submitted to RSpamd");
        Ok(result)
    }

    fn respond(&mut self, json: Rspam, token: &str) -> BoxResult<()> {
        let mut message = self.parse_message()?;
        match json.action {
            RspamActions::Greylist => {
                self.reason = String::from("421 greylisted");
                message.headers.insert(Header::new(
                    "X-Spam-Action".into(),
                    String::from("greylist"),
                ));
            }
            RspamActions::AddHeader => {
                message
                    .headers
                    .insert(Header::new("X-Spam".into(), String::from("yes")));
                message.headers.insert(Header::new(
                    "X-Spam-Action".into(),
                    String::from("add header"),
                ));
            }
            RspamActions::Rewrite => {
                message.headers.insert(Header::new(
                    "X-Spam-Action".into(),
                    String::from("rewrite subject"),
                ));
                if let Some(subj) = json.subject {
                    message.headers.insert(Header::new("Subject".into(), subj));
                }
            }
            RspamActions::SoftReject => {
                message.headers.insert(Header::new(
                    "X-Spam-Action".into(),
                    String::from("soft reject"),
                ));
                self.reason = String::from("451 try again later");
            }
            RspamActions::Reject => {
                message
                    .headers
                    .insert(Header::new("X-Spam-Action".into(), String::from("reject")));
                self.reason = String::from("550 message rejected");
            }
            _ => message.headers.insert(Header::new(
                "X-Spam-Action".into(),
                String::from("no action"),
            )),
        }
        message.headers.insert(Header::new(
            "X-Spam-Score".into(),
            format!("{} / {}", json.score, json.required_score),
        ));
        let id = &self.session_id;
        for line in message.as_string().split("\n") {
            dataline(token, id, line);
        }
        dataline(token, id, ".");
        Ok(())
    }
}

#[derive(Deserialize, Debug)]
struct Rspam {
    #[serde(rename = "is_skipped")]
    skipped: bool,
    score: f32,
    required_score: f32,
    #[serde(deserialize_with = "deserialize_action")]
    action: RspamActions,
    symbols: Option<Value>,
    urls: Option<Vec<String>>,
    emails: Option<Vec<String>>,
    #[serde(rename = "message-id")]
    message_id: Option<Value>,
    subject: Option<String>,
}

fn deserialize_action<'de, D>(deserializer: D) -> Result<RspamActions, D::Error>
where
    D: Deserializer<'de>,
{
    let act = String::deserialize(deserializer)?;
    match act.as_ref() {
        "no action" => Ok(RspamActions::None),
        "greylist" => Ok(RspamActions::Greylist),
        "add header" => Ok(RspamActions::AddHeader),
        "rewrite subject" => Ok(RspamActions::Rewrite),
        "soft reject" => Ok(RspamActions::SoftReject),
        "reject" => Ok(RspamActions::Reject),
        _ => Err(D::Error::custom("got unexpected action")),
    }
}

#[derive(Debug, Default)]
struct Event {
    kind: String,
    version: String,
    pub timestamp: String,
    pub subsystem: String,
    pub event: String,
    pub token: Option<String>,
    pub session_id: String,
    pub data: Option<Vec<String>>,
}

enum Data {
    Complete,
    Ongoing,
}

#[derive(Debug)]
enum RspamActions {
    None,       // message is likely ham
    Greylist,   // message should be greylisted
    AddHeader,  // message is suspicious and should be marked as spam
    Rewrite,    // message is suspicious and should have subject rewritten
    SoftReject, // message should be temporary rejected (for example, due to rate limit exhausting)
    Reject,     //message should be rejected as spam
}

enum Register {
    Filter,
    Report,
    Event,
}
