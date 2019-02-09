use std::collections::HashMap;
use std::fmt;

fn main() -> Result<(), std::io::Error> {
    let mut controller = Controller {
        callbacks: HashMap::new(),
        sessions: HashMap::new(),
    };

    controller.add_callback("link-connect", link_connect_cb);
    controller.add_callback("link-identify", link_identify_cb);
    controller.add_callback("tx-begin", tx_begin_cb);
    controller.add_callback("tx-mail", tx_mail_cb);
    controller.add_callback("tx-rcpt", tx_rcpt_cb);
    controller.add_callback("tx-data", tx_data_cb);
    controller.add_callback("tx-commit", tx_cleanup_cb);
    controller.add_callback("tx-rollback", tx_cleanup_cb);

    controller.add_callback("commit", filter_commit_cb);
    controller.add_callback("data-line", filter_data_cb);

    controller.add_callback("link-disconnect", |ctrl, _, _, id, _| {
        ctrl.sessions.remove(&id);
    });

    loop {
        let mut buffer = String::new();
        std::io::stdin().read_line(&mut buffer)?;
        let event = parse_event(buffer);
        dbg!(&event);
        controller.run_event_callback(event);
        dbg!(&controller);
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
        session_id: id.clone(),
        ..Default::default()
    };
    ses.control.insert("pass", String::from("all"));
    if let Some(args) = args {
        let rdns = &args[0];
        let laddr: Vec<&str> = args[2].split(":").collect();
        if laddr[0] != "local" {
            ses.control.insert("ip", laddr[0].into());
        }
        if !rdns.is_empty() {
            ses.control.insert("hostname", rdns.to_string());
        }
    }
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
            match ses.add_data_line(line) {
                Data::Complete => {
                    let json = ses.submit_to_rspamd();
                }
                _ => return,
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

fn parse_event(b: String) -> Event {
    let mut fields: Vec<&str> = b.trim().split('|').collect();
    let kind = fields[0];
    match kind {
        "report" => Event {
            kind: kind.into(),
            version: fields[1].into(),
            timestamp: fields[2].into(),
            subsystem: fields[3].into(),
            event: fields[4].into(),
            session_id: fields[5].into(),
            data: None,
            token: None,
        },
        "filter" => {
            let mut e = Event {
                kind: kind.into(),
                version: fields[1].into(),
                timestamp: fields[2].into(),
                subsystem: fields[3].into(),
                event: fields[4].into(),
                token: Some(fields[5].into()),
                session_id: fields[6].into(),
                data: None,
            };
            if fields.len() > 7 {
                e.data = Some(fields.drain(7..).map(String::from).collect());
            }
            e
        }
        _ => unreachable!(),
    }
}

struct Controller<'a> {
    callbacks: HashMap<
        &'a str,
        Box<fn(&mut Controller, String, Option<String>, String, Option<Vec<String>>)>,
    >,
    sessions: HashMap<String, Session<'a>>,
}

impl<'a> fmt::Debug for Controller<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Controller: Current sessions: {:?}", self.sessions)
    }
}

impl<'a> Controller<'a> {
    fn add_callback(
        &mut self,
        name: &'a str,
        f: fn(&mut Controller, String, Option<String>, String, Option<Vec<String>>),
    ) {
        self.callbacks.insert(name, Box::new(f));
    }

    fn run_event_callback(&mut self, event: Event) {
        let name: &str = event.event.as_ref();
        dbg!(name);
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

#[derive(Debug, Default)]
struct Session<'b> {
    control: HashMap<&'b str, String>,
    session_id: String,
    payload: Vec<String>,
    reason: String,
}

impl<'b> Session<'b> {
    pub fn add_data_line(&mut self, line: &str) -> Data {
        match line {
            "." => Data::Complete,
            _ => {
                self.payload.push(line.into());
                Data::Ongoing
            }
        }
    }

    fn submit_to_rspamd(&self) -> Result<Rspam, std::io::Error> {
        let mut headers = reqwest::header::HeaderMap::new();
        for (k, v) in self.control.iter() {
            let name = reqwest::header::HeaderName::from_bytes(k.as_bytes()).unwrap();
            headers.insert(name, v.parse().unwrap());
        }
        let raw = self.payload.join("\n");
        let message = email::MimeMessage::parse(&raw).unwrap().as_string();
        dbg!(&headers);
        dbg!(&message);
        let client = reqwest::Client::new();
        client
            .post("http://localhost:11333/checkv2")
            .headers(headers)
            .body(message)
            .send()
            .unwrap()
            .json()
            .unwrap()
    }
}

#[derive(Deserialize)]
struct Rspam {}

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
