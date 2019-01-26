fn main() -> Result<(), std::io::Error> {
    loop {
        let mut buffer = String::new();
        std::io::stdin().read_line(&mut buffer)?;
        let event = parse_event(buffer);
        dbg!(event);
    }
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
