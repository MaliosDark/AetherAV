use anyhow::{bail, ensure, Context, Result};
use clap::Args;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const WINDOW_US: u64 = 300_000_000;
const MAX_EVENTS: usize = 250_000;
const MAX_INPUT_LINES: usize = 1_000_000;

#[derive(Debug, Args)]
pub struct SshEventsArgs {
    /// OpenSSH events exported as journalctl -o json, one file per host or batch.
    #[arg(required = true)]
    inputs: Vec<PathBuf>,
    /// Optional Linux sshd rule using the documented JSON-formatted Sigma subset.
    #[arg(long)]
    sigma: Vec<PathBuf>,
}

#[derive(Debug)]
struct Event {
    ts: u64,
    host: String,
    user: String,
    ip: IpAddr,
    success: bool,
    message: String,
}

fn parse(value: &Value) -> Option<Event> {
    let comm = value.get("_COMM")?.as_str()?;
    if !matches!(comm, "sshd" | "sshd-session" | "sshd-auth") {
        return None;
    }
    let message = value.get("MESSAGE")?.as_str()?;
    if message.len() > 4096 {
        return None;
    }
    let (status, rest) = message.split_once(' ')?;
    if !matches!(status, "Accepted" | "Failed") {
        return None;
    }
    let (_, tail) = rest.split_once(" for ")?;
    let (user, source) = tail.split_once(" from ")?;
    let user = user.strip_prefix("invalid user ").unwrap_or(user);
    let source = source.split_whitespace().next()?.parse().ok()?;
    let host = value.get("_HOSTNAME")?.as_str()?;
    if user.is_empty()
        || user.len() > 128
        || user.chars().any(|c| c.is_whitespace() || c.is_control())
        || host.is_empty()
        || host.len() > 253
        || host.chars().any(char::is_control)
    {
        return None;
    }
    let timestamp = value.get("__REALTIME_TIMESTAMP")?;
    let ts = timestamp
        .as_u64()
        .or_else(|| timestamp.as_str()?.parse().ok())?;
    Some(Event {
        ts,
        host: host.to_owned(),
        user: user.to_owned(),
        ip: source,
        success: status == "Accepted",
        message: message.to_owned(),
    })
}

#[derive(Default)]
struct FailureWindow<'a> {
    items: VecDeque<&'a Event>,
    users: HashMap<&'a str, usize>,
    hosts: HashMap<&'a str, usize>,
    accounts: HashMap<(&'a str, &'a str), usize>,
}

fn remove_count<K: std::hash::Hash + Eq>(map: &mut HashMap<K, usize>, key: K) {
    if let std::collections::hash_map::Entry::Occupied(mut entry) = map.entry(key) {
        *entry.get_mut() -= 1;
        if *entry.get() == 0 {
            entry.remove();
        }
    }
}

impl<'a> FailureWindow<'a> {
    fn expire(&mut self, now: u64) {
        while self
            .items
            .front()
            .is_some_and(|old| now.saturating_sub(old.ts) > WINDOW_US)
        {
            let old = self.items.pop_front().expect("expired entry is present");
            remove_count(&mut self.users, old.user.as_str());
            remove_count(&mut self.hosts, old.host.as_str());
            remove_count(&mut self.accounts, (old.host.as_str(), old.user.as_str()));
        }
    }

    fn push(&mut self, event: &'a Event) {
        self.items.push_back(event);
        *self.users.entry(&event.user).or_default() += 1;
        *self.hosts.entry(&event.host).or_default() += 1;
        *self.accounts.entry((&event.host, &event.user)).or_default() += 1;
    }
}

fn correlate(events: &[Event]) -> Vec<Value> {
    let mut windows: HashMap<IpAddr, FailureWindow<'_>> = HashMap::new();
    let mut reported = HashSet::new();
    let mut alerts = Vec::new();
    for event in events {
        let window = windows.entry(event.ip).or_default();
        window.expire(event.ts);
        if event.success {
            if window.items.len() >= 6
                && window
                    .accounts
                    .contains_key(&(event.host.as_str(), event.user.as_str()))
                && reported.insert((event.ip, "ssh.login_after_failures"))
            {
                alerts.push(alert(
                    event,
                    "ssh.login_after_failures",
                    "high",
                    window.items.len(),
                ));
            }
            continue;
        }
        window.push(event);
        if window.items.len() >= 6 {
            if window.users.len() >= 3 && reported.insert((event.ip, "ssh.password_spray")) {
                alerts.push(alert(
                    event,
                    "ssh.password_spray",
                    "medium",
                    window.items.len(),
                ));
            }
            if window.hosts.len() >= 3 && reported.insert((event.ip, "ssh.multi_host_source")) {
                alerts.push(alert(
                    event,
                    "ssh.multi_host_source",
                    "medium",
                    window.items.len(),
                ));
            }
        }
    }
    alerts
}

fn alert(event: &Event, id: &str, severity: &str, failures: usize) -> Value {
    json!({"schema":"aether.security_event.v1","event_time_us":event.ts,"host":event.host,
        "source_ip":event.ip.to_string(),"target_user":event.user,"rule_id":id,
        "severity":severity,"failures_in_window":failures})
}

enum Operator {
    Equal,
    Contains,
    StartsWith,
    EndsWith,
}

struct Selector {
    field: String,
    operator: Operator,
    values: Vec<String>,
}

struct Sigma {
    id: String,
    severity: String,
    selectors: Vec<Selector>,
}

impl Sigma {
    fn load(path: &Path) -> Result<Self> {
        let mut text = String::new();
        File::open(path)?.take(65_537).read_to_string(&mut text)?;
        ensure!(text.len() <= 65_536, "Sigma rule exceeds 64 KiB");
        Self::parse(&serde_json::from_str(&text).context("expected a JSON-formatted Sigma rule")?)
    }

    fn parse(rule: &Value) -> Result<Self> {
        let string = |value: &Value, key: &str| -> Result<String> {
            value
                .get(key)
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .with_context(|| format!("missing Sigma {key}"))
        };
        let source = &rule["logsource"];
        ensure!(
            source["product"] == "linux" && source["service"] == "sshd",
            "only Linux sshd Sigma rules are supported"
        );
        let detection = rule["detection"]
            .as_object()
            .context("missing Sigma detection")?;
        let condition = string(&rule["detection"], "condition")?;
        ensure!(
            detection.len() == 2,
            "Sigma subset expects a single named selection"
        );
        let selection = detection
            .get(&condition)
            .and_then(Value::as_object)
            .context("Sigma condition must name the sole selection")?;
        ensure!(!selection.is_empty(), "empty Sigma selection");
        let mut selectors = Vec::new();
        for (key, value) in selection {
            let (field, operator) = match key.split_once('|') {
                None => (key.as_str(), Operator::Equal),
                Some((name, "contains")) => (name, Operator::Contains),
                Some((name, "startswith")) => (name, Operator::StartsWith),
                Some((name, "endswith")) => (name, Operator::EndsWith),
                _ => bail!("unsupported Sigma field modifier"),
            };
            ensure!(
                matches!(
                    field,
                    "Message" | "TargetUser" | "SourceIp" | "Hostname" | "Outcome"
                ),
                "unsupported Sigma field"
            );
            let items: Vec<&Value> = value
                .as_array()
                .map_or_else(|| vec![value], |v| v.iter().collect());
            ensure!(!items.is_empty(), "empty Sigma string list");
            let values = items
                .into_iter()
                .map(|item| -> Result<String> {
                    let s = item
                        .as_str()
                        .context("Sigma subset only supports string values")?;
                    ensure!(
                        !s.is_empty() && !s.contains(['*', '?', '\\']),
                        "unsupported Sigma wildcard or empty value"
                    );
                    Ok(s.to_ascii_lowercase())
                })
                .collect::<Result<_>>()?;
            selectors.push(Selector {
                field: field.to_owned(),
                operator,
                values,
            });
        }
        let severity = string(rule, "level")?;
        ensure!(
            matches!(
                severity.as_str(),
                "informational" | "low" | "medium" | "high" | "critical"
            ),
            "invalid Sigma severity"
        );
        Ok(Self {
            id: string(rule, "id")?,
            severity,
            selectors,
        })
    }

    fn matches(&self, event: &Event) -> bool {
        let ip = event.ip.to_string();
        self.selectors.iter().all(|selector| {
            let field = match selector.field.as_str() {
                "Message" => &event.message,
                "TargetUser" => &event.user,
                "SourceIp" => &ip,
                "Hostname" => &event.host,
                "Outcome" if event.success => "success",
                "Outcome" => "failure",
                _ => return false,
            }
            .to_ascii_lowercase();
            selector.values.iter().any(|value| match selector.operator {
                Operator::Equal => field == *value,
                Operator::Contains => field.contains(value),
                Operator::StartsWith => field.starts_with(value),
                Operator::EndsWith => field.ends_with(value),
            })
        })
    }
}

pub fn run(args: SshEventsArgs) -> Result<ExitCode> {
    let rules = args
        .sigma
        .iter()
        .map(|path| Sigma::load(path).with_context(|| format!("loading {}", path.display())))
        .collect::<Result<Vec<_>>>()?;
    let mut events = Vec::new();
    let mut repeated = HashSet::new();
    let mut lines = 0;
    let mut batch_bytes = 0;
    for path in args.inputs {
        let mut input = BufReader::new(
            File::open(&path).with_context(|| format!("opening {}", path.display()))?,
        );
        let mut line = String::new();
        let mut number = 0;
        loop {
            line.clear();
            if input.by_ref().take(65_537).read_line(&mut line)? == 0 {
                break;
            }
            number += 1;
            lines += 1;
            batch_bytes += line.len();
            ensure!(
                batch_bytes <= 512 * 1024 * 1024,
                "journal batch exceeds 512 MiB"
            );
            ensure!(
                lines <= MAX_INPUT_LINES,
                "batch exceeds the journal line limit"
            );
            ensure!(
                line.len() <= 65_536,
                "{}:{number} exceeds the journal line limit",
                path.display()
            );
            let value: Value = serde_json::from_str(&line)
                .with_context(|| format!("{}:{number}", path.display()))?;
            if let Some(event) = parse(&value) {
                if let Some(cursor) = value.get("__CURSOR").and_then(Value::as_str) {
                    if !repeated.insert((event.host.clone(), cursor.to_owned())) {
                        continue;
                    }
                }
                ensure!(
                    events.len() < MAX_EVENTS,
                    "batch exceeds the accepted SSH event limit"
                );
                events.push(event);
            }
        }
    }
    events.sort_by_key(|e| e.ts);
    for finding in correlate(&events) {
        println!("{finding}");
    }
    for event in &events {
        for rule in &rules {
            if rule.matches(event) {
                println!("{}", alert(event, &rule.id, &rule.severity, 0));
            }
        }
    }
    tracing::info!(
        accepted = events.len(),
        lines,
        "SSH journal correlation complete"
    );
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correlates_multi_host_spray_and_login() {
        let mut events = Vec::new();
        for i in 0..7 {
            let state = if i == 6 { "Accepted" } else { "Failed" };
            let value = json!({"_COMM":"sshd-session","_HOSTNAME":format!("h{}",i%3),
                "__REALTIME_TIMESTAMP":(i*1_000_000).to_string(),
                "MESSAGE":format!("{state} password for user{} from 2001:db8::25 port 2222 ssh2",i%3)});
            events.push(parse(&value).unwrap());
        }
        assert_eq!(correlate(&events).len(), 3);
        events[6].ts = WINDOW_US + 6_000_000;
        assert_eq!(correlate(&events).len(), 2);
    }

    #[test]
    fn sigma_subset_checks_all_fields_and_rejects_unsupported_conditions() {
        let mut rule = json!({"id":"test","logsource":{"product":"linux","service":"sshd"},"level":"high",
            "detection":{"condition":"detect","detect":{"Outcome":"success","TargetUser":["root","admin"],"Message|startswith":"Accepted"}}});
        let record = json!({"_COMM":"sshd","_HOSTNAME":"h","__REALTIME_TIMESTAMP":"1",
            "MESSAGE":"Accepted publickey for root from 192.0.2.15 port 9000 ssh2"});
        assert!(Sigma::parse(&rule)
            .unwrap()
            .matches(&parse(&record).unwrap()));
        rule["detection"]["condition"] = json!("detect or other");
        assert!(Sigma::parse(&rule).is_err());
    }
}
