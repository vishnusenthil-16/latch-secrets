use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::{
    io::Write,
    process::{Command, Stdio},
};
use zeroize::Zeroizing;

pub(crate) fn validate(endpoint: &str, target: &str, selector: &str) -> Result<()> {
    let u = url::Url::parse(endpoint).map_err(|_| anyhow::anyhow!("invalid CDP endpoint"))?;
    ensure!(
        u.scheme() == "ws"
            && matches!(u.host_str(), Some("127.0.0.1" | "[::1]"))
            && u.username().is_empty()
            && u.password().is_none()
            && u.query().is_none()
            && u.fragment().is_none()
            && u.path().starts_with("/devtools/browser/"),
        "use a loopback browser WebSocket endpoint"
    );
    ensure!(
        !target.is_empty() && target.len() <= 128 && !selector.is_empty() && selector.len() <= 4096,
        "invalid browser target or selector"
    );
    Ok(())
}

// Fail closed on unsupported matching modes rather than weakening path restrictions.
pub(crate) fn rules(raw: &str, id: &str) -> Result<Vec<Value>> {
    let item: Value =
        serde_json::from_str(raw).map_err(|_| anyhow::anyhow!("invalid vault item"))?;
    ensure!(
        item["id"] == id
            && item["type"] == 1
            && item["deletedDate"].is_null()
            && item["archivedDate"].is_null(),
        "browser fill requires an active login item"
    );
    ensure!(
        item["reprompt"].as_u64() == Some(0),
        "browser fill requires explicit reprompt=0"
    );
    let uris = item["login"]["uris"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("item has no destination policy"))?;
    let mut rules = Vec::new();
    for entry in uris {
        // Only explicit base-domain, host and exact modes. Null inherits an unknown
        // account default; regex, prefix and never are intentionally unsupported.
        let mode = match entry["match"].as_u64() {
            Some(n @ (0 | 1 | 3)) => n,
            _ => continue,
        };
        let Some(uri) = entry["uri"].as_str() else {
            continue;
        };
        let Ok(u) = url::Url::parse(uri) else {
            continue;
        };
        if u.scheme() != "https" || !u.username().is_empty() || u.password().is_some() {
            continue;
        }
        // Exact matching must not silently normalize away path/query restrictions.
        rules.push(json!({"origin":u.origin().ascii_serialization(), "exact":if mode == 3 {Some(uri)} else {None}}));
    }
    ensure!(
        !rules.is_empty(),
        "no supported HTTPS vault URI; set an explicit host, base-domain or exact match"
    );
    Ok(rules)
}

pub(crate) fn payload(
    raw: &str,
    id: &str,
    endpoint: &str,
    target: &str,
    selector: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let rules = rules(raw, id)?;
    let item: Value =
        serde_json::from_str(raw).map_err(|_| anyhow::anyhow!("invalid vault item"))?;
    let password = item["login"]["password"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("login password missing"))?;
    let bytes = Zeroizing::new(serde_json::to_vec(
        &json!({"endpoint":endpoint,"target":target,"selector":selector,"rules":rules,"value":password}),
    )?);
    ensure!(bytes.len() <= 1024 * 1024, "browser input too large");
    Ok(bytes)
}

pub(crate) fn deliver(payload: &[u8]) -> Result<()> {
    let mut command = Command::new("node");
    let driver = format!(
        "{}\n{}",
        include_str!("../browser/extension/fill.js").trim_start_matches("export "),
        include_str!("../browser/driver.mjs")
    );
    command.args(["--input-type=module", "--eval", &driver]);
    command.env_clear();
    if let Some(path) = std::env::var_os("PATH") {
        command.env("PATH", path);
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = command
        .spawn()
        .map_err(|_| anyhow::anyhow!("browser fill requires Node.js 22.4+ on PATH"))?;
    let written = child.stdin.take().expect("piped stdin").write_all(payload);
    if written.is_err() {
        let _ = child.kill();
    }
    let status = child
        .wait()
        .map_err(|_| anyhow::anyhow!("browser outcome unknown; do not retry automatically"))?;
    match status.code() {
        Some(0) if written.is_ok() => Ok(()),
        Some(10) => anyhow::bail!("browser target or destination rejected; no fill performed"),
        _ => anyhow::bail!("browser outcome unknown; inspect the page before retrying"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn item() -> Value {
        json!({"id":"id","type":1,"reprompt":0,"login":{"password":"CANARY","uris":[{"uri":"https://example.test/login?a=1","match":3}]}})
    }
    #[test]
    fn policy_and_reprompt_fail_closed() {
        let run = |v: Value| payload(&v.to_string(), "id", "endpoint", "target", "#p");
        let p: Value = serde_json::from_slice(&run(item()).unwrap()).unwrap();
        assert_eq!(p["rules"][0]["exact"], "https://example.test/login?a=1");
        for mode in [json!(null), json!(2), json!(4), json!(5), json!(9)] {
            let mut v = item();
            v["login"]["uris"][0]["match"] = mode;
            assert!(run(v).is_err());
        }
        for (key, value) in [
            ("reprompt", json!(1)),
            ("reprompt", json!(null)),
            ("type", json!(2)),
            ("deletedDate", json!("date")),
            ("archivedDate", json!("date")),
            ("id", json!("other")),
        ] {
            let mut v = item();
            v[key] = value;
            assert!(run(v).is_err());
        }
        for uri in [
            "http://example.test",
            "https://user:pass@example.test",
            "not-url",
        ] {
            let mut v = item();
            v["login"]["uris"][0]["uri"] = json!(uri);
            assert!(run(v).is_err());
        }
    }
    #[test]
    fn endpoint_restrictions() {
        assert!(validate("ws://127.0.0.1:9222/devtools/browser/id", "target", "#p").is_ok());
        for endpoint in [
            "http://127.0.0.1:9222",
            "ws://example.test/devtools/browser/id",
            "ws://localhost/devtools/browser/id",
            "ws://127.0.0.1/devtools/page/id",
            "ws://user@127.0.0.1/devtools/browser/id",
        ] {
            assert!(validate(endpoint, "target", "#p").is_err());
        }
    }
}
