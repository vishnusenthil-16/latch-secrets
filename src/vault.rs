use anyhow::{Result, bail, ensure};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use zeroize::Zeroizing;

pub(crate) struct Binding {
    pub name: String,
    pub id: String,
    pub field: String,
}
pub(crate) fn parse_bindings(values: &[String]) -> Result<Vec<Binding>> {
    let mut seen = HashSet::new();
    values
        .iter()
        .map(|raw| {
            let (name, reference) = raw
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("expected NAME=ITEM_UUID/FIELD"))?;
            ensure!(
                valid_name(name)
                    && !name.starts_with("BW_")
                    && !name.starts_with("BITWARDENCLI_")
                    && !name.starts_with("LATCH_"),
                "invalid or reserved environment variable name"
            );
            ensure!(seen.insert(name), "duplicate environment variable mapping");
            let (id, field) = reference
                .split_once('/')
                .ok_or_else(|| anyhow::anyhow!("expected item UUID and field"))?;
            let id = uuid::Uuid::parse_str(id)
                .map_err(|_| anyhow::anyhow!("item reference must be a UUID"))?
                .hyphenated()
                .to_string();
            ensure!(
                matches!(field, "login.username" | "login.password")
                    || field
                        .strip_prefix("custom.")
                        .is_some_and(|name| !name.is_empty()),
                "supported fields: login.username, login.password, custom.NAME"
            );
            Ok(Binding {
                name: name.to_owned(),
                id,
                field: field.to_owned(),
            })
        })
        .collect()
}
pub(crate) fn valid_name(name: &str) -> bool {
    let mut chars = name.bytes();
    chars
        .next()
        .is_some_and(|c| c == b'_' || c.is_ascii_alphabetic())
        && chars.all(|c| c == b'_' || c.is_ascii_alphanumeric())
}
pub(crate) fn metadata(items: &Value, search: Option<&str>) -> Result<Value> {
    let items = items
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("bw returned invalid item list"))?;
    let query = search.map(str::to_lowercase);
    let mut output = Vec::new();
    for item in items {
        let name = item["name"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("item has invalid metadata"))?;
        if query
            .as_ref()
            .is_some_and(|q| !name.to_lowercase().contains(q))
        {
            continue;
        }
        let id = item["id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("item has invalid metadata"))?;
        let kind = item["type"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("item has invalid metadata"))?;
        ensure!(
            item["organizationId"].is_null() || item["organizationId"].is_string(),
            "invalid organization metadata"
        );
        ensure!(
            item["collectionIds"].is_null()
                || item["collectionIds"]
                    .as_array()
                    .is_some_and(|ids| ids.iter().all(Value::is_string)),
            "invalid collection metadata"
        );
        output.push(json!({"id":id,"name":name,"type":kind,"organizationId":item["organizationId"],"collectionIds":item["collectionIds"]}));
    }
    Ok(json!(output))
}
pub(crate) fn resolve(
    bindings: &[Binding],
    mut fetch: impl FnMut(&str) -> Result<String>,
) -> Result<Vec<(String, String)>> {
    let mut cache = HashMap::new();
    let mut output = Vec::new();
    for binding in bindings {
        if !cache.contains_key(&binding.id) {
            let raw = Zeroizing::new(fetch(&binding.id)?);
            let item: Value = serde_json::from_str(&raw)
                .map_err(|_| anyhow::anyhow!("bw returned invalid item data"))?;
            ensure!(
                item["id"] == binding.id,
                "bw returned a different item than requested"
            );
            cache.insert(binding.id.clone(), item);
        }
        let item = &cache[&binding.id];
        let value = if let Some(field) = binding.field.strip_prefix("login.") {
            item["login"][field]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("requested login field is missing"))?
        } else {
            let name = binding
                .field
                .strip_prefix("custom.")
                .expect("validated field");
            let fields = item["fields"]
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("custom field is missing"))?;
            let mut matching = fields.iter().filter(|f| f["name"] == name);
            let field = matching
                .next()
                .ok_or_else(|| anyhow::anyhow!("custom field is missing"))?;
            ensure!(matching.next().is_none(), "custom field name is ambiguous");
            ensure!(
                matches!(field["type"].as_u64(), Some(0 | 1)),
                "only text and hidden custom fields are supported"
            );
            field["value"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("custom field has no text value"))?
        };
        if value.contains('\0') {
            bail!("secret contains NUL and cannot be injected");
        }
        output.push((binding.name.clone(), value.to_owned()));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    const ID: &str = "00000000-0000-4000-8000-000000000001";
    #[test]
    fn metadata_never_includes_other_fields() {
        let out = metadata(&json!([{"id":ID,"name":"service","type":1,"login":{"password":"CANARY"},"notes":"CANARY","fields":[{"value":"CANARY"}]}]), None).unwrap();
        assert!(!out.to_string().contains("CANARY"));
        assert_eq!(out[0].as_object().unwrap().len(), 5);
    }
    #[test]
    fn exact_fields_cached_and_ambiguity_rejected() {
        let bindings = parse_bindings(&[
            format!("A={ID}/login.password"),
            format!("B={ID}/custom.token"),
        ])
        .unwrap();
        let mut calls = 0;
        let values=resolve(&bindings, |_| { calls+=1; Ok(json!({"id":ID,"login":{"password":"p"},"fields":[{"name":"token","type":1,"value":"t"}]}).to_string()) }).unwrap();
        assert_eq!(calls, 1);
        assert_eq!(values[1].1, "t");
        assert!(resolve(&bindings, |_| Ok(json!({"id":ID,"login":{"password":"p"},"fields":[{"name":"token","type":1,"value":"t"},{"name":"token","type":1,"value":"u"}]}).to_string())).is_err());
    }
    #[test]
    fn reject_invalid_and_duplicate_bindings() {
        for mappings in [
            vec![format!("BW_SESSION={ID}/login.password")],
            vec![format!("A={ID}/login.password"); 2],
            vec!["A=ambiguous-name/login.password".into()],
        ] {
            assert!(parse_bindings(&mappings).is_err());
        }
    }
}
