//! Strict stdin-only login mutations. Rotation changes vault storage, not providers.
use crate::bw::Bw;
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::HashSet,
    io::{IsTerminal, Read},
};
use zeroize::Zeroizing;

pub(crate) const INPUT_LIMIT: usize = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Input {
    #[serde(default, deserialize_with = "present")]
    name: Option<String>,
    #[serde(default, deserialize_with = "present")]
    login: Option<Login>,
    #[serde(default, deserialize_with = "present")]
    fields: Option<Vec<Field>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Login {
    #[serde(default, deserialize_with = "present")]
    username: Option<String>,
    #[serde(default, deserialize_with = "present")]
    password: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Field {
    name: String,
    value: String,
    #[serde(default, deserialize_with = "present")]
    r#type: Option<FieldType>,
}
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum FieldType {
    Text,
    Hidden,
}
impl FieldType {
    fn number(self) -> u64 {
        match self {
            Self::Text => 0,
            Self::Hidden => 1,
        }
    }
}
fn present<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

pub(crate) fn read_stdin(create: bool) -> Result<Input> {
    ensure!(
        !std::io::stdin().is_terminal(),
        "mutation input requires piped or redirected JSON stdin; never put credentials in arguments"
    );
    let mut raw = Zeroizing::new(Vec::new());
    std::io::stdin()
        .take(INPUT_LIMIT as u64 + 1)
        .read_to_end(&mut raw)
        .context("cannot read mutation stdin")?;
    parse(&raw, create)
}
fn parse(raw: &[u8], create: bool) -> Result<Input> {
    ensure!(
        raw.len() <= INPUT_LIMIT,
        "mutation input exceeds 1 MiB limit"
    );
    // Never display serde errors: they can contain supplied secret values/keys.
    let input: Input = serde_json::from_slice(raw).map_err(|_| {
        anyhow::anyhow!("invalid mutation JSON; see latch capabilities for the strict input schema")
    })?;
    ensure!(!create || input.name.is_some(), "create requires a name");
    if let Some(name) = &input.name {
        ensure!(
            !name.trim().is_empty() && !name.contains('\0'),
            "invalid item name"
        );
    }
    let mut changed = input.name.is_some();
    if let Some(login) = &input.login {
        ensure!(
            login.username.is_some() || login.password.is_some(),
            "login must contain username or password"
        );
        for value in [&login.username, &login.password].into_iter().flatten() {
            ensure!(
                !value.contains('\0'),
                "credential values cannot contain NUL"
            );
        }
        changed = true;
    }
    if let Some(fields) = &input.fields {
        ensure!(!fields.is_empty(), "fields must not be empty");
        let mut names = HashSet::new();
        for field in fields {
            ensure!(
                !field.name.trim().is_empty() && !field.name.contains('\0'),
                "invalid custom field name"
            );
            ensure!(names.insert(&field.name), "duplicate custom field name");
            ensure!(
                !field.value.contains('\0'),
                "credential values cannot contain NUL"
            );
        }
        changed = true;
    }
    ensure!(changed, "mutation must specify at least one change");
    Ok(input)
}

fn apply(input: Input, mut item: Value) -> Result<Value> {
    ensure!(
        item.is_object() && item["type"] == 1,
        "only login items can be updated"
    );
    ensure!(
        item["deletedDate"].is_null() && item["archivedDate"].is_null(),
        "deleted or archived items cannot be updated"
    );
    if let Some(name) = input.name {
        item["name"] = json!(name);
    }
    if let Some(login) = input.login {
        ensure!(item["login"].is_object(), "item has invalid login data");
        if let Some(value) = login.username {
            item["login"]["username"] = json!(value);
        }
        if let Some(value) = login.password {
            item["login"]["password"] = json!(value);
        }
    }
    if let Some(patches) = input.fields {
        if item["fields"].is_null() {
            item["fields"] = json!([]);
        }
        let fields = item["fields"]
            .as_array_mut()
            .ok_or_else(|| anyhow::anyhow!("item has invalid custom fields"))?;
        for patch in patches {
            let matching: Vec<usize> = fields
                .iter()
                .enumerate()
                .filter(|(_, f)| f["name"] == patch.name)
                .map(|(i, _)| i)
                .collect();
            ensure!(matching.len() <= 1, "custom field name is ambiguous");
            if let Some(index) = matching.first() {
                let field = &mut fields[*index];
                ensure!(
                    matches!(field["type"].as_u64(), Some(0 | 1)),
                    "only text and hidden custom fields can be updated"
                );
                field["value"] = json!(patch.value);
                if let Some(kind) = patch.r#type {
                    field["type"] = json!(kind.number());
                }
            } else {
                fields.push(json!({"name":patch.name,"value":patch.value,"type":patch.r#type.unwrap_or(FieldType::Hidden).number()}));
            }
        }
    }
    Ok(item)
}

pub(crate) fn execute(
    backend: &Bw<'_>,
    token: &str,
    id: Option<&str>,
    input: Input,
) -> Result<Value> {
    let id = id
        .map(|id| {
            uuid::Uuid::parse_str(id)
                .map(|id| id.hyphenated().to_string())
                .map_err(|_| anyhow::anyhow!("update item identifier must be a UUID"))
        })
        .transpose()?;
    backend.call(&["sync"], Some(token))?;
    let original = if let Some(id) = &id {
        let raw = Zeroizing::new(backend.call(&["get", "item", id], Some(token))?);
        let item: Value = serde_json::from_str(&raw)
            .map_err(|_| anyhow::anyhow!("bw returned invalid item data"))?;
        ensure!(
            item["id"] == *id,
            "bw returned a different item than requested"
        );
        item
    } else {
        json!({"type":1,"name":"","login":{},"fields":[],"notes":null,"favorite":false,"reprompt":0,"organizationId":null,"collectionIds":[],"folderId":null})
    };
    let item = apply(input, original)?;
    let raw = Zeroizing::new(serde_json::to_string(&item).context("cannot encode mutation")?);
    // bw 2026.8.0 create/edit read base64 JSON from stdin when requestJson is omitted.
    let encoded = Zeroizing::new(base64(raw.as_bytes()));
    let args = if let Some(id) = &id {
        vec!["edit", "item", id]
    } else {
        vec!["create", "item"]
    };
    let response = Zeroizing::new(backend.mutate(&args, token, encoded)?);
    let result: Value = serde_json::from_str(&response).map_err(|_| anyhow::anyhow!("mutation outcome uncertain: bw returned invalid item data; inspect vault before retrying"))?;
    let result_id = result["id"].as_str().and_then(|s| uuid::Uuid::parse_str(s).ok())
        .ok_or_else(|| anyhow::anyhow!("mutation outcome uncertain: bw returned invalid item ID; inspect vault before retrying"))?.hyphenated().to_string();
    ensure!(
        id.as_ref().is_none_or(|id| *id == result_id),
        "mutation outcome uncertain: bw returned a different item; inspect vault before retrying"
    );
    // Return only the validated identifier and operation, never arbitrary backend strings.
    Ok(json!({"id":result_id,"created":id.is_none(),"updated":id.is_some()}))
}

/// Sync and inspect the exact target before making one soft-delete request.
pub(crate) fn delete(backend: &Bw<'_>, token: &str, id: &str) -> Result<Value> {
    let id = uuid::Uuid::parse_str(id)
        .map_err(|_| anyhow::anyhow!("delete item identifier must be a UUID"))?
        .hyphenated()
        .to_string();
    backend.call(&["sync"], Some(token))?;
    let raw = Zeroizing::new(backend.call(&["get", "item", &id], Some(token))?);
    let item: Value =
        serde_json::from_str(&raw).map_err(|_| anyhow::anyhow!("bw returned invalid item data"))?;
    ensure!(
        item["id"] == id,
        "bw returned a different item than requested"
    );
    ensure!(
        item["deletedDate"].is_null(),
        "item is already deleted; permanent deletion is not supported"
    );
    backend.soft_delete(&id, token)?;
    Ok(json!({"id":id,"deleted":true,"permanent":false}))
}

// Standard RFC 4648 base64, kept local to avoid an extra dependency for one encoder.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = *chunk.get(1).unwrap_or(&0);
        let c = *chunk.get(2).unwrap_or(&0);
        out.push(ALPHABET[(a >> 2) as usize] as char);
        out.push(ALPHABET[(((a & 3) << 4) | (b >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(((b & 15) << 2) | (c >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(c & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_and_sanitized_input() {
        for raw in [
            r#"{"name":"x","name":"CANARY"}"#,
            r#"{"login":{"password":null}}"#,
            r#"{"login":{"password":"x","password":"CANARY"}}"#,
            r#"{"fields":[{"name":"t","value":"x","type":"CANARY"}]}"#,
            r#"{"fields":[{"name":"t","value":"x"},{"name":"t","value":"y"}]}"#,
            r#"{"CANARY":true}"#,
            "{}",
            r#"{"login":{}}"#,
            r#"{"fields":[]}"#,
            r#"{"name":null}"#,
            r#"{"login":{"password":"\u0000"}}"#,
        ] {
            let err = parse(raw.as_bytes(), false).err().expect("must reject");
            assert!(!err.to_string().contains("CANARY"));
        }
        assert!(parse(br#"{"login":{"password":""}}"#, false).is_ok());
        assert!(parse(br#"{"login":{"password":"x"}}"#, true).is_err());
        assert!(parse(&vec![b' '; INPUT_LIMIT + 1], false).is_err());
    }
    #[test]
    fn patches_preserve_unselected_data() {
        let original = json!({"type":1,"name":"old","notes":"keep","login":{"username":"keep","password":"old","totp":"keep","uris":[{"uri":"keep"}]},"fields":[{"name":"t","type":0,"value":"old","extra":true},{"name":"other","type":2,"value":"true"}],"revisionDate":"keep","attachments":[{"id":"keep"}],"organizationId":"keep","collectionIds":["keep"]});
        let mut expected = original.clone();
        expected["login"]["password"] = json!("new");
        expected["fields"][0]["value"] = json!("new");
        let input = parse(
            br#"{"login":{"password":"new"},"fields":[{"name":"t","value":"new"}]}"#,
            false,
        )
        .unwrap();
        assert_eq!(apply(input, original).unwrap(), expected);
        for fields in [
            json!([{"name":"t","type":0},{"name":"t","type":1}]),
            json!([{"name":"t","type":2}]),
            json!([{"name":"t","type":3}]),
        ] {
            assert!(
                apply(
                    parse(br#"{"fields":[{"name":"t","value":"x"}]}"#, false).unwrap(),
                    json!({"type":1,"fields":fields})
                )
                .is_err()
            );
        }
    }
    #[test]
    fn base64_vectors() {
        for (input, expected) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(input.as_bytes()), expected);
        }
    }
}
