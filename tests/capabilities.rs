use serde_json::Value;
use std::{fs, process::Command};

#[test]
fn discovery_needs_no_home_backend_or_state_and_is_read_only() {
    let temporary = tempfile::tempdir().unwrap();
    let state = temporary.path().join("not-a-state-directory");
    fs::write(&state, "unchanged").unwrap();
    let mut results = Vec::new();
    for args in [
        vec!["capabilities", "--json"],
        vec!["--json", "capabilities"],
        vec!["capabilities"],
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_latch"))
            .args(["--state-dir", state.to_str().unwrap()])
            .args(args)
            .env_remove("HOME")
            .env("PATH", "")
            .output()
            .unwrap();
        assert!(result.status.success(), "{:?}", result);
        assert!(result.stderr.is_empty());
        results.push(serde_json::from_slice::<Value>(&result.stdout).unwrap());
    }
    assert!(results.windows(2).all(|pair| pair[0] == pair[1]));
    assert_eq!(fs::read_to_string(state).unwrap(), "unchanged");
    assert_eq!(fs::read_dir(temporary.path()).unwrap().count(), 1);
    let manifest = &results[0];
    assert_eq!(manifest["schema_version"], 1);
    assert_eq!(manifest["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(manifest["discovery"]["reports_runtime_readiness"], false);
    let commands = manifest["commands"].as_array().unwrap();
    let names: Vec<_> = commands
        .iter()
        .map(|entry| entry["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "capabilities",
            "configure",
            "login",
            "status",
            "sync",
            "list",
            "create",
            "update",
            "delete",
            "run",
            "write",
            "lock",
            "doctor"
        ]
    );
    for entry in commands {
        assert!(
            entry["usage"]
                .as_str()
                .unwrap()
                .contains(&format!("latch {}", entry["name"].as_str().unwrap()))
        );
    }
    assert_eq!(
        manifest["bindings"]["fields"],
        serde_json::json!(["login.username", "login.password", "custom.NAME"])
    );
    assert_eq!(
        manifest["output"]["operational_error_with_json"]["error"]["code"],
        "LATCH_ERROR"
    );
}

#[test]
fn delete_contract_is_soft_only() {
    let output = Command::new(env!("CARGO_BIN_EXE_latch"))
        .args(["capabilities", "--json"])
        .output()
        .unwrap();
    let m: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(m["deletion"]["permanent_deletion_supported"], false);
    assert_eq!(m["deletion"]["automatic_retry"], false);
    let command = m["commands"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "delete")
        .unwrap();
    assert_eq!(command["requires_stored_session"], true);
    assert!(
        command["arguments"]
            .as_array()
            .unwrap()
            .iter()
            .all(|a| a["long"] != "permanent")
    );
}
