use clap::CommandFactory;
use serde_json::{Value, json};

/// Static interface metadata: never inspect configuration, sessions, or the vault.
pub(crate) fn manifest() -> Value {
    let mut cli = crate::Cli::command();
    cli.build();
    let commands: Vec<Value> = cli
        .get_subcommands()
        .filter(|command| !command.is_hide_set() && command.get_name() != "help")
        .map(|command| {
            let name = command.get_name();
            let mut usage = command.clone().bin_name(format!("latch {name}"));
            let arguments: Vec<Value> = command
                .get_arguments()
                .filter(|arg| !arg.is_hide_set())
                .map(|arg| {
                    json!({
                        "name": arg.get_id().as_str(),
                        "long": arg.get_long(),
                        "short": arg.get_short().map(|short| short.to_string()),
                        "description": arg.get_help().map(ToString::to_string),
                        "required": arg.is_required_set(),
                        "takes_value": arg.get_action().takes_values(),
                        "repeatable": matches!(arg.get_action(), clap::ArgAction::Append),
                        "positional": arg.get_index().is_some()
                    })
                })
                .collect();
            json!({
                "name": name,
                "description": command.get_about().map(ToString::to_string),
                "usage": usage.render_usage().to_string(),
                "arguments": arguments,
                "help_command": ["latch", name, "--help"],
                "requires_interactive_terminal": name == "login",
                "requires_stored_session": matches!(name, "sync" | "list" | "run" | "write" | "create" | "update" | "delete"),
            })
        })
        .collect();
    json!({
        "schema_version": 1,
        "name": "latch",
        "version": env!("CARGO_PKG_VERSION"),
        "supported_platforms": ["macos"],
        "commands": commands,
        "discovery": {
            "requires_configuration": false,
            "requires_authentication": false,
            "reports_runtime_readiness": false,
            "readiness_commands": [["latch", "status", "--json"], ["latch", "doctor", "--json"]]
        },
        "authentication": {
            "backend": "bitwarden-cli",
            "supported_backend_version": crate::bw::VERSION,
            "login_command": ["latch", "login"],
            "login_api_key_command": ["latch", "login", "--api-key"],
            "agent_instruction": "Ask the user to run login in their terminal; never request credentials in chat.",
            "noninteractive_commands_prompt_for_login": false
        },
        "bindings": {
            "syntax": "NAME=ITEM_UUID/FIELD",
            "fields": ["login.username", "login.password", "custom.NAME"],
            "item_identifier": "uuid",
            "environment_name_pattern": "^[A-Za-z_][A-Za-z0-9_]*$",
            "reserved_environment_prefixes": ["BW_", "BITWARDENCLI_", "LATCH_"],
            "duplicate_environment_names_allowed": false,
            "discovery_command": ["latch", "list", "--search", "NAME", "--json"]
        },
        "mutations": {
            "commands": {"create": ["latch", "create"], "update": ["latch", "update", "ITEM_UUID"]},
            "input": "one strict UTF-8 JSON object on non-terminal stdin",
            "max_input_bytes": crate::mutate::INPUT_LIMIT,
            "schema": {
                "name": "optional nonempty string; required for create",
                "login": {"username": "optional string", "password": "optional string"},
                "fields": [{"name": "unique nonempty exact name", "value": "string", "type": "optional: text or hidden"}]
            },
            "rules": ["unknown and duplicate JSON keys, nulls, NUL characters, empty patches and unsupported types are rejected", "login if present must contain username or password; fields if present must be nonempty", "new custom fields default to hidden; existing field types are preserved unless specified", "empty credential strings are allowed; field deletion is not supported", "create makes personal login items only; update accepts non-deleted, non-archived login items only", "update preserves unspecified fields and metadata; ambiguous or unsupported targeted custom fields are rejected"],
            "backend_transport": "base64 JSON through stdin, never argv",
            "implicit_sync": true,
            "automatic_retry": false,
            "concurrency": "exclusive local state lock and sync before fetch/edit; not an atomic cross-client compare-and-swap; avoid concurrent vault edits",
            "failure": "a mutation error can have an uncertain outcome; inspect vault before retrying",
            "rotation": "updates stored vault values only; does not issue or revoke provider credentials or refresh previously written files",
            "success_fields": ["id", "created", "updated"],
            "agent_instruction": "Never place secrets in argv, chat, shell history, tracing, or output. Feed stdin from a trusted secret source."
        },
        "deletion": {
            "command": ["latch", "delete", "ITEM_UUID"],
            "item_identifier": "uuid",
            "input": "UUID argument only; no stdin payload",
            "semantics": "soft delete to vault trash only; already-deleted items are refused",
            "permanent_deletion_supported": false,
            "implicit_sync": true,
            "automatic_retry": false,
            "concurrency": "exclusive local state lock; sync and exact-target validation before delete; not atomic across clients",
            "failure": "backend delete failures have uncertain outcome; inspect vault before retrying",
            "success": {"id": "ITEM_UUID", "deleted": true, "permanent": false},
            "credential_effect": "deleted items cannot be injected by run/write; previously written files and provider credentials remain unchanged"
        },
        "credential_delivery": {
            "run": {
                "destination": "child_process_environment",
                "implicit_shell": false,
                "implicit_sync": false,
                "example_argv": ["latch", "run", "--env", "API_TOKEN=ITEM_UUID/login.password", "--", "command", "args"]
            },
            "write": {
                "formats": ["dotenv", "zshrc"],
                "plaintext": true,
                "persists_after_lock": true,
                "agent_instruction": "Use only when the user requests plaintext persistence."
            },
            "agent_instruction": "Do not print credentials, dump process environments, or enable shell tracing. Child processes can expose their own credentials."
        },
        "output": {
            "success_stream": "stdout",
            "default_format": "pretty_json",
            "json_flag": "--json",
            "json_flag_format": "compact_json",
            "operational_error_stream": "stderr",
            "operational_error_with_json": {"error": {"code": "LATCH_ERROR", "message": "human-readable description"}},
            "cli_syntax_errors": "text, including with --json",
            "run_after_exec": "stdout and stderr belong to the child; output is not wrapped in JSON",
            "exit_codes": {"success": 0, "operational_error": 1, "cli_syntax_error": 2},
            "run_exit_behavior": "preserves child exit status and signals",
            "readiness": "status and doctor may exit 0 when not ready; inspect result fields"
        }
    })
}
