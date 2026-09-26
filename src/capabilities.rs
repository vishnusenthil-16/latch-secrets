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
                "requires_stored_session": matches!(name, "sync" | "list" | "run" | "write"),
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
