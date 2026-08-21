# Fish shell completions for hardening-loop
# Algorithmic Code Hardening Loop CLI

# Disable file completions by default unless specified
complete -c hardening-loop -f

# Subcommands
complete -c hardening-loop -n "__fish_use_subcommand" -a "run" -d "Execute hardening phases on a target"
complete -c hardening-loop -n "__fish_use_subcommand" -a "review" -d "Review a Knowledge Candidate in Admission Gate"
complete -c hardening-loop -n "__fish_use_subcommand" -a "inspect" -d "Cryptographically verify an evidence directory"
complete -c hardening-loop -n "__fish_use_subcommand" -a "validate" -d "Validate artifact against normative JSON Schemas"
complete -c hardening-loop -n "__fish_use_subcommand" -a "telemetry" -d "Display performance telemetry and latencies"

# Subcommand: run
complete -c hardening-loop -n "__fish_seen_subcommand_from run" -l target -r -F -d "Path to target code or module"
complete -c hardening-loop -n "__fish_seen_subcommand_from run" -l phase -x -a "all question delete simplify verify codify" -d "Hardening phase to execute"
complete -c hardening-loop -n "__fish_seen_subcommand_from run" -l output -r -d "Output evidence directory"
complete -c hardening-loop -n "__fish_seen_subcommand_from run" -l workspace-root -r -d "Root directory confining authorized file access"
complete -c hardening-loop -n "__fish_seen_subcommand_from run" -l json -d "Emit raw JSON manifest to stdout"
complete -c hardening-loop -n "__fish_seen_subcommand_from run" -s q -l quiet -d "Suppress verbose banners"

# Subcommand: review
complete -c hardening-loop -n "__fish_seen_subcommand_from review" -l admit -d "Admit candidate into accepted knowledge"
complete -c hardening-loop -n "__fish_seen_subcommand_from review" -l reject -d "Reject candidate"
complete -c hardening-loop -n "__fish_seen_subcommand_from review" -l reviewer -r -d "Identifier of the human reviewer"
complete -c hardening-loop -n "__fish_seen_subcommand_from review" -l notes -r -d "Review notes or justification"
complete -c hardening-loop -n "__fish_seen_subcommand_from review" -l workspace-root -r -d "Root directory confining authorized file access"
complete -c hardening-loop -n "__fish_seen_subcommand_from review" -l json -d "Emit review result as JSON"
complete -c hardening-loop -n "__fish_seen_subcommand_from review" -s q -l quiet -d "Suppress non-essential text"
complete -c hardening-loop -n "__fish_seen_subcommand_from review" -F

# Subcommand: inspect
complete -c hardening-loop -n "__fish_seen_subcommand_from inspect" -l workspace-root -r -d "Root directory confining authorized file access"
complete -c hardening-loop -n "__fish_seen_subcommand_from inspect" -l json -d "Emit inspection report as JSON"
complete -c hardening-loop -n "__fish_seen_subcommand_from inspect" -s q -l quiet -d "Suppress non-essential output"
complete -c hardening-loop -n "__fish_seen_subcommand_from inspect" -F

# Subcommand: validate
complete -c hardening-loop -n "__fish_seen_subcommand_from validate" -l schema -x -a "evidence_envelope knowledge_candidate work_unit" -d "Schema name to validate against"
complete -c hardening-loop -n "__fish_seen_subcommand_from validate" -l workspace-root -r -d "Root directory confining authorized file access"
complete -c hardening-loop -n "__fish_seen_subcommand_from validate" -l json -d "Emit validation result as JSON"
complete -c hardening-loop -n "__fish_seen_subcommand_from validate" -s q -l quiet -d "Suppress non-essential output"
complete -c hardening-loop -n "__fish_seen_subcommand_from validate" -F

# Subcommand: telemetry
complete -c hardening-loop -n "__fish_seen_subcommand_from telemetry" -l workspace-root -r -d "Root directory confining authorized file access"
complete -c hardening-loop -n "__fish_seen_subcommand_from telemetry" -l posthog -d "Export telemetry batch to PostHog Cloud"
complete -c hardening-loop -n "__fish_seen_subcommand_from telemetry" -l api-key -r -d "PostHog API Key or Project Token"
complete -c hardening-loop -n "__fish_seen_subcommand_from telemetry" -l dry-run -d "Simulate export without network requests"
complete -c hardening-loop -n "__fish_seen_subcommand_from telemetry" -l json -d "Emit telemetry metrics as JSON"
complete -c hardening-loop -n "__fish_seen_subcommand_from telemetry" -s q -l quiet -d "Suppress non-essential output"
complete -c hardening-loop -n "__fish_seen_subcommand_from telemetry" -F
