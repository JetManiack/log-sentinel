# log-sentinel

Deterministic security log audit daemon for Kubernetes and bare-metal hosts.

Polls VictoriaLogs via LogsQL, fires on rule matches, masks secrets before any output,
optionally enriches findings with an LLM (structured output, cannot suppress alerts),
and publishes results to stdout JSON and a coordination board.

## How it works

```
VictoriaLogs ──LogsQL──► Detector ──► Masker ──► Triager (optional LLM) ──► Sinks
                         rules +                   json_schema output        stdout JSON
                         fail-open                 ±context window           board MCP
```

Every finding has a stable fingerprint (`sha256(ruleID + source + key)[:16]`).
SQLite deduplicates; quiet windows (set via `/quiet` or config) silence repeats without
dropping findings from state.

**Fail-open patterns** are scanned on every poll independently of rules. If a rule is
missing or misconfigured, substrings like `"permission denied"` or `"x509"` still fire
a `medium` finding as a backstop.

## Quick start

```bash
# Docker
docker run -d \
  --name sentinel \
  -v ./config.yaml:/etc/sentinel/config.yaml:ro \
  -v ./rules.d:/etc/sentinel/rules.d:ro \
  ghcr.io/jetmaniack/log-sentinel:latest \
  --config /etc/sentinel/config.yaml

# From source
git clone https://github.com/JetManiack/log-sentinel
cd log-sentinel
make build
./bin/sentinel --config config.example.yaml
```

Health endpoints on port `9100`: `/livez` (always 200), `/readyz` (200 when SQLite is reachable).

## Configuration

Copy `config.example.yaml` and edit. Minimal working config:

```yaml
state: "data/sentinel.db"

logs:
  - name: "local"
    url:  "http://victorialogs:9428"

detector:
  interval:             1m
  quiet_window_default: 24h
  rules_dir:            "rules.d"
  fail_open_patterns:
    - "401"
    - "permission denied"
    - "x509"

sinks:
  stdout_json: true

digest:
  time:     "19:00"
  timezone: "Asia/Nicosia"
```

All config fields are documented in [`config.example.yaml`](config.example.yaml).

## Rules

Rules live in `*.yaml` files under `rules_dir`. Each file has a top-level `rules:` list.
Rules with unknown severity, empty ID, or missing query are skipped with a warning — a
single bad file never disables all detection.

```yaml
rules:
  - id:          "sshd-failure"
    severity:    "medium"      # low | medium | high | critical
    description: "SSH auth failure"
    source:      "local"       # optional; empty = all sources
    query: '{unit="sshd"} |= "Failed password"'
```

Inline rules (in the config file) take precedence over directory rules by the same ID.

### Built-in rule sets

| Rule ID | Severity | What it catches |
|---|---|---|
| `k8s-exec-attach` | high | `kubectl exec` / `attach` into a pod |
| `k8s-secrets-read` | high | Secrets `get`/`list` by non-controller identities |
| `k8s-rbac-write` | high | ClusterRole / RoleBinding created or modified |
| `k8s-image-digest-change` | medium | Running container image digest changed |
| `sshd-failure` | medium | Failed SSH authentication attempts |
| `sshd-new-key` | medium | New `authorized_key` added |
| `sudo-command` | medium | sudo execution |
| `useradd-usermod` | high | System user created or modified |
| `kernel-oops` | critical | Kernel oops / panic |
| `squid-denied` | high | `TCP_DENIED` in Squid proxy log |
| `dns-first-seen` | medium | First-ever resolution of a domain (new-domain baseline) |

## Secret masking

The masker runs before log lines reach the LLM, the board, or the digest.
Built-in patterns redact: Bearer tokens, `Authorization:` headers, `api_key=` / `secret=` /
`password=` / `token=` fields, `sk-` / `glsa_` / `ghp_` prefixed tokens, PEM private key
blocks, and long base64 runs (≥40 chars). Redaction preserves the key name prefix:
`api_key=[REDACTED]`.

## LLM triage

Disabled by default. Enable with `llm.enabled: true` — the finding is **always published**
regardless of what the LLM returns.

```yaml
llm:
  enabled:        true
  base_url:       "http://llm-gateway/v1"
  model:          "gemma-4-26b-a4b-it"
  context_window: 2m    # ±window to fetch surrounding lines
  context_lines:  20    # max surrounding lines to include
  # prompts_dir: "prompts.d"  # optional blueprint override directory
```

**What the LLM can do:** explain what happened (`what_happened_ru`), assess impact
(`impact_ru`), suggest checks (`recommended_check_ru`), flag as likely benign.

**What the LLM cannot do:** suppress or delay a finding, downgrade severity, raise
severity by more than +1 level, or parse `/quiet`/`/benign` commands.

If the LLM returns `finish_reason=length`, malformed output, or times out, the finding
is published unenriched — no alert is dropped.

### Structured output

The triage prompt blueprint includes a JSON Schema (`internal/prompt/builtin/triage.yaml`).
When the provider supports OpenAI-compatible `json_schema` response format, it is used
(strict mode). Providers that don't support it fall back to `json_object`. Override or
replace the blueprint by pointing `llm.prompts_dir` at a directory containing a `triage.yaml`
with a `schema:` block.

### Context window

For each finding the sentinel fetches up to `llm.context_lines` surrounding lines from
the same pod/namespace/job stream over a `±context_window` window. The LLM prompt shows
the matched lines and the surrounding context in separate sections.

### Prompt blueprints

Prompts are Go `text/template` YAML files, embedded in the binary. Override without
recompiling by pointing `llm.prompts_dir` at a directory of `*.yaml` files — any blueprint
whose `name:` matches a built-in replaces it.

## Board sink

```yaml
sinks:
  board:
    enabled:      true
    url:          "https://board.example.com/mcp"
    token:        "..."
    min_severity: "medium"   # low findings → digest only
```

Each fingerprint gets one board thread. Repeat firings become replies to that thread.

## Board commands

Reply to a sentinel thread with a command at the **start of a line**. Commands are parsed
deterministically — no LLM involved. Every accepted or rejected command generates an audit
reply.

```
/quiet 2h    maintenance window          Suppress repeats for 2h (supports: 30m, 2h, 1d, 2w, 1mo)
/unquiet                                 Cancel the active quiet window immediately
/benign      routine backup noise        Mark this rule+source combination as benign
```

Authorization uses the stable board actor ID, not the mutable display nickname. Processed
reply IDs are persisted in SQLite so commands are not replayed on restart.

| Config field | Who can |
|---|---|
| `commands.allowed_actors` | Issue any command |
| `commands.critical_mute_actors` | Also quiet or benign `critical` findings |
| `commands.max_agent_quiet_days` | Cap on non-critical-mute quiet duration (default 7d) |
| `commands.max_agent_benign_days` | Expiry of agent benign overrides (default 30d) |

**Benign overrides are scoped.** `/benign` creates an override for `ruleID@source`, not the
bare rule — one ack cannot blanket-suppress a rule across all log sources.

## Daily digest

```yaml
digest:
  time:     "19:00"        # HH:MM
  timezone: "Asia/Nicosia" # IANA timezone
```

Findings from the past 24 h, sorted critical → low. Silently skipped if empty.
Emitted as a JSON line to stdout and, if the board sink is enabled, as a new board thread
tagged `digest`.

## stdout JSON output

Every finding is a single JSON line (HTML escaping disabled). vlagent picks these up and
ships them to VictoriaLogs, where a Grafana alert rule fires and notifies via Telegram.

```json
{
  "time": "2026-10-22T01:00:00Z",
  "level": "ERROR",
  "msg": "kubectl exec or attach into a running pod",
  "severity": "high",
  "rule_id": "k8s-exec-attach",
  "source": "local",
  "evidence": ["..."],
  "enrichment": { ... }
}
```

## Kubernetes deployment

The sentinel needs no ServiceAccount or RBAC — it never calls the Kubernetes API.

```yaml
spec:
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
  containers:
    - name: sentinel
      image: ghcr.io/jetmaniack/log-sentinel:latest
      args: ["--config", "/etc/sentinel/config.yaml"]
      livenessProbe:
        httpGet: { path: /livez, port: 9100 }
      readinessProbe:
        httpGet: { path: /readyz, port: 9100 }
```

Docker image: multi-arch (`linux/amd64`, `linux/arm64`), `CGO_ENABLED=0`, based on
`alpine:3.22` + `tzdata`.

## Security notes

- No operator names, IPs, or hostnames in source code — all in the config file.
- Masking runs before the LLM, board, and digest — secrets never leave the machine in cleartext.
- LLM cannot suppress findings. Any failure in the triage path → unenriched finding is published.
- Rule validation at startup — a single malformed file in `rules_dir` does not disable detection.
- Command replay protection — board reply IDs persisted in SQLite.
