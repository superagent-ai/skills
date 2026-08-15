---
name: superagent
description: Configure and safely use Superagent's remote MCP server for findings, security reports, Contributor Trust, Context Guardrails, and Runtime Guardrails. Use when the user asks to install, connect, configure, troubleshoot, or operate Superagent from Cursor, Claude Code, Codex CLI, or another MCP client.
---

# Superagent MCP

Connect a coding agent to Superagent, then use its MCP tools without exposing
credentials or surprising the user with remote, billable, destructive, or
policy-changing actions.

Superagent MCP is an authenticated remote service. Do not connect to it, send
it data, or change an MCP client configuration unless the user explicitly asks.

## Setup workflow

1. Identify the MCP client and whether the user wants setup, troubleshooting,
   or an operation on an existing connection.
2. For setup, direct the user to create an organization API key at
   [Superagent Settings](https://www.superagent.sh/app/settings#api-keys).
   Never ask them to paste the key into chat.
3. Store the key as `SUPERAGENT_API_KEY` in the user's shell or system
   environment. Never put it in a repository, tracked `.env` file, command
   output, or response.
4. Use the exact endpoint `https://www.superagent.sh/mcp`. The bare domain
   redirects, and some MCP clients fail on redirected POST requests.
5. Show the proposed configuration and obtain approval before editing client
   configuration or running a setup command.
6. Verify that the client connects and exposes Superagent tools before
   attempting a product operation.

An organization API key can access the entire organization. Prefer a dedicated,
revocable key for agent use and revoke it immediately if it is exposed.

## Client configuration

### Cursor

Add this server to `mcp.json`. Remote servers cannot read `envFile`, so
`SUPERAGENT_API_KEY` must exist in the environment that launches Cursor.

```json
{
  "mcpServers": {
    "superagent": {
      "url": "https://www.superagent.sh/mcp",
      "headers": {
        "Authorization": "Bearer ${env:SUPERAGENT_API_KEY}"
      }
    }
  }
}
```

### Claude Code

After confirming that `SUPERAGENT_API_KEY` is exported, propose:

```bash
claude mcp add --transport http --scope user superagent https://www.superagent.sh/mcp \
  --header "Authorization: Bearer $SUPERAGENT_API_KEY"
```

Run `/mcp` in Claude Code to confirm the connection.

### Codex CLI

Add the following to `~/.codex/config.toml`. The feature flag must appear above
every `[mcp_servers.*]` block. The token setting is the environment variable's
name, not the token itself.

```toml
experimental_use_rmcp_client = true

[mcp_servers.superagent]
url = "https://www.superagent.sh/mcp"
bearer_token_env_var = "SUPERAGENT_API_KEY"
```

Export the variable before launching Codex, then use `/mcp` to verify.

### Other MCP clients

Configure Streamable HTTP with:

- URL: `https://www.superagent.sh/mcp`
- Header: `Authorization: Bearer $SUPERAGENT_API_KEY`

Keep the token in the client's supported secret or environment-variable store,
not in a tracked configuration file.

## Operating Superagent

Inspect the connected server's available tools rather than assuming a fixed
tool list. Match the user's request to these capability groups:

- **Findings**: list and inspect findings, update manual triage, or request
  automated triage.
- **Reports**: list or inspect repository, Web app, agent, and package reports;
  create a new report only after confirmation.
- **Contributor Trust**: retrieve a cached result or start and check a scan.
- **Context Guardrails**: score Web pages, email, files, skills, and public MCP
  repositories before an agent consumes them.
- **Runtime Guardrails**: manage endpoint clients, groups, rules, built-in rule
  modes, and alerts.

Prefer the smallest read-only call that answers the question. Summarize the
result and preserve identifiers the user needs for a follow-up. For
asynchronous operations, report the returned status or identifier and avoid
tight polling.

## Confirmation gates

Get explicit confirmation immediately before:

- creating any report or running automated finding triage, because these
  consume organization credits;
- permanently deleting a finding;
- creating, updating, assigning, or deleting Runtime Guardrails clients,
  groups, or rules;
- changing or restoring a built-in rule mode, because endpoint policy changes
  immediately;
- sending a target or content the user has not already authorized for remote
  analysis.

State the exact action, target, and consequence in the confirmation request.
Tool annotations are hints, not a substitute for this gate.

## Troubleshooting

- `401 invalid_token`: verify the key is present, active, and sent as
  `Authorization: Bearer ...`.
- `404` or failed connection on `superagent.sh/mcp`: switch to
  `https://www.superagent.sh/mcp`.
- Connected server with no tools: verify a proxy is not stripping the
  authorization header.
- Codex server unavailable: put `experimental_use_rmcp_client = true` above
  all MCP server blocks and ensure `bearer_token_env_var` contains the variable
  name.
- `429`: wait for the server's `Retry-After` interval. Do not retry
  aggressively.

## Documentation

- [MCP server](https://www.superagent.sh/docs/mcp)
- [API overview](https://www.superagent.sh/docs/api)
- [Settings and API keys](https://www.superagent.sh/docs/reference/settings)
- [Findings](https://www.superagent.sh/docs/findings)
- [Red Team reports](https://www.superagent.sh/docs/red-team)
- [Context Guardrails](https://www.superagent.sh/docs/context-guardrails)
