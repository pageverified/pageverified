# PageVerified

PageVerified is a paid API for AI agents. One API key and one prepaid credit balance cover every
tool: capture a web page with a SHA-256 hash and a UTC timestamp, inspect MCP servers and x402
payment offers before an agent pays, check a seller's domain, verify links, and search a directory
of agent tools.

Website: https://pageverified.com

This repository holds the public pieces: how to connect, the MCP Registry entry, the offline
record verifier and a few examples. The service itself is not in this repository.

## Connect over MCP

| Setting | Value |
| --- | --- |
| Endpoint | `https://pageverified.com/mcp` |
| Transport | Streamable HTTP. Requests are JSON-RPC over POST. A GET returns 405. |
| Authentication | `Authorization: Bearer <key>` |
| Without a key | `initialize` and `tools/list` work, and `directory_search` is free. Other `tools/call` calls need a key. |
| Credits | The same key and the same balance as the HTTP API. |

Get a free key with no signup, email or card:

```sh
curl -s -X POST https://pageverified.com/api/v1/keys \
  -H "content-type: application/json" -d '{"label":"my agent"}'
```

The key is shown once, so save it. Set it as `PAGEVERIFIED_API_KEY`, or put it in your client's
secret settings.

### Claude Code

```sh
claude mcp add --transport http pageverified https://pageverified.com/mcp \
  --header "Authorization: Bearer $PAGEVERIFIED_API_KEY"
```

Or in a project's `.mcp.json`:

```json
{
  "mcpServers": {
    "pageverified": {
      "type": "http",
      "url": "https://pageverified.com/mcp",
      "headers": { "Authorization": "Bearer ${PAGEVERIFIED_API_KEY}" }
    }
  }
}
```

### Cursor

In `.cursor/mcp.json` for one project, or `~/.cursor/mcp.json` for all of them:

```json
{
  "mcpServers": {
    "pageverified": {
      "url": "https://pageverified.com/mcp",
      "headers": { "Authorization": "Bearer ${env:PAGEVERIFIED_API_KEY}" }
    }
  }
}
```

### Codex

In `~/.codex/config.toml`:

```toml
[mcp_servers.pageverified]
url = "https://pageverified.com/mcp"
bearer_token_env_var = "PAGEVERIFIED_API_KEY"
```

### Any other client

A client that supports Streamable HTTP and lets you set a request header can connect. Give it the
endpoint and the `Authorization` header above. Client config formats belong to each client and can
change; the current versions are on https://pageverified.com/screenshot-mcp-server.

`tools/list` always returns the current tools, their inputs and their costs.

## Pay per call with x402, no key

Some tools can be paid for one call at a time in USDC on Base (x402 version 2, scheme `exact`),
with no API key. POST the tool's JSON input with no `Authorization` header. The answer is a 402
whose `PAYMENT-REQUIRED` header carries the offer. Sign it and resend the same POST with a
`PAYMENT-SIGNATURE` header. The tool runs and its answer comes back with a `PAYMENT-RESPONSE`
header.

Prices when this file was written (18 November 2026), from the service's own configuration, at one
US cent a credit:

| Route | Tool | Required input | Price |
| --- | --- | --- | --- |
| `POST /api/v1/prepay/check` | `prepay_check` | url | US$0.05 (5 credits) |
| `POST /api/v1/capture` | `capture` | url | US$0.01 (1 credit); PDF US$0.02 (2 credits) |
| `POST /api/v1/capture/record` | `capture_record` | url | US$0.05 (5 credits); PDF US$0.06 (6 credits) |
| `POST /api/v1/seller/check` | `seller_check` | domain | US$0.03 (3 credits) |
| `POST /api/v1/x402/inspect` | `x402_inspect` | url | US$0.01 (1 credit) |
| `POST /api/v1/links/verify` | `links_verify` | page_url, target | US$0.01 (1 credit) |
| `POST /api/v1/agent/readiness` | `agent_readiness` | domain | US$0.03 (3 credits) |

Prices and the routes on sale can change. The live list, prices and per-payer spending limits are
at https://pageverified.com/pricing and https://pageverified.com/.well-known/x402. Nothing is
charged for input a tool would refuse. If a tool fails after payment, the credits are held on an
API key returned with the answer, so you can retry with that key.

The same tools are sold per call over MCP at https://pageverified.com/mcp (x402 MCP transport v2). A `tools/call` with no key returns a tool result with `isError: true` whose `structuredContent` is the x402 `PaymentRequired` object (also in `content[0].text` as JSON). Sign `accepts[0]` and call the tool again with the payment in `params._meta["x402/payment"]`. The answer carries `_meta["x402/payment-response"]`.

For many calls, buy a credit pack and use an API key instead: see https://pageverified.com/pricing
and https://pageverified.com/agents/pay.

## Free checkers

These run in a browser with no key:

- https://pageverified.com/check/mcp: inspect an MCP server.
- https://pageverified.com/check/x402: read an x402 payment offer without paying.
- https://pageverified.com/check/agent-readiness: what an AI agent can find and use on a domain.

All of them are listed at https://pageverified.com/check.

## Docs

- https://pageverified.com/docs: quickstart, MCP setup, buying credits and every tool's reference page.
- https://pageverified.com/openapi.yaml: OpenAPI description of every endpoint.
- https://pageverified.com/llms.txt: a short plain-text map of the service.
- https://pageverified.com/.well-known/mcp/server-card.json: the MCP Server Card.

## Records and the offline verifier

PageVerified can sign what it observed as a record. The open format is specified at
https://pageverified.com/spec/record-format. Public keys are at
https://pageverified.com/.well-known/pageverified-keys.json.

[`verifier/pageverified-verify.mjs`](verifier/pageverified-verify.mjs) checks a record on your own
computer: one file, MIT licence, Node.js 20 or newer, no dependencies and no network calls. It is
the same file served at https://pageverified.com/verify/pageverified-verify.mjs. How to use it, and
what each check does and does not prove, is in [`verifier/README.md`](verifier/README.md).

Captures are not a forensic chain of custody, and a valid signature does not show that what a page
says is true.

## Files

| Path | What it is |
| --- | --- |
| `server.json` | The manifest for the official MCP Registry entry `com.pageverified/tools`. |
| `verifier/` | The offline record verifier and its instructions. |
| `examples/` | curl examples: MCP `initialize`, MCP `tools/list`, and an x402 offer probe. None of them spends anything. |

## Licence

MIT. See [LICENSE](LICENSE).
