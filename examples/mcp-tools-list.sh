#!/bin/sh
# List PageVerified's MCP tools. No API key is needed and no tool runs.
# If the answer carries a nextCursor, send it back in params.cursor to get the next page.
curl -s -X POST https://pageverified.com/mcp \
  -H "content-type: application/json" \
  -H "accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
echo
