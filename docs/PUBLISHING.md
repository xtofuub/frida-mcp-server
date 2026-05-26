# Publishing to the MCP Registry

The [official MCP Registry](https://registry.modelcontextprotocol.io) stores
**metadata only** — the actual package must live on npm first. So publishing is
two stages: npm, then the registry. Both stages need interactive auth that only
you (the maintainer) can complete.

Server name (GitHub namespace): **`io.github.xtofuub/frida-mcp-server`**
(`mcpName` in `package.json` and `name` in `server.json` already match this).

> Runtime note: this npm package is a Node launcher for a **Python** Frida server.
> A client running `npx frida-mcp-server serve` still needs Python with `frida`
> and `mcp` installed (`FRIDA_MCP_PYTHON` points at it). That dependency is
> inherent to the project and documented in the README.

## One-time prep (already done in-repo)

- `package.json` → `"mcpName": "io.github.xtofuub/frida-mcp-server"`, `version` bumped.
- `server.json` → schema `2025-12-11`, npm package, `transport: stdio`,
  `packageArguments: ["serve"]`, optional `FRIDA_MCP_PYTHON`.

Keep `version` identical in `package.json` and `server.json` on every release.

## Stage 1 — publish to npm

```bash
# from repo root; name "frida-mcp-server" is currently available
npm login                 # interactive — run yourself
npm publish --access public
# verify:
npm view frida-mcp-server version
```

The registry verifies ownership by reading `mcpName` from the **published** npm
package, so this must happen before stage 2.

## Stage 2 — publish to the MCP Registry

Install the publisher CLI (Windows PowerShell):

```powershell
$arch = if ([System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -eq "Arm64") { "arm64" } else { "amd64" }
Invoke-WebRequest -Uri "https://github.com/modelcontextprotocol/registry/releases/latest/download/mcp-publisher_windows_$arch.tar.gz" -OutFile "mcp-publisher.tar.gz"
tar xf mcp-publisher.tar.gz mcp-publisher.exe
Remove-Item mcp-publisher.tar.gz
# move mcp-publisher.exe somewhere on PATH
```

Then authenticate and publish:

```bash
mcp-publisher login github      # interactive device-code flow — run yourself
mcp-publisher publish           # validates server.json, verifies npm ownership
# verify:
curl "https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.xtofuub/frida-mcp-server"
```

## Releasing a new version

1. Bump `version` in **both** `package.json` and `server.json`.
2. `npm publish --access public`.
3. `mcp-publisher publish`.

Optionally automate stages with the
[Publish MCP Server GitHub Action](https://github.com/marketplace/actions/publish-mcp-server).

## Troubleshooting

| Error | Fix |
|-------|-----|
| `Registry validation failed for package` | `mcpName` missing/mismatched in the *published* npm package — republish npm first. |
| `Invalid or expired Registry JWT token` | Re-run `mcp-publisher login github`. |
| `You do not have permission to publish this server` | Name must start with `io.github.xtofuub/` for GitHub auth. |
