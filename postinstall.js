#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

if (process.env.FLEX_MCP_SKIP_AUTO_INSTALL === '1') {
  console.log('flex-mcp-server: auto-registration skipped by FLEX_MCP_SKIP_AUTO_INSTALL=1');
  process.exit(0);
}

const cliPath = path.join(__dirname, 'bin', 'cli.js');

if (!fs.existsSync(cliPath)) {
  console.log('flex-mcp-server: postinstall could not find bin/cli.js during npm install.');
  console.log('flex-mcp-server: install finished without auto-registration; run `flex-mcp-server install` after npm completes.');
  process.exit(0);
}

const result = spawnSync(process.execPath, [cliPath, 'install', '--from-postinstall'], {
  stdio: 'inherit',
  shell: false,
});

if (result.error || result.status !== 0) {
  const detail = result.error ? ` ${result.error.message}` : '';
  console.log(`flex-mcp-server: auto-registration did not complete.${detail}`);
  console.log('flex-mcp-server: run `flex-mcp-server install` manually after npm completes.');
}

process.exit(0);
