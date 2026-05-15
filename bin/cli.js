#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn, spawnSync } = require('child_process');

const PKG_ROOT = path.resolve(__dirname, '..');
const SKILLS_ROOT = path.join(PKG_ROOT, 'skills');
const SERVER_PATH = path.join(PKG_ROOT, 'flex_mcp_server.py');
const CLI_PATH = path.join(PKG_ROOT, 'bin', 'cli.js');
const HOME = os.homedir();
const PYTHON = process.env.FLEX_MCP_PYTHON || (process.platform === 'win32' ? 'python' : 'python3');

const AGENTS = {
  'Claude Code': path.join(HOME, '.claude'),
  Codex: path.join(HOME, '.codex'),
  OpenCode: path.join(HOME, '.opencode'),
  Cursor: path.join(HOME, '.cursor'),
  Cline: path.join(HOME, '.cline'),
  'Kiro CLI': path.join(HOME, '.kiro'),
  'GitHub Copilot': path.join(HOME, '.github'),
};

const rawArgs = process.argv.slice(2);
const firstArg = rawArgs[0] || '';
const hasCommand = firstArg && !firstArg.startsWith('-');
const command = hasCommand ? firstArg.toLowerCase() : 'install';
const commandArgs = hasCommand ? rawArgs.slice(1) : rawArgs;

const force = commandArgs.includes('--force') || commandArgs.includes('-f');
const dryRun = commandArgs.includes('--dry-run');
const installClaudeCode = commandArgs.includes('--claude-code');

function printHelp() {
  console.log(`flex-mcp-server

Usage:
  flex-mcp-server install [--force] [--claude-code]
  flex-mcp-server serve [server args...]
  flex-mcp-server config
  flex-mcp-server path
  flex-mcp-server doctor

Commands:
  install        Install bundled skills into detected agent dirs and print MCP config.
  serve          Start the Python MCP server over stdio. Pass server args after serve.
  config         Print the stdio MCP config for this install.
  path           Print the absolute path to flex_mcp_server.py.
  doctor         Check local runtime prerequisites.

Options:
  --force        Overwrite existing installed skill directories.
  --claude-code  Also run: claude mcp add frida-flex flex-mcp-server serve
  --dry-run      Show what would be installed without copying files.

Environment:
  FLEX_MCP_PYTHON  Python command to use for serve/config/doctor. Default: ${PYTHON}
`);
}

function copyDir(src, dst) {
  fs.mkdirSync(dst, { recursive: true });
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    const source = path.join(src, entry.name);
    const target = path.join(dst, entry.name);
    if (entry.isDirectory()) {
      copyDir(source, target);
    } else {
      fs.copyFileSync(source, target);
    }
  }
}

function removeDir(target) {
  if (!fs.existsSync(target)) return;
  fs.rmSync(target, { recursive: true, force: true });
}

function getSkillDirs() {
  if (!fs.existsSync(SKILLS_ROOT)) return [];
  return fs.readdirSync(SKILLS_ROOT, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => ({ name: entry.name, src: path.join(SKILLS_ROOT, entry.name) }));
}

function getMcpConfig() {
  return {
    mcpServers: {
      'frida-flex': {
        command: PYTHON,
        args: [SERVER_PATH],
      },
    },
  };
}

function printMcpConfig() {
  console.log(JSON.stringify(getMcpConfig(), null, 2));
}

function installSkills() {
  const skills = getSkillDirs();
  if (skills.length === 0) {
    console.error('No skill directories found under skills/.');
    process.exit(1);
  }

  console.log(`\nflex-mcp-server: ${dryRun ? 'checking' : 'installing'} ${skills.length} bundled skill(s)\n`);

  let touchedAgents = 0;
  let totalInstalled = 0;
  let totalSkipped = 0;

  for (const [agentName, root] of Object.entries(AGENTS)) {
    if (!fs.existsSync(root)) continue;
    touchedAgents += 1;

    const skillsDir = path.join(root, 'skills');
    if (!dryRun) fs.mkdirSync(skillsDir, { recursive: true });

    let installed = 0;
    let skipped = 0;

    for (const skill of skills) {
      const target = path.join(skillsDir, skill.name);
      if (fs.existsSync(target) && !force) {
        skipped += 1;
        continue;
      }

      if (!dryRun) {
        removeDir(target);
        copyDir(skill.src, target);
      }
      installed += 1;
    }

    if (installed > 0 || skipped > 0) {
      const parts = [];
      if (installed) parts.push(`${dryRun ? 'would_install' : 'installed'}=${installed}`);
      if (skipped) parts.push(`skipped=${skipped}`);
      console.log(`  ${agentName}: ${parts.join(', ')}`);
    }

    totalInstalled += installed;
    totalSkipped += skipped;
  }

  if (touchedAgents === 0) {
    console.log('  No known agent directories were found. Skill install skipped.');
  }

  console.log(`\nDone. ${dryRun ? 'would_install' : 'installed'}=${totalInstalled}, skipped=${totalSkipped}`);
}

function installClaudeCodeMcp() {
  console.log('\nInstalling MCP server into Claude Code...\n');
  const result = spawnSync(
    'claude',
    ['mcp', 'add', 'frida-flex', 'flex-mcp-server', 'serve'],
    { stdio: 'inherit', shell: process.platform === 'win32' },
  );

  if (result.error || result.status !== 0) {
    console.log('\nClaude Code install did not complete.');
    console.log('Run this manually after installing Claude Code:');
    console.log('  claude mcp add frida-flex flex-mcp-server serve');
  }
}

function install() {
  installSkills();

  if (installClaudeCode && !dryRun) {
    installClaudeCodeMcp();
  }

  console.log('\nAdd this to any stdio MCP client config:\n');
  printMcpConfig();
  console.log('\nUseful commands:');
  console.log('  flex-mcp-server serve --transport sse --port 8099');
  console.log('  flex-mcp-server doctor');
  console.log();
}

function serve() {
  if (!fs.existsSync(SERVER_PATH)) {
    console.error(`Server file not found: ${SERVER_PATH}`);
    process.exit(1);
  }

  const child = spawn(PYTHON, [SERVER_PATH, ...commandArgs], {
    stdio: 'inherit',
    shell: process.platform === 'win32',
  });

  child.on('error', (error) => {
    console.error(`Failed to start Python command "${PYTHON}": ${error.message}`);
    console.error('Set FLEX_MCP_PYTHON to the Python executable you want to use.');
    process.exit(1);
  });

  child.on('exit', (code, signal) => {
    if (signal) process.kill(process.pid, signal);
    process.exit(code === null ? 1 : code);
  });
}

function doctor() {
  let ok = true;

  function check(label, passed, detail) {
    console.log(`${passed ? 'OK  ' : 'FAIL'} ${label}${detail ? ` - ${detail}` : ''}`);
    if (!passed) ok = false;
  }

  check('server file', fs.existsSync(SERVER_PATH), SERVER_PATH);
  check('cli file', fs.existsSync(CLI_PATH), CLI_PATH);

  const skills = getSkillDirs();
  check('bundled skills', skills.length > 0, `${skills.length} found`);

  const py = spawnSync(PYTHON, ['-c', 'import sys; print(sys.version.split()[0])'], {
    encoding: 'utf8',
    shell: process.platform === 'win32',
  });
  check('python executable', py.status === 0, PYTHON);
  if (py.status === 0) {
    console.log(`    Python ${py.stdout.trim()}`);
  }

  const packages = spawnSync(PYTHON, ['-c', 'import frida, mcp; print("frida and mcp import OK")'], {
    encoding: 'utf8',
    shell: process.platform === 'win32',
  });
  check('python packages', packages.status === 0, 'requires frida and mcp');
  if (packages.status === 0) {
    console.log(`    ${packages.stdout.trim()}`);
  }

  process.exit(ok ? 0 : 1);
}

if ((command === 'help') || (command !== 'serve' && (rawArgs.includes('--help') || rawArgs.includes('-h')))) {
  printHelp();
  process.exit(0);
}

if (command === 'install') {
  install();
} else if (command === 'serve') {
  serve();
} else if (command === 'config') {
  printMcpConfig();
} else if (command === 'path') {
  process.stdout.write(SERVER_PATH);
} else if (command === 'doctor') {
  doctor();
} else {
  console.error(`Unknown command: ${command}`);
  console.error('Run: flex-mcp-server help');
  process.exit(1);
}
