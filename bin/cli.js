#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn, spawnSync } = require('child_process');

const PKG_ROOT = path.resolve(__dirname, '..');
const SKILLS_ROOT = path.join(PKG_ROOT, 'skills');
const KIT_ROOT = path.join(PKG_ROOT, '.claude');
const SERVER_PATH = path.join(PKG_ROOT, 'frida_mcp_server.py');
const CLI_PATH = path.join(PKG_ROOT, 'bin', 'cli.js');
const HOME = os.homedir();
const APPDATA = process.env.APPDATA || path.join(HOME, 'AppData', 'Roaming');
const XDG_CONFIG_HOME = process.env.XDG_CONFIG_HOME || path.join(HOME, '.config');
const OPENCODE_CONFIG_DIR = path.join(XDG_CONFIG_HOME, 'opencode');
const OPENCODE_LEGACY_DIR = path.join(HOME, '.opencode');
const PYTHON = process.env.FRIDA_MCP_PYTHON || (process.platform === 'win32' ? 'python' : 'python3');
const SERVER_NAME = 'frida';

const AGENTS = {
  'Claude Code': path.join(HOME, '.claude'),
  Codex: path.join(HOME, '.codex'),
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
const noConfig = commandArgs.includes('--no-config');
const noSkills = commandArgs.includes('--no-skills');
const noCommands = commandArgs.includes('--no-commands');
const installClaudeCode = commandArgs.includes('--claude-code');

function printHelp() {
  console.log(`frida-mcp-server

Usage:
  frida-mcp-server install [--force] [--no-config] [--no-skills] [--no-commands] [--claude-code]
  frida-mcp-server register [--claude-code]
  frida-mcp-server serve [server args...]
  frida-mcp-server config
  frida-mcp-server path
  frida-mcp-server doctor

Commands:
  install        Install bundled skills, the orchestration kit (slash commands +
                 subagents, Claude Code), and register MCP configs for detected clients.
  register       Register MCP configs without copying skills.
  serve          Start the Python MCP server over stdio. Pass server args after serve.
  config         Print the stdio MCP config for this install.
  path           Print the absolute path to frida_mcp_server.py.
  doctor         Check local runtime prerequisites.

Options:
  --force        Overwrite existing installed skill directories.
  --no-config    Skip MCP config registration.
  --no-skills    Skip bundled skill installation.
  --no-commands  Skip the orchestration kit (slash commands + subagents).
  --claude-code  Force a Claude Code CLI registration attempt.
  --dry-run      Show what would be installed or configured without writing files.

Environment:
  FRIDA_MCP_PYTHON             Python command used by generated MCP configs. Default: ${PYTHON}
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

function getMcpServerConfig() {
  return {
    command: PYTHON,
    args: [SERVER_PATH],
  };
}

function getMcpConfig() {
  return {
    mcpServers: {
      [SERVER_NAME]: getMcpServerConfig(),
    },
  };
}

function getOpenCodeConfig() {
  return {
    type: 'local',
    command: [PYTHON, SERVER_PATH],
    enabled: true,
  };
}

function printMcpConfig() {
  console.log(JSON.stringify(getMcpConfig(), null, 2));
}

function stripJsonComments(input) {
  let output = '';
  let inString = false;
  let stringQuote = '';
  let escaped = false;

  for (let i = 0; i < input.length; i += 1) {
    const char = input[i];
    const next = input[i + 1];

    if (inString) {
      output += char;
      if (escaped) {
        escaped = false;
      } else if (char === '\\') {
        escaped = true;
      } else if (char === stringQuote) {
        inString = false;
      }
      continue;
    }

    if (char === '"' || char === "'") {
      inString = true;
      stringQuote = char;
      output += char;
      continue;
    }

    if (char === '/' && next === '/') {
      while (i < input.length && input[i] !== '\n') i += 1;
      output += '\n';
      continue;
    }

    if (char === '/' && next === '*') {
      i += 2;
      while (i < input.length && !(input[i] === '*' && input[i + 1] === '/')) i += 1;
      i += 1;
      continue;
    }

    output += char;
  }

  return output;
}

function stripTrailingCommas(input) {
  let output = '';
  let inString = false;
  let stringQuote = '';
  let escaped = false;

  for (let i = 0; i < input.length; i += 1) {
    const char = input[i];

    if (inString) {
      output += char;
      if (escaped) {
        escaped = false;
      } else if (char === '\\') {
        escaped = true;
      } else if (char === stringQuote) {
        inString = false;
      }
      continue;
    }

    if (char === '"' || char === "'") {
      inString = true;
      stringQuote = char;
      output += char;
      continue;
    }

    if (char === ',') {
      let j = i + 1;
      while (j < input.length && /\s/.test(input[j])) j += 1;
      if (input[j] === '}' || input[j] === ']') continue;
    }

    output += char;
  }

  return output;
}

function readJsonLike(filePath) {
  if (!fs.existsSync(filePath)) return {};
  const raw = fs.readFileSync(filePath, 'utf8').trim();
  if (!raw) return {};
  return JSON.parse(stripTrailingCommas(stripJsonComments(raw)));
}

function stableJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function backupFile(filePath) {
  if (!fs.existsSync(filePath)) return null;
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const backupPath = `${filePath}.bak-${stamp}`;
  fs.copyFileSync(filePath, backupPath);
  return backupPath;
}

function writeIfChanged(filePath, content) {
  const previous = fs.existsSync(filePath) ? fs.readFileSync(filePath, 'utf8') : null;
  if (previous === content) return { changed: false, backup: null };
  if (!dryRun) {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    const backup = backupFile(filePath);
    fs.writeFileSync(filePath, content);
    return { changed: true, backup };
  }
  return { changed: true, backup: null };
}

function mergeMcpServersConfig(filePath) {
  const config = readJsonLike(filePath);
  if (!config.mcpServers || typeof config.mcpServers !== 'object') {
    config.mcpServers = {};
  }
  config.mcpServers[SERVER_NAME] = getMcpServerConfig();
  return writeIfChanged(filePath, stableJson(config));
}

function mergeOpenCodeConfig(filePath) {
  const config = readJsonLike(filePath);
  if (!config.mcp || typeof config.mcp !== 'object') {
    config.mcp = {};
  }
  config.mcp[SERVER_NAME] = getOpenCodeConfig();
  return writeIfChanged(filePath, stableJson(config));
}

function tomlString(value) {
  return JSON.stringify(value);
}

function getCodexTomlBlock() {
  return [
    '# frida-mcp-server start',
    `[mcp_servers.${SERVER_NAME}]`,
    `command = ${tomlString(PYTHON)}`,
    `args = [${tomlString(SERVER_PATH)}]`,
    '# frida-mcp-server end',
    '',
  ].join('\n');
}

function mergeCodexToml(filePath) {
  const block = getCodexTomlBlock();
  const content = fs.existsSync(filePath) ? fs.readFileSync(filePath, 'utf8') : '';
  const markerPattern = /# frida-mcp-server start[\s\S]*?# frida-mcp-server end\n?/m;
  const tablePattern = /^\[mcp_servers\.frida\][\s\S]*?(?=^\[|$(?![\s\S]))/m;
  let next;

  if (markerPattern.test(content)) {
    next = content.replace(markerPattern, block);
  } else if (tablePattern.test(content)) {
    next = content.replace(tablePattern, block);
  } else {
    next = `${content.replace(/\s*$/, '')}\n\n${block}`;
  }

  return writeIfChanged(filePath, next);
}

function pathExists(p) {
  try {
    return fs.existsSync(p);
  } catch (_) {
    return false;
  }
}

function commandExists(cmd) {
  const check = process.platform === 'win32' ? 'where' : 'command';
  const args = process.platform === 'win32' ? [cmd] : ['-v', cmd];
  const result = spawnSync(check, args, {
    stdio: 'ignore',
    shell: process.platform !== 'win32',
  });
  return result.status === 0;
}

function isOpenCodeDetected() {
  return pathExists(OPENCODE_CONFIG_DIR) || pathExists(OPENCODE_LEGACY_DIR) || commandExists('opencode');
}

function getSkillTargets() {
  const targets = Object.entries(AGENTS)
    .filter(([, root]) => pathExists(root))
    .map(([agentName, root]) => ({
      agentName,
      skillsDir: path.join(root, 'skills'),
    }));

  if (isOpenCodeDetected()) {
    targets.push({
      agentName: 'OpenCode',
      skillsDir: path.join(OPENCODE_CONFIG_DIR, 'skills'),
    });
  }

  return targets;
}

function installSkills() {
  const skills = getSkillDirs();
  if (skills.length === 0) {
    console.error('No skill directories found under skills/.');
    process.exit(1);
  }

  console.log(`\nfrida-mcp-server: ${dryRun ? 'checking' : 'installing'} ${skills.length} bundled skill(s)\n`);

  let touchedAgents = 0;
  let totalInstalled = 0;
  let totalSkipped = 0;

  for (const { agentName, skillsDir } of getSkillTargets()) {
    touchedAgents += 1;
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

  console.log(`\nSkills done. ${dryRun ? 'would_install' : 'installed'}=${totalInstalled}, skipped=${totalSkipped}`);
}

function copyKitFiles(srcDir, dstDir) {
  // Copy *.md files from a kit subdir into a client dir. Returns [installed, skipped].
  if (!fs.existsSync(srcDir)) return [0, 0];
  let installed = 0;
  let skipped = 0;
  if (!dryRun) fs.mkdirSync(dstDir, { recursive: true });
  for (const entry of fs.readdirSync(srcDir, { withFileTypes: true })) {
    if (!entry.isFile() || !entry.name.endsWith('.md')) continue;
    const target = path.join(dstDir, entry.name);
    if (fs.existsSync(target) && !force) {
      skipped += 1;
      continue;
    }
    if (!dryRun) fs.copyFileSync(path.join(srcDir, entry.name), target);
    installed += 1;
  }
  return [installed, skipped];
}

function getCommandTargets() {
  // Clients that understand markdown slash-commands + subagents. Same .md files,
  // different directory conventions per client.
  const targets = [];
  const claudeRoot = AGENTS['Claude Code'];
  if (installClaudeCode || pathExists(claudeRoot)) {
    targets.push({
      name: 'Claude Code',
      commandsDir: path.join(claudeRoot, 'commands'),
      agentsDir: path.join(claudeRoot, 'agents'),
    });
  }
  if (isOpenCodeDetected()) {
    // OpenCode uses singular command/ and agent/ under its config dir.
    targets.push({
      name: 'OpenCode',
      commandsDir: path.join(OPENCODE_CONFIG_DIR, 'command'),
      agentsDir: path.join(OPENCODE_CONFIG_DIR, 'agent'),
    });
  }
  return targets;
}

function installCommands() {
  const targets = getCommandTargets();
  if (targets.length === 0) {
    console.log('\nOrchestration kit: no command-capable client (Claude Code / OpenCode) detected, skipping.');
    return;
  }

  console.log(`\nfrida-mcp-server: ${dryRun ? 'checking' : 'installing'} orchestration kit (commands + agents)\n`);

  const verb = dryRun ? 'would_install' : 'installed';
  for (const t of targets) {
    const [cmdI, cmdS] = copyKitFiles(path.join(KIT_ROOT, 'commands'), t.commandsDir);
    const [agtI, agtS] = copyKitFiles(path.join(KIT_ROOT, 'agents'), t.agentsDir);
    console.log(`  ${t.name}: commands ${verb}=${cmdI}, skipped=${cmdS}; agents ${verb}=${agtI}, skipped=${agtS}`);
  }
  console.log('  Use /autopilot <bundle_id> (or the autopilot prompt) to drive an autonomous assessment.');
}

function getConfigTargets() {
  const targets = [];

  const claudeDesktopPath = process.platform === 'darwin'
    ? path.join(HOME, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json')
    : process.platform === 'win32'
      ? path.join(APPDATA, 'Claude', 'claude_desktop_config.json')
      : path.join(XDG_CONFIG_HOME, 'Claude', 'claude_desktop_config.json');
  if (pathExists(claudeDesktopPath) || pathExists(path.dirname(claudeDesktopPath))) {
    targets.push({
      name: 'Claude Desktop',
      filePath: claudeDesktopPath,
      kind: 'mcpServersJson',
      register: mergeMcpServersConfig,
    });
  }

  if (pathExists(AGENTS.Cursor)) {
    targets.push({
      name: 'Cursor',
      filePath: path.join(AGENTS.Cursor, 'mcp.json'),
      kind: 'mcpServersJson',
      register: mergeMcpServersConfig,
    });
  }

  if (isOpenCodeDetected()) {
    const existingOpenCodePaths = [
      path.join(OPENCODE_CONFIG_DIR, 'opencode.json'),
      path.join(OPENCODE_CONFIG_DIR, 'opencode.jsonc'),
      path.join(XDG_CONFIG_HOME, 'opencode', 'opencode.jsonc'),
      path.join(APPDATA, 'opencode', 'opencode.json'),
      path.join(APPDATA, 'opencode', 'opencode.jsonc'),
      path.join(OPENCODE_LEGACY_DIR, 'opencode.json'),
      path.join(OPENCODE_LEGACY_DIR, 'opencode.jsonc'),
      path.join(OPENCODE_LEGACY_DIR, 'config.jsonc'),
    ].filter(pathExists);
    const openCodePath = existingOpenCodePaths[0] || path.join(OPENCODE_CONFIG_DIR, 'opencode.json');
    targets.push({
      name: 'OpenCode',
      filePath: openCodePath,
      kind: 'opencodeJsonc',
      register: mergeOpenCodeConfig,
    });
  }

  if (pathExists(AGENTS.Codex)) {
    targets.push({
      name: 'Codex',
      filePath: path.join(AGENTS.Codex, 'config.toml'),
      kind: 'codexToml',
      register: mergeCodexToml,
    });
  }

  return targets;
}

function installClaudeCodeMcp() {
  if (!pathExists(AGENTS['Claude Code']) && !installClaudeCode) {
    return { attempted: false, configured: false, skipped: true, message: 'Claude Code not detected' };
  }

  if (!commandExists('claude')) {
    return {
      attempted: true,
      configured: false,
      skipped: true,
      message: 'claude CLI not found; run: claude mcp add frida frida-mcp-server serve',
    };
  }

  if (dryRun) {
    return {
      attempted: true,
      configured: true,
      message: 'would run: claude mcp add frida frida-mcp-server serve',
    };
  }

  const result = spawnSync(
    'claude',
    ['mcp', 'add', SERVER_NAME, 'frida-mcp-server', 'serve'],
    { encoding: 'utf8', shell: process.platform === 'win32' },
  );

  if (result.error || result.status !== 0) {
    const detail = (result.stderr || result.stdout || result.error?.message || '').trim();
    return {
      attempted: true,
      configured: false,
      skipped: false,
      message: detail || 'Claude Code registration did not complete',
    };
  }

  return { attempted: true, configured: true, skipped: false, message: 'registered with claude mcp add' };
}

function registerMcpConfigs() {
  console.log(`\nfrida-mcp-server: ${dryRun ? 'checking' : 'registering'} MCP configs\n`);

  const targets = getConfigTargets();
  let configured = 0;
  let unchanged = 0;
  let failed = 0;
  let skipped = 0;

  for (const target of targets) {
    try {
      const result = target.register(target.filePath);
      if (result.changed) configured += 1;
      else unchanged += 1;
      const action = result.changed ? (dryRun ? 'would_configure' : 'configured') : 'already_configured';
      console.log(`  ${target.name}: ${action} ${target.filePath}`);
      if (result.backup) console.log(`    backup: ${result.backup}`);
    } catch (error) {
      failed += 1;
      console.log(`  ${target.name}: failed ${target.filePath}`);
      console.log(`    ${error.message}`);
    }
  }

  const claudeResult = installClaudeCodeMcp();
  if (claudeResult.attempted) {
    if (claudeResult.configured) configured += 1;
    else if (claudeResult.skipped) skipped += 1;
    else failed += 1;
    console.log(`  Claude Code: ${claudeResult.configured ? (dryRun ? 'would_configure' : 'configured') : 'skipped'}`);
    console.log(`    ${claudeResult.message}`);
  }

  if (targets.length === 0 && !claudeResult.attempted) {
    console.log('  No supported MCP client config targets were detected.');
  }

  console.log(`\nConfigs done. ${dryRun ? 'would_configure' : 'configured'}=${configured}, unchanged=${unchanged}, skipped=${skipped}, failed=${failed}`);
  return { configured, unchanged, skipped, failed };
}

function install() {
  if (!noSkills) installSkills();
  if (!noCommands) installCommands();
  if (!noConfig) registerMcpConfigs();

  console.log('\nCurrent stdio MCP config:\n');
  printMcpConfig();
  console.log('\nUseful commands:');
  console.log('  frida-mcp-server doctor');
  console.log('  frida-mcp-server serve --transport sse --port 8099');
  console.log();
}

function serve() {
  if (!fs.existsSync(SERVER_PATH)) {
    console.error(`Server file not found: ${SERVER_PATH}`);
    process.exit(1);
  }

  const child = spawn(PYTHON, [SERVER_PATH, ...commandArgs], {
    stdio: 'inherit',
    shell: false,
  });

  child.on('error', (error) => {
    console.error(`Failed to start Python command "${PYTHON}": ${error.message}`);
    console.error('Set FRIDA_MCP_PYTHON to the Python executable you want to use.');
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

  const configTargets = getConfigTargets();
  check('supported config targets', configTargets.length > 0 || pathExists(AGENTS['Claude Code']), `${configTargets.length} file target(s)`);

  const py = spawnSync(PYTHON, ['-c', 'import sys; print(sys.version.split()[0])'], {
    encoding: 'utf8',
    shell: false,
  });
  check('python executable', py.status === 0, PYTHON);
  if (py.status === 0) {
    console.log(`    Python ${py.stdout.trim()}`);
  }

  const packages = spawnSync(PYTHON, ['-c', 'import frida, mcp; print("frida and mcp import OK")'], {
    encoding: 'utf8',
    shell: false,
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
} else if (command === 'register') {
  registerMcpConfigs();
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
  console.error('Run: frida-mcp-server help');
  process.exit(1);
}
