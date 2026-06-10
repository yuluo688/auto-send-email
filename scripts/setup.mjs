import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';

const DEFAULT_DB_NAME = 'auto_send_email';
const CONFIG_PATH = 'wrangler.toml';
const MESSAGES = {
  zh: {
    setupFailed: '配置失败',
    languageQuestion: '请选择语言（直接回车为中文，输入 en 切换英文）',
    bannerTitle: 'Auto Send Email 一键部署向导',
    bannerBody: '将自动配置 D1、设置 Cloudflare 密钥、应用数据库迁移并部署 Worker。',
    dbName: 'D1 数据库名称',
    loginNeeded: '当前还没有登录 Cloudflare Wrangler，接下来会打开浏览器登录。',
    useExistingDb: (name, uuid) => `使用已有 D1 数据库：${name} (${uuid})`,
    createDb: (name) => `D1 数据库 "${name}" 不存在，是否现在创建？`,
    pasteDbId: '粘贴已有的 D1 database_id',
    readDbIdFailed: '无法从 Wrangler 输出中读取 database_id。请手动创建 D1，并把 id 填入 wrangler.toml。',
    createdDb: (name, uuid) => `已创建 D1 数据库：${name} (${uuid})`,
    settingSecret: (name) => `正在设置密钥：${name}`,
    secretDone: (name) => `密钥已设置：${name}`,
    applyingMigrations: '正在应用远程 D1 数据库迁移...',
    deploying: '正在部署 Worker...',
    migrationsDone: '远程 D1 数据库迁移已完成。',
    deployDone: 'Worker 已部署完成。',
    deploymentUrl: (url) => `访问地址：${url}`,
    versionId: (id) => `版本 ID：${id}`,
    done: '完成。打开上方 Worker URL，创建第一个管理员账号，然后在 Settings 中配置发信方式。',
    required: '此项必填。',
    missingFile: (path) => `缺少 ${path}`,
    missingTomlKey: (key) => `wrangler.toml 中找不到 ${key}`,
    commandFailed: (command) => `${command} 执行失败`
  },
  en: {
    setupFailed: 'Setup failed',
    languageQuestion: 'Select language (press Enter for Chinese, type en for English)',
    bannerTitle: 'Auto Send Email one-command setup',
    bannerBody: 'This will configure D1, set Cloudflare secrets, apply migrations, and deploy the Worker.',
    dbName: 'D1 database name',
    loginNeeded: 'You are not logged in to Cloudflare Wrangler yet. A browser login will open now.',
    useExistingDb: (name, uuid) => `Using existing D1 database: ${name} (${uuid})`,
    createDb: (name) => `D1 database "${name}" does not exist. Create it now?`,
    pasteDbId: 'Paste an existing D1 database_id',
    readDbIdFailed: 'Could not read database_id from Wrangler output. Create D1 manually and paste the id into wrangler.toml.',
    createdDb: (name, uuid) => `Created D1 database: ${name} (${uuid})`,
    settingSecret: (name) => `Setting secret: ${name}`,
    secretDone: (name) => `Secret set: ${name}`,
    applyingMigrations: 'Applying remote D1 database migrations...',
    deploying: 'Deploying Worker...',
    migrationsDone: 'Remote D1 database migrations completed.',
    deployDone: 'Worker deployed.',
    deploymentUrl: (url) => `URL: ${url}`,
    versionId: (id) => `Version ID: ${id}`,
    done: 'Done. Open the Worker URL above, create your first admin account, then configure email delivery in Settings.',
    required: 'This value is required.',
    missingFile: (path) => `Missing ${path}`,
    missingTomlKey: (key) => `Could not find ${key} in wrangler.toml`,
    commandFailed: (command) => `${command} failed`
  }
};

const rl = createInterface({ input, output });
let language = 'zh';

main().catch((error) => {
  console.error(`\n${t('setupFailed')}: ${error.message}`);
  process.exit(1);
}).finally(() => rl.close());

async function main() {
  language = await selectLanguage();
  banner();
  ensureFile(CONFIG_PATH);
  ensureCommand('node', ['--version']);
  ensureCommand('npx', ['wrangler', '--version']);

  await ensureCloudflareLogin();

  const dbName = await promptDefault(t('dbName'), getTomlValue('database_name') || DEFAULT_DB_NAME);
  const database = await ensureD1Database(dbName);
  updateWranglerToml({ databaseName: dbName, databaseId: database.uuid });


  const authSecret = randomBytes(48).toString('base64url');

  putSecret('AUTH_SECRET', authSecret);

  console.log(`\n${t('applyingMigrations')}`);
  run('npx', ['wrangler', 'd1', 'migrations', 'apply', dbName, '--remote'], { input: 'y\n' });
  console.log(t('migrationsDone'));

  console.log(`\n${t('deploying')}`);
  const deploy = run('npx', ['wrangler', 'deploy'], { capture: true });
  const deployInfo = parseDeployOutput(`${deploy.stdout}\n${deploy.stderr}`);
  console.log(t('deployDone'));
  if (deployInfo.url) console.log(t('deploymentUrl', deployInfo.url));
  if (deployInfo.versionId) console.log(t('versionId', deployInfo.versionId));

  console.log(`\n${t('done')}`);
}

async function selectLanguage() {
  const answer = await promptDefault(t('languageQuestion'), 'zh');
  return /^en(glish)?$/i.test(answer) ? 'en' : 'zh';
}

function banner() {
  console.log(`\n${t('bannerTitle')}`);
  console.log(`${t('bannerBody')}\n`);
}

async function ensureCloudflareLogin() {
  const result = run('npx', ['wrangler', 'whoami'], { allowFailure: true, capture: true });
  if (result.status === 0) return;

  console.log(t('loginNeeded'));
  run('npx', ['wrangler', 'login'], { inherit: true });
}

async function ensureD1Database(name) {
  const existing = listD1Databases().find((database) => database.name === name);
  if (existing) {
    console.log(t('useExistingDb', name, existing.uuid));
    return existing;
  }

  const answer = await promptDefault(t('createDb', name), 'Y');
  if (!isYes(answer)) {
    const id = await promptRequired(t('pasteDbId'));
    return { name, uuid: id };
  }

  const result = run('npx', ['wrangler', 'd1', 'create', name], { capture: true });
  const uuid = parseDatabaseId(result.stdout);
  if (!uuid) {
    console.log(result.stdout);
    throw new Error(t('readDbIdFailed'));
  }
  console.log(t('createdDb', name, uuid));
  return { name, uuid };
}

function listD1Databases() {
  const result = run('npx', ['wrangler', 'd1', 'list', '--json'], { capture: true, allowFailure: true });
  if (result.status !== 0) return [];
  try {
    const parsed = JSON.parse(result.stdout);
    return Array.isArray(parsed) ? parsed.map((item) => ({ name: item.name, uuid: item.uuid || item.id })) : [];
  } catch {
    return [];
  }
}

function parseDatabaseId(text) {
  const jsonMatch = text.match(/"(?:database_id|uuid|id)"\s*:\s*"([^"]+)"/);
  if (jsonMatch) return jsonMatch[1];

  const tomlMatch = text.match(/database_id\s*=\s*"([^"]+)"/);
  if (tomlMatch) return tomlMatch[1];

  const uuidMatch = text.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i);
  return uuidMatch ? uuidMatch[0] : '';
}

function putSecret(name, value) {
  console.log(t('settingSecret', name));
  run('npx', ['wrangler', 'secret', 'put', name], { input: `${value}\n` });
  console.log(t('secretDone', name));
}

function updateWranglerToml(values) {
  let text = readFileSync(CONFIG_PATH, 'utf8');
  if (values.databaseName) text = replaceTomlValue(text, 'database_name', values.databaseName);
  if (values.databaseId) text = replaceTomlValue(text, 'database_id', values.databaseId);
  writeFileSync(CONFIG_PATH, text);
}

function replaceTomlValue(text, key, value) {
  const escaped = String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  const pattern = new RegExp(`^${key}\\s*=\\s*".*"$`, 'm');
  if (!pattern.test(text)) throw new Error(t('missingTomlKey', key));
  return text.replace(pattern, `${key} = "${escaped}"`);
}

function getTomlValue(key) {
  const text = readFileSync(CONFIG_PATH, 'utf8');
  const match = text.match(new RegExp(`^${key}\\s*=\\s*"([^"]*)"$`, 'm'));
  return match ? match[1] : '';
}

async function promptDefault(question, defaultValue) {
  const answer = await rl.question(`${question} [${defaultValue}]: `);
  return answer.trim() || defaultValue;
}

async function promptRequired(question) {
  while (true) {
    const answer = await rl.question(`${question}: `);
    if (answer.trim()) return answer.trim();
    console.log(t('required'));
  }
}

function ensureFile(path) {
  if (!existsSync(path)) throw new Error(t('missingFile', path));
}

function ensureCommand(command, args) {
  run(command, args, { allowFailure: false, capture: true });
}

function run(command, args, options = {}) {
  const result = spawnSync(commandForPlatform(command), args, {
    encoding: 'utf8',
    input: options.input,
    stdio: options.inherit ? 'inherit' : 'pipe'
  });

  if (!options.inherit && !options.capture && !options.input && result.stderr) process.stderr.write(result.stderr);
  if (!options.allowFailure && result.status !== 0) {
    if (result.stdout) process.stdout.write(result.stdout);
    if (result.stderr) process.stderr.write(result.stderr);
    throw new Error(t('commandFailed', `${command} ${args.join(' ')}`));
  }
  return {
    status: result.status ?? 1,
    stdout: result.stdout || '',
    stderr: result.stderr || ''
  };
}

function commandForPlatform(command) {
  if (process.platform === 'win32' && ['npm', 'npx'].includes(command)) return `${command}.cmd`;
  return command;
}

function parseDeployOutput(text) {
  const urlMatch = text.match(/https:\/\/[^\s]+\.workers\.dev[^\s]*/);
  const versionMatch = text.match(/Current Version ID:\s*([0-9a-f-]+)/i);
  return {
    url: urlMatch ? urlMatch[0] : '',
    versionId: versionMatch ? versionMatch[1] : ''
  };
}

function isYes(value) {
  return /^(y|yes|是|好|确认|确定)$/i.test(String(value).trim());
}

function t(key, ...args) {
  const value = MESSAGES[language][key] || MESSAGES.zh[key];
  return typeof value === 'function' ? value(...args) : value;
}
