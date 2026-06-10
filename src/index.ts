import { connect } from 'cloudflare:sockets';

type Env = {
  DB: D1Database;
  RESEND_API_KEY?: string;
  AUTH_SECRET: string;
  FROM_EMAIL?: string;
  APP_NAME?: string;
  APP_URL?: string;
};

type User = {
  id: number;
  email: string;
  name: string;
  role: 'admin' | 'user';
};

type Setting = {
  key: string;
  value: string;
};

type EmailProvider = 'resend' | 'smtp';
type EmailLanguage = 'zh' | 'en';
type EmailTemplate = 'letter' | 'card' | 'custom';

type EmailSettings = {
  provider: EmailProvider;
  from_email: string;
  resend_api_key: string;
  smtp_host: string;
  smtp_port: number;
  smtp_secure: 'ssl' | 'starttls';
  smtp_username: string;
  smtp_password: string;
  email_language: EmailLanguage;
  email_template: EmailTemplate;
  custom_email_html: string;
};

type UserEmailTemplate = {
  user_id: number;
  email_language: EmailLanguage;
  email_template: EmailTemplate;
  custom_email_html: string;
};

type PublicEmailSettings = Omit<EmailSettings, 'resend_api_key' | 'smtp_password'> & {
  resend_api_key: '';
  smtp_password: '';
  has_resend_api_key: boolean;
  has_smtp_password: boolean;
};

type Reminder = {
  id: number;
  user_id: number;
  title: string;
  message: string;
  recipient_email: string;
  schedule_type: 'once' | 'daily' | 'weekly' | 'monthly';
  time_of_day: string;
  timezone: string;
  day_of_week: number | null;
  day_of_month: number | null;
  once_at: string | null;
  next_run_at: string;
  enabled: number;
  important: number;
  resend_interval_minutes: number;
  confirmation_token: string;
  confirmed_at: string | null;
  last_sent_at: string | null;
  owner_email?: string;
};

const SESSION_COOKIE = 'ase_session';
const PBKDF2_ITERATIONS = 100000;
const WEEKDAY_NAMES = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      return await handleRequest(request, env);
    } catch (error) {
      console.error(error);
      return json({ error: 'Internal server error' }, 500);
    }
  },

  async scheduled(_event: ScheduledEvent, env: Env): Promise<void> {
    await processDueReminders(env);
  }
};

async function handleRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  if (url.protocol === 'http:' && !isLocalHost(url.hostname)) {
    url.protocol = 'https:';
    return Response.redirect(url.toString(), 308);
  }
  const path = url.pathname;

  if (path === '/api/bootstrap' && request.method === 'GET') {
    const count = await getUserCount(env.DB);
    return json({ needsSetup: count === 0 });
  }

  if ((path === '/api/register' || path === '/api/setup') && request.method === 'POST') {
    const secretError = requireAuthSecret(env);
    if (secretError) return secretError;

    const input = await request.json<Partial<{ email: string; name: string; password: string }>>();
    const email = normalizeEmail(input.email);
    const name = String(input.name ?? '').trim();
    const password = String(input.password ?? '');
    if (!email || password.length < 8) return json({ error: 'Email and password with at least 8 characters are required' }, 400);

    const role = (await getUserCount(env.DB)) === 0 ? 'admin' : 'user';
    const hash = await hashPassword(password);
    try {
      const result = await env.DB.prepare('INSERT INTO users (email, name, role, password_hash) VALUES (?, ?, ?, ?)')
        .bind(email, name, role, hash)
        .run();
      const user = { id: Number(result.meta.last_row_id), email, name, role: role as User['role'] };
      return withSession(json({ user }), user, env);
    } catch {
      return json({ error: 'Email is already registered' }, 409);
    }
  }

  if (path === '/api/login' && request.method === 'POST') {
    const secretError = requireAuthSecret(env);
    if (secretError) return secretError;

    const input = await request.json<Partial<{ email: string; password: string }>>();
    const email = normalizeEmail(input.email);
    const password = String(input.password ?? '');
    const row = email ? await env.DB.prepare('SELECT id, email, name, role, password_hash FROM users WHERE email = ?').bind(email).first<User & { password_hash: string }>() : null;
    if (!row || !(await verifyPassword(password, row.password_hash))) return json({ error: 'Invalid email or password' }, 401);
    return withSession(json({ user: publicUser(row) }), publicUser(row), env);
  }

  if (path === '/api/logout' && request.method === 'POST') {
    const response = json({ ok: true });
    response.headers.set('Set-Cookie', `${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax; Secure`);
    return response;
  }

  if (path.startsWith('/api/')) {
    const user = await requireUser(request, env);
    if (!user) return json({ error: 'Unauthorized' }, 401);

    if (path === '/api/me' && request.method === 'GET') return json({ user });

    if (path === '/api/settings' && request.method === 'GET') {
      const settings = await getEmailSettings(env);
      return json({ settings: publicSettings(settings, user.role === 'admin') });
    }

    if (path === '/api/settings' && request.method === 'PUT') {
      if (user.role !== 'admin') return json({ error: 'Forbidden' }, 403);
      const input = await request.json<Partial<Record<keyof EmailSettings, string | number>>>();
      const existing = await getEmailSettings(env);
      const provider = input.provider === 'smtp' ? 'smtp' : 'resend';
      const fromEmail = String(input.from_email ?? '').trim();
      if (!isValidSender(fromEmail)) return json({ error: 'Use sender format: Name <email@example.com>' }, 400);

      const settings: EmailSettings = {
        provider,
        from_email: fromEmail,
        resend_api_key: String(input.resend_api_key ?? '').trim() || existing.resend_api_key,
        smtp_host: String(input.smtp_host ?? '').trim(),
        smtp_port: Number(input.smtp_port || (provider === 'smtp' ? 465 : existing.smtp_port)),
        smtp_secure: input.smtp_secure === 'starttls' ? 'starttls' : 'ssl',
        smtp_username: String(input.smtp_username ?? '').trim(),
        smtp_password: String(input.smtp_password ?? '') || existing.smtp_password,
        email_language: input.email_language === 'en' ? 'en' : input.email_language === 'zh' ? 'zh' : existing.email_language,
        email_template: input.email_template === 'card' ? 'card' : input.email_template === 'custom' ? 'custom' : input.email_template === 'letter' ? 'letter' : existing.email_template,
        custom_email_html: input.custom_email_html == null ? existing.custom_email_html : String(input.custom_email_html).trim()
      };

      const validation = validateEmailSettings(settings);
      if (validation) return json({ error: validation }, 400);

      await setSettings(env.DB, settings);
      return json({ ok: true, settings: publicSettings(await getEmailSettings(env), true) });
    }

    if (path === '/api/template' && request.method === 'GET') {
      const template = await getUserEmailTemplate(env, user.id);
      return json({ template });
    }

    if (path === '/api/template' && request.method === 'PUT') {
      const input = await request.json<Partial<Record<keyof UserEmailTemplate, string | number>>>();
      const template: UserEmailTemplate = {
        user_id: user.id,
        email_language: input.email_language === 'en' ? 'en' : 'zh',
        email_template: input.email_template === 'card' ? 'card' : input.email_template === 'custom' ? 'custom' : 'letter',
        custom_email_html: String(input.custom_email_html ?? '').trim()
      };
      await setUserEmailTemplate(env.DB, template);
      return json({ ok: true, template: await getUserEmailTemplate(env, user.id) });
    }

    if (path === '/api/template/preview' && request.method === 'POST') {
      const input = await request.json<Partial<Record<keyof UserEmailTemplate, string | number>>>();
      const template: UserEmailTemplate = {
        user_id: user.id,
        email_language: input.email_language === 'en' ? 'en' : 'zh',
        email_template: input.email_template === 'card' ? 'card' : input.email_template === 'custom' ? 'custom' : 'letter',
        custom_email_html: String(input.custom_email_html ?? '').trim()
      };
      return json({ html: buildReminderEmailHtml(env, template, sampleReminder(user)), text: buildReminderEmailText(env, template, sampleReminder(user)) });
    }

    if (path === '/api/users' && request.method === 'GET') {
      if (user.role !== 'admin') return json({ error: 'Forbidden' }, 403);
      const rows = await env.DB.prepare('SELECT id, email, name, role FROM users ORDER BY created_at DESC').all<User>();
      return json({ users: rows.results });
    }

    const userMatch = path.match(/^\/api\/users\/(\d+)$/);
    if (userMatch && request.method === 'PUT') {
      if (user.role !== 'admin') return json({ error: 'Forbidden' }, 403);
      const id = Number(userMatch[1]);
      const input = await request.json<Partial<{ role: string }>>();
      const role = input.role === 'admin' ? 'admin' : 'user';
      const target = await env.DB.prepare('SELECT id, role FROM users WHERE id = ?').bind(id).first<Pick<User, 'id' | 'role'>>();
      if (!target) return json({ error: 'User not found' }, 404);
      if (target.role === 'admin' && role === 'user' && (await getAdminCount(env.DB)) <= 1) {
        return json({ error: 'At least one admin is required' }, 400);
      }
      await env.DB.prepare(`UPDATE users SET role = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?`).bind(role, id).run();
      return json({ ok: true });
    }

    if (path === '/api/reminders' && request.method === 'GET') {
      const reminders = await listReminders(env.DB, user);
      return json({ reminders });
    }

    if (path === '/api/reminders' && request.method === 'POST') {
      const input = await request.json<Record<string, unknown>>();
      const ownerId = user.role === 'admin' && input.user_id ? Number(input.user_id) : user.id;
      const reminder = parseReminderInput({ ...input, user_id: ownerId }, ownerId);
      if ('error' in reminder) return json({ error: reminder.error }, 400);
      await createReminder(env.DB, reminder.value);
      return json({ ok: true }, 201);
    }

    const confirmMatch = path.match(/^\/api\/reminders\/(\d+)\/confirm$/);
    if (confirmMatch && request.method === 'POST') {
      const id = Number(confirmMatch[1]);
      const existing = await getReminderForUser(env.DB, id, user);
      if (!existing) return json({ error: 'Reminder not found' }, 404);
      if (!existing.important) return json({ error: 'Only important reminders need confirmation' }, 400);
      await confirmReminder(env.DB, existing, new Date());
      return json({ ok: true });
    }

    const toggleMatch = path.match(/^\/api\/reminders\/(\d+)\/toggle$/);
    if (toggleMatch && request.method === 'POST') {
      const id = Number(toggleMatch[1]);
      const existing = await getReminderForUser(env.DB, id, user);
      if (!existing) return json({ error: 'Reminder not found' }, 404);
      const enabled = existing.enabled ? 0 : 1;
      await env.DB.prepare(`UPDATE reminders SET enabled = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?`)
        .bind(enabled, id)
        .run();
      return json({ ok: true, enabled });
    }

    const reminderMatch = path.match(/^\/api\/reminders\/(\d+)$/);
    if (reminderMatch) {
      const id = Number(reminderMatch[1]);
      const existing = await getReminderForUser(env.DB, id, user);
      if (!existing) return json({ error: 'Reminder not found' }, 404);
      if (request.method === 'PUT') {
        const input = await request.json<Record<string, unknown>>();
        const ownerId = user.role === 'admin' && input.user_id ? Number(input.user_id) : existing.user_id;
        const parsed = parseReminderInput({ ...input, user_id: ownerId }, ownerId);
        if ('error' in parsed) return json({ error: parsed.error }, 400);
        await updateReminder(env.DB, id, parsed.value);
        return json({ ok: true });
      }
      if (request.method === 'DELETE') {
        await env.DB.prepare('DELETE FROM reminders WHERE id = ?').bind(id).run();
        return json({ ok: true });
      }
    }

    if (path === '/api/logs' && request.method === 'GET') {
      const sql = user.role === 'admin'
        ? `SELECT send_logs.*, reminders.title, users.email AS owner_email FROM send_logs JOIN reminders ON reminders.id = send_logs.reminder_id JOIN users ON users.id = send_logs.user_id ORDER BY send_logs.created_at DESC LIMIT 50`
        : `SELECT send_logs.*, reminders.title, users.email AS owner_email FROM send_logs JOIN reminders ON reminders.id = send_logs.reminder_id JOIN users ON users.id = send_logs.user_id WHERE send_logs.user_id = ? ORDER BY send_logs.created_at DESC LIMIT 50`;
      const statement = env.DB.prepare(sql);
      const rows = user.role === 'admin' ? await statement.all() : await statement.bind(user.id).all();
      return json({ logs: rows.results });
    }

    return json({ error: 'Not found' }, 404);
  }

  const publicConfirmMatch = path.match(/^\/confirm\/([a-f0-9-]{20,80})$/i);
  if (publicConfirmMatch && request.method === 'GET') {
    const reminder = await env.DB.prepare('SELECT * FROM reminders WHERE confirmation_token = ?')
      .bind(publicConfirmMatch[1])
      .first<Reminder>();
    if (!reminder || !reminder.important) return html(renderMessagePage(env.APP_NAME || 'Auto Send Email', 'Reminder not found', 'This confirmation link is no longer valid.'));
    await confirmReminder(env.DB, reminder, new Date());
    return html(renderMessagePage(env.APP_NAME || 'Auto Send Email', 'Reminder confirmed', 'You can close this page. This reminder will not be resent for the current occurrence.'));
  }

  return html(renderApp(env.APP_NAME || 'Auto Send Email'));
}

function publicUser(row: User): User {
  return { id: row.id, email: row.email, name: row.name, role: row.role };
}

async function getEmailSettings(env: Env): Promise<EmailSettings> {
  const rows = await env.DB.prepare('SELECT key, value FROM settings').all<Setting>();
  const values = Object.fromEntries(rows.results.map((row) => [row.key, row.value]));
  const provider = values.provider === 'smtp' ? 'smtp' : 'resend';
  return {
    provider,
    from_email: values.from_email || env.FROM_EMAIL || '',
    resend_api_key: values.resend_api_key || env.RESEND_API_KEY || '',
    smtp_host: values.smtp_host || defaultSmtpHost(values.smtp_username || ''),
    smtp_port: Number(values.smtp_port || '465'),
    smtp_secure: values.smtp_secure === 'starttls' ? 'starttls' : 'ssl',
    smtp_username: values.smtp_username || '',
    smtp_password: values.smtp_password || '',
    email_language: values.email_language === 'en' ? 'en' : 'zh',
    email_template: values.email_template === 'card' ? 'card' : values.email_template === 'custom' ? 'custom' : 'letter',
    custom_email_html: values.custom_email_html || ''
  };
}

function publicSettings(settings: EmailSettings, includeAdminFields: boolean): PublicEmailSettings {
  return {
    provider: settings.provider,
    from_email: settings.from_email,
    resend_api_key: '',
    has_resend_api_key: Boolean(settings.resend_api_key),
    smtp_host: includeAdminFields ? settings.smtp_host : '',
    smtp_port: includeAdminFields ? settings.smtp_port : 465,
    smtp_secure: includeAdminFields ? settings.smtp_secure : 'ssl',
    smtp_username: includeAdminFields ? settings.smtp_username : '',
    smtp_password: '',
    has_smtp_password: includeAdminFields && Boolean(settings.smtp_password),
    email_language: includeAdminFields ? settings.email_language : 'zh',
    email_template: includeAdminFields ? settings.email_template : 'letter',
    custom_email_html: includeAdminFields ? settings.custom_email_html : ''
  };
}

async function setSettings(db: D1Database, settings: EmailSettings): Promise<void> {
  const entries: Array<[string, string]> = [
    ['provider', settings.provider],
    ['from_email', settings.from_email],
    ['smtp_host', settings.smtp_host],
    ['smtp_port', String(settings.smtp_port)],
    ['smtp_secure', settings.smtp_secure],
    ['smtp_username', settings.smtp_username],
    ['email_language', settings.email_language],
    ['email_template', settings.email_template],
    ['custom_email_html', settings.custom_email_html]
  ];
  if (settings.resend_api_key) entries.push(['resend_api_key', settings.resend_api_key]);
  if (settings.smtp_password) entries.push(['smtp_password', settings.smtp_password]);
  for (const [key, value] of entries) await setSetting(db, key, value);
}

async function setSetting(db: D1Database, key: string, value: string): Promise<void> {
  await db.prepare(`INSERT INTO settings (key, value, updated_at) VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`)
    .bind(key, value)
    .run();
}

async function getUserEmailTemplate(env: Env, userId: number): Promise<UserEmailTemplate> {
  const row = await env.DB.prepare('SELECT user_id, email_language, email_template, custom_email_html FROM user_email_templates WHERE user_id = ?')
    .bind(userId)
    .first<UserEmailTemplate>();
  if (row) {
    return {
      user_id: userId,
      email_language: row.email_language === 'en' ? 'en' : 'zh',
      email_template: row.email_template === 'card' ? 'card' : row.email_template === 'custom' ? 'custom' : 'letter',
      custom_email_html: row.custom_email_html || ''
    };
  }
  const settings = await getEmailSettings(env);
  return {
    user_id: userId,
    email_language: settings.email_language,
    email_template: settings.email_template,
    custom_email_html: settings.custom_email_html
  };
}

async function setUserEmailTemplate(db: D1Database, template: UserEmailTemplate): Promise<void> {
  await db.prepare(`INSERT INTO user_email_templates (user_id, email_language, email_template, custom_email_html, updated_at)
    VALUES (?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    ON CONFLICT(user_id) DO UPDATE SET email_language = excluded.email_language, email_template = excluded.email_template, custom_email_html = excluded.custom_email_html, updated_at = excluded.updated_at`)
    .bind(template.user_id, template.email_language, template.email_template, template.custom_email_html)
    .run();
}

function isValidSender(value: string): boolean {
  return /^.+ <[^@\s]+@[^@\s]+\.[^@\s]+>$/.test(value);
}

function isLocalHost(hostname: string): boolean {
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '0.0.0.0' || hostname.endsWith('.localhost');
}

function requireAuthSecret(env: Env): Response | null {
  if (String(env.AUTH_SECRET || '').trim()) return null;
  return json({ error: 'AUTH_SECRET is not configured. Run setup again or set the AUTH_SECRET Worker secret.' }, 500);
}

function validateEmailSettings(settings: EmailSettings): string {
  if (settings.provider === 'resend' && !settings.resend_api_key) return 'Resend API key is required';
  if (settings.provider === 'smtp') {
    if (!settings.smtp_host) return 'SMTP host is required';
    if (!Number.isInteger(settings.smtp_port) || settings.smtp_port < 1 || settings.smtp_port > 65535) return 'SMTP port must be between 1 and 65535';
    if (!settings.smtp_username) return 'SMTP username is required';
    if (!settings.smtp_password) return 'SMTP password or authorization code is required';
  }
  return '';
}

async function getUserCount(db: D1Database): Promise<number> {
  const row = await db.prepare('SELECT COUNT(*) AS count FROM users').first<{ count: number }>();
  return Number(row?.count ?? 0);
}

async function getAdminCount(db: D1Database): Promise<number> {
  const row = await db.prepare(`SELECT COUNT(*) AS count FROM users WHERE role = 'admin'`).first<{ count: number }>();
  return Number(row?.count ?? 0);
}

async function requireUser(request: Request, env: Env): Promise<User | null> {
  const token = getCookie(request, SESSION_COOKIE);
  if (!token) return null;
  const payload = await verifySession(token, env.AUTH_SECRET);
  if (!payload) return null;
  const user = await env.DB.prepare('SELECT id, email, name, role FROM users WHERE id = ?').bind(payload.userId).first<User>();
  return user ? publicUser(user) : null;
}

function getCookie(request: Request, name: string): string | null {
  const cookies = request.headers.get('Cookie') || '';
  for (const part of cookies.split(';')) {
    const [key, ...value] = part.trim().split('=');
    if (key === name) return value.join('=');
  }
  return null;
}

async function withSession(response: Response, user: User, env: Env): Promise<Response> {
  const token = await signSession({ userId: user.id, exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30 }, env.AUTH_SECRET);
  response.headers.set('Set-Cookie', `${SESSION_COOKIE}=${token}; Path=/; Max-Age=2592000; HttpOnly; SameSite=Lax; Secure`);
  return response;
}

async function signSession(payload: { userId: number; exp: number }, secret: string): Promise<string> {
  const body = base64UrlEncode(JSON.stringify(payload));
  const signature = await hmac(body, secret);
  return `${body}.${signature}`;
}

async function verifySession(token: string, secret: string): Promise<{ userId: number; exp: number } | null> {
  const [body, signature] = token.split('.');
  if (!body || !signature || (await hmac(body, secret)) !== signature) return null;
  try {
    const payload = JSON.parse(base64UrlDecode(body)) as { userId: number; exp: number };
    if (!payload.userId || payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}

async function hmac(input: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(input));
  return base64UrlEncodeBytes(new Uint8Array(sig));
}

async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await pbkdf2(password, salt, PBKDF2_ITERATIONS);
  return `pbkdf2$${PBKDF2_ITERATIONS}$${base64UrlEncodeBytes(salt)}$${base64UrlEncodeBytes(hash)}`;
}

async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [scheme, iterText, saltText, hashText] = stored.split('$');
  if (scheme !== 'pbkdf2') return false;
  const expected = base64UrlDecodeBytes(hashText);
  const actual = await pbkdf2(password, base64UrlDecodeBytes(saltText), Number(iterText));
  return timingSafeEqual(actual, expected);
}

async function pbkdf2(password: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const saltBuffer = salt.buffer.slice(salt.byteOffset, salt.byteOffset + salt.byteLength) as ArrayBuffer;
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: saltBuffer, iterations }, key, 256);
  return new Uint8Array(bits);
}

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i += 1) out |= a[i] ^ b[i];
  return out === 0;
}

function base64UrlEncode(value: string): string {
  return base64UrlEncodeBytes(new TextEncoder().encode(value));
}

function base64UrlEncodeBytes(bytes: Uint8Array): string {
  let binary = '';
  bytes.forEach((byte) => (binary += String.fromCharCode(byte)));
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(value: string): string {
  return new TextDecoder().decode(base64UrlDecodeBytes(value));
}

function base64UrlDecodeBytes(value: string): Uint8Array {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (value.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

async function listReminders(db: D1Database, user: User): Promise<Reminder[]> {
  const sql = user.role === 'admin'
    ? `SELECT reminders.*, users.email AS owner_email FROM reminders JOIN users ON users.id = reminders.user_id ORDER BY enabled DESC, next_run_at ASC`
    : `SELECT reminders.*, users.email AS owner_email FROM reminders JOIN users ON users.id = reminders.user_id WHERE reminders.user_id = ? ORDER BY enabled DESC, next_run_at ASC`;
  const statement = db.prepare(sql);
  const rows = user.role === 'admin' ? await statement.all<Reminder>() : await statement.bind(user.id).all<Reminder>();
  return rows.results;
}

async function getReminderForUser(db: D1Database, id: number, user: User): Promise<Reminder | null> {
  const sql = user.role === 'admin'
    ? 'SELECT * FROM reminders WHERE id = ?'
    : 'SELECT * FROM reminders WHERE id = ? AND user_id = ?';
  const statement = db.prepare(sql);
  return user.role === 'admin' ? await statement.bind(id).first<Reminder>() : await statement.bind(id, user.id).first<Reminder>();
}

type ReminderInput = Omit<Reminder, 'id' | 'confirmation_token' | 'confirmed_at' | 'last_sent_at' | 'owner_email'>;

function parseReminderInput(input: Record<string, unknown>, defaultUserId: number): { value: ReminderInput } | { error: string } {
  const title = String(input.title ?? '').trim();
  const message = String(input.message ?? '').trim();
  const recipients = parseRecipientEmails(String(input.recipient_email ?? ''));
  const scheduleType = String(input.schedule_type ?? 'daily') as Reminder['schedule_type'];
  const timeOfDay = String(input.time_of_day ?? '').trim();
  const timezone = String(input.timezone ?? 'Asia/Shanghai').trim() || 'Asia/Shanghai';
  const userId = Number(input.user_id || defaultUserId);
  const enabled = input.enabled === false || input.enabled === 0 || input.enabled === '0' ? 0 : 1;
  const important = input.important === true || input.important === 1 || input.important === '1' || input.important === 'on' ? 1 : 0;
  const resendInterval = Math.max(5, Math.min(1440, Number(input.resend_interval_minutes || 30)));

  if (!title) return { error: 'Title is required' };
  if ('error' in recipients) return { error: recipients.error };
  if (!['once', 'daily', 'weekly', 'monthly'].includes(scheduleType)) return { error: 'Invalid schedule type' };
  if (!/^\d{2}:\d{2}$/.test(timeOfDay)) return { error: 'Time must be HH:mm' };

  const rawDayOfWeek = Number(input.day_of_week);
  const rawDayOfMonth = Number(input.day_of_month);
  const dayOfWeek = scheduleType === 'weekly' ? rawDayOfWeek : null;
  const dayOfMonth = scheduleType === 'monthly' ? rawDayOfMonth : null;
  const onceAt = scheduleType === 'once' ? String(input.once_at ?? '') : null;

  if (scheduleType === 'weekly' && (!Number.isInteger(rawDayOfWeek) || rawDayOfWeek < 0 || rawDayOfWeek > 6)) return { error: 'Weekly reminders need a weekday' };
  if (scheduleType === 'monthly' && (!Number.isInteger(rawDayOfMonth) || rawDayOfMonth < 1 || rawDayOfMonth > 31)) return { error: 'Monthly reminders need a day from 1 to 31' };
  if (scheduleType === 'once' && !onceAt) return { error: 'One-time reminders need a date' };

  const nextRunAt = computeNextRunAt({ scheduleType, timeOfDay, timezone, dayOfWeek, dayOfMonth, onceAt }, new Date());
  if (!nextRunAt) return { error: 'Could not compute next run time' };

  return {
    value: {
      user_id: userId,
      title,
      message,
      recipient_email: recipients.value.join(', '),
      schedule_type: scheduleType,
      time_of_day: timeOfDay,
      timezone,
      day_of_week: dayOfWeek,
      day_of_month: dayOfMonth,
      once_at: onceAt,
      next_run_at: nextRunAt,
      enabled,
      important,
      resend_interval_minutes: Number.isFinite(resendInterval) ? resendInterval : 30
    }
  };
}

async function createReminder(db: D1Database, reminder: ReminderInput): Promise<void> {
  await db.prepare(`INSERT INTO reminders (user_id, title, message, recipient_email, schedule_type, time_of_day, timezone, day_of_week, day_of_month, once_at, next_run_at, enabled, important, resend_interval_minutes, confirmation_token) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(
    reminder.user_id,
    reminder.title,
    reminder.message,
    reminder.recipient_email,
    reminder.schedule_type,
    reminder.time_of_day,
    reminder.timezone,
    reminder.day_of_week,
    reminder.day_of_month,
    reminder.once_at,
    reminder.next_run_at,
    reminder.enabled,
    reminder.important,
    reminder.resend_interval_minutes,
    crypto.randomUUID()
  ).run();
}

async function updateReminder(db: D1Database, id: number, reminder: ReminderInput): Promise<void> {
  await db.prepare(`UPDATE reminders SET user_id = ?, title = ?, message = ?, recipient_email = ?, schedule_type = ?, time_of_day = ?, timezone = ?, day_of_week = ?, day_of_month = ?, once_at = ?, next_run_at = ?, enabled = ?, important = ?, resend_interval_minutes = ?, confirmation_token = CASE WHEN confirmation_token = '' THEN ? ELSE confirmation_token END, confirmed_at = NULL, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?`).bind(
    reminder.user_id,
    reminder.title,
    reminder.message,
    reminder.recipient_email,
    reminder.schedule_type,
    reminder.time_of_day,
    reminder.timezone,
    reminder.day_of_week,
    reminder.day_of_month,
    reminder.once_at,
    reminder.next_run_at,
    reminder.enabled,
    reminder.important,
    reminder.resend_interval_minutes,
    crypto.randomUUID(),
    id
  ).run();
}

type ScheduleSpec = {
  scheduleType: Reminder['schedule_type'];
  timeOfDay: string;
  timezone: string;
  dayOfWeek: number | null;
  dayOfMonth: number | null;
  onceAt: string | null;
};

function computeNextRunAt(spec: ScheduleSpec, from: Date): string | null {
  if (spec.scheduleType === 'once') {
    const candidate = localDateTimeToUtc(spec.onceAt || '', spec.timeOfDay, spec.timezone);
    return candidate ? candidate.toISOString() : null;
  }

  for (let offset = 0; offset < 370; offset += 1) {
    const local = getLocalParts(addDays(from, offset), spec.timezone);
    if (spec.scheduleType === 'weekly' && local.weekday !== spec.dayOfWeek) continue;
    if (spec.scheduleType === 'monthly' && local.day !== spec.dayOfMonth) continue;
    const date = `${local.year}-${pad(local.month)}-${pad(local.day)}`;
    const candidate = localDateTimeToUtc(date, spec.timeOfDay, spec.timezone);
    if (candidate && candidate.getTime() > from.getTime()) return candidate.toISOString();
  }
  return null;
}

function localDateTimeToUtc(dateText: string, timeText: string, timezone: string): Date | null {
  const match = dateText.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  const time = timeText.match(/^(\d{2}):(\d{2})$/);
  if (!match || !time) return null;
  const desired = {
    year: Number(match[1]),
    month: Number(match[2]),
    day: Number(match[3]),
    hour: Number(time[1]),
    minute: Number(time[2])
  };
  let utc = Date.UTC(desired.year, desired.month - 1, desired.day, desired.hour, desired.minute);
  for (let i = 0; i < 4; i += 1) {
    const parts = getLocalParts(new Date(utc), timezone);
    const diffMinutes = ((parts.year - desired.year) * 525600) + ((parts.month - desired.month) * 43200) + ((parts.day - desired.day) * 1440) + ((parts.hour - desired.hour) * 60) + (parts.minute - desired.minute);
    if (diffMinutes === 0) break;
    utc -= diffMinutes * 60000;
  }
  return new Date(utc);
}

function getLocalParts(date: Date, timezone: string): { year: number; month: number; day: number; hour: number; minute: number; weekday: number } {
  const formatter = new Intl.DateTimeFormat('en-US', {
    timeZone: timezone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
    weekday: 'short'
  });
  const parts = Object.fromEntries(formatter.formatToParts(date).map((part) => [part.type, part.value]));
  return {
    year: Number(parts.year),
    month: Number(parts.month),
    day: Number(parts.day),
    hour: Number(parts.hour),
    minute: Number(parts.minute),
    weekday: WEEKDAY_NAMES.indexOf(parts.weekday)
  };
}

function addDays(date: Date, days: number): Date {
  return new Date(date.getTime() + days * 86400000);
}

function addMinutes(date: Date, minutes: number): Date {
  return new Date(date.getTime() + minutes * 60000);
}

function pad(value: number): string {
  return String(value).padStart(2, '0');
}

async function processDueReminders(env: Env): Promise<void> {
  const now = new Date();
  const rows = await env.DB.prepare(`SELECT reminders.*, users.email AS owner_email FROM reminders JOIN users ON users.id = reminders.user_id WHERE reminders.enabled = 1 AND reminders.next_run_at <= ? ORDER BY reminders.next_run_at ASC LIMIT 25`)
    .bind(now.toISOString())
    .all<Reminder>();

  for (const reminder of rows.results) {
    await sendOneReminder(env, reminder, now);
  }
}

async function sendOneReminder(env: Env, reminder: Reminder, now: Date): Promise<void> {
  const settings = await getEmailSettings(env);
  if (!isValidSender(settings.from_email)) {
    await env.DB.prepare('INSERT INTO send_logs (reminder_id, user_id, status, response) VALUES (?, ?, ?, ?)')
      .bind(reminder.id, reminder.user_id, 'failed', 'Missing verified sender. Set From email in Settings.')
      .run();
    return;
  }

  const template = await getUserEmailTemplate(env, reminder.user_id);
  const result = await sendEmail(settings, {
    to: recipientListForReminder(reminder),
    subject: reminder.title,
    text: buildReminderEmailText(env, template, reminder),
    html: buildReminderEmailHtml(env, template, reminder)
  });
  const status = result.ok ? 'sent' : 'failed';
  await env.DB.prepare('INSERT INTO send_logs (reminder_id, user_id, status, response) VALUES (?, ?, ?, ?)')
    .bind(reminder.id, reminder.user_id, status, result.response.slice(0, 1000))
    .run();

  if (!result.ok) return;

  if (reminder.important) {
    const interval = Math.max(5, Math.min(1440, Number(reminder.resend_interval_minutes || 30)));
    await env.DB.prepare('UPDATE reminders SET next_run_at = ?, confirmed_at = NULL, last_sent_at = ?, updated_at = strftime(\'%Y-%m-%dT%H:%M:%fZ\', \'now\') WHERE id = ?')
      .bind(addMinutes(now, interval).toISOString(), now.toISOString(), reminder.id)
      .run();
    return;
  }

  const nextRunAt = computeNextRunAt({
    scheduleType: reminder.schedule_type,
    timeOfDay: reminder.time_of_day,
    timezone: reminder.timezone,
    dayOfWeek: reminder.day_of_week,
    dayOfMonth: reminder.day_of_month,
    onceAt: reminder.once_at
  }, new Date(now.getTime() + 1000));

  if (reminder.schedule_type === 'once' || !nextRunAt) {
    await env.DB.prepare('UPDATE reminders SET enabled = 0, last_sent_at = ?, updated_at = strftime(\'%Y-%m-%dT%H:%M:%fZ\', \'now\') WHERE id = ?')
      .bind(now.toISOString(), reminder.id)
      .run();
  } else {
    await env.DB.prepare('UPDATE reminders SET next_run_at = ?, last_sent_at = ?, updated_at = strftime(\'%Y-%m-%dT%H:%M:%fZ\', \'now\') WHERE id = ?')
      .bind(nextRunAt, now.toISOString(), reminder.id)
      .run();
  }
}

function buildReminderEmailText(env: Env, template: Pick<UserEmailTemplate, 'email_language'>, reminder: Reminder): string {
  const copy = emailCopy(template.email_language);
  const lines = [reminder.message || reminder.title];
  if (reminder.important) {
    lines.push('');
    lines.push(copy.importantText(reminder.resend_interval_minutes || 30));
    const baseUrl = String(env.APP_URL || '').replace(/\/+$/, '');
    if (baseUrl && reminder.confirmation_token) lines.push(`${baseUrl}/confirm/${reminder.confirmation_token}`);
    else lines.push(copy.openApp);
  }
  return lines.join('\n');
}

function buildReminderEmailHtml(env: Env, template: Pick<UserEmailTemplate, 'email_language' | 'email_template' | 'custom_email_html'>, reminder: Reminder): string {
  const baseUrl = String(env.APP_URL || '').replace(/\/+$/, '');
  const confirmUrl = reminder.important && baseUrl && reminder.confirmation_token ? `${baseUrl}/confirm/${reminder.confirmation_token}` : '';
  const copy = emailCopy(template.email_language);
  const message = reminder.message || reminder.title;
  const schedule = emailScheduleLabel(reminder, template.email_language);
  const data = {
    app_name: 'Auto Send Email',
    title: reminder.title,
    message,
    schedule,
    confirm_url: confirmUrl,
    confirm_button: confirmUrl ? emailButton(confirmUrl, copy.confirm) : '',
    important_notice: reminder.important ? emailNotice(copy.importantHtml(reminder.resend_interval_minutes || 30)) : '',
    footer: copy.footer
  };
  if (template.email_template === 'custom' && template.custom_email_html.trim()) return renderCustomEmailTemplate(template.custom_email_html, data);
  return template.email_template === 'card' ? renderCardEmail(data, copy) : renderLetterEmail(data, copy);
}

function emailCopy(lang: EmailLanguage) {
  return lang === 'en'
    ? {
      preheader: 'A reminder from Auto Send Email.',
      schedule: 'Schedule',
      confirm: 'Confirm reminder',
      footer: 'You received this because a reminder was scheduled in Auto Send Email.',
      openApp: 'Open the reminder app and confirm this reminder.',
      importantText: (minutes: number) => `This is an important reminder. Confirm it to stop follow-up emails for this occurrence. It will resend every ${minutes} minutes until confirmed.`,
      importantHtml: (minutes: number) => `This important reminder will be sent again every ${minutes} minutes until you confirm it.`
    }
    : {
      preheader: '来自 Auto Send Email 的提醒。',
      schedule: '提醒时间',
      confirm: '确认提醒',
      footer: '你收到这封邮件，是因为你在 Auto Send Email 中创建了提醒。',
      openApp: '打开提醒应用并确认这条提醒。',
      importantText: (minutes: number) => `这是一条重要提醒。确认后，本次提醒将停止重复发送。未确认前每 ${minutes} 分钟重发一次。`,
      importantHtml: (minutes: number) => `这条重要提醒会每 ${minutes} 分钟重复发送，直到你确认它。`
    };
}

function emailScheduleLabel(reminder: Reminder, lang: EmailLanguage): string {
  if (lang === 'zh') {
    if (reminder.schedule_type === 'once') return `一次性 · ${reminder.once_at || ''} ${reminder.time_of_day} · ${reminder.timezone}`;
    if (reminder.schedule_type === 'weekly') return `每周 · ${WEEKDAY_NAMES[Number(reminder.day_of_week)] || '-'} ${reminder.time_of_day} · ${reminder.timezone}`;
    if (reminder.schedule_type === 'monthly') return `每月 · ${reminder.day_of_month || '-'} 日 ${reminder.time_of_day} · ${reminder.timezone}`;
    return `每天 · ${reminder.time_of_day} · ${reminder.timezone}`;
  }
  if (reminder.schedule_type === 'once') return `One time · ${reminder.once_at || ''} ${reminder.time_of_day} · ${reminder.timezone}`;
  if (reminder.schedule_type === 'weekly') return `Weekly · ${WEEKDAY_NAMES[Number(reminder.day_of_week)] || '-'} ${reminder.time_of_day} · ${reminder.timezone}`;
  if (reminder.schedule_type === 'monthly') return `Monthly · day ${reminder.day_of_month || '-'} ${reminder.time_of_day} · ${reminder.timezone}`;
  return `Daily · ${reminder.time_of_day} · ${reminder.timezone}`;
}

function sampleReminder(user: User): Reminder {
  return {
    id: 0,
    user_id: user.id,
    title: user.role === 'admin' ? '测试提醒' : '重要事项提醒',
    message: '这是一封模板预览邮件。你可以切换语言、选择样式，或使用自定义 HTML 调整邮件外观。',
    recipient_email: user.email,
    schedule_type: 'once',
    time_of_day: '09:00',
    timezone: 'Asia/Shanghai',
    day_of_week: null,
    day_of_month: null,
    once_at: '2026-06-10',
    next_run_at: '2026-06-10T01:00:00.000Z',
    enabled: 1,
    important: 1,
    resend_interval_minutes: 30,
    confirmation_token: 'preview-token',
    confirmed_at: null,
    last_sent_at: null,
    owner_email: user.email
  };
}

function renderLetterEmail(data: Record<string, string>, copy: ReturnType<typeof emailCopy>): string {
  return emailShell(copy.preheader,
    '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:680px; background:#fffefa;">' +
    '<tr><td style="padding:34px 30px 18px; border-bottom:1px solid #e8e1d7;">' +
      '<div style="font-size:12px; color:#817a70; letter-spacing:.08em; text-transform:uppercase; margin-bottom:16px;">' + escHtml(data.app_name) + '</div>' +
      '<h1 style="margin:0; color:#22201c; font-size:28px; line-height:1.25; font-weight:700;">' + escHtml(data.title) + '</h1>' +
    '</td></tr>' +
    '<tr><td style="padding:28px 30px 8px;"><div style="white-space:pre-wrap; font-size:16px; line-height:1.8; color:#3e3a33;">' + escHtml(data.message) + '</div></td></tr>' +
    '<tr><td style="padding:18px 30px;"><div style="border-left:3px solid #7f927f; padding:2px 0 2px 14px; color:#817a70; font-size:13px; line-height:1.6;"><strong style="display:block; color:#22201c; margin-bottom:3px;">' + escHtml(copy.schedule) + '</strong>' + escHtml(data.schedule) + '</div></td></tr>' +
    data.important_notice +
    (data.confirm_button ? '<tr><td style="padding:4px 30px 30px;">' + data.confirm_button + '</td></tr>' : '') +
    '<tr><td style="padding:18px 30px 30px; color:#aaa298; font-size:12px; line-height:1.6; border-top:1px solid #e8e1d7;">' + escHtml(data.footer) + '</td></tr>' +
    '</table>');
}

function renderCardEmail(data: Record<string, string>, copy: ReturnType<typeof emailCopy>): string {
  return emailShell(copy.preheader,
    '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:640px; background:#fffefa; border:1px solid #e8e1d7; border-radius:18px; overflow:hidden;">' +
    '<tr><td style="padding:30px 30px 22px; background:#f7f5ef;">' +
      '<div style="font-size:12px; color:#817a70; margin-bottom:14px;">' + escHtml(data.app_name) + '</div>' +
      '<h1 style="margin:0; color:#22201c; font-size:30px; line-height:1.22; font-weight:750;">' + escHtml(data.title) + '</h1>' +
    '</td></tr>' +
    '<tr><td style="padding:28px 30px 12px;"><div style="white-space:pre-wrap; font-size:16px; line-height:1.75; color:#3e3a33;">' + escHtml(data.message) + '</div></td></tr>' +
    '<tr><td style="padding:12px 30px;"><div style="background:#f7f5ef; border-radius:12px; padding:14px 16px; font-size:13px; line-height:1.6; color:#817a70;"><strong style="display:block; color:#22201c; margin-bottom:3px;">' + escHtml(copy.schedule) + '</strong>' + escHtml(data.schedule) + '</div></td></tr>' +
    data.important_notice +
    (data.confirm_button ? '<tr><td style="padding:6px 30px 30px;">' + data.confirm_button + '</td></tr>' : '') +
    '<tr><td style="padding:18px 30px 28px; color:#aaa298; font-size:12px; line-height:1.6; border-top:1px solid #e8e1d7;">' + escHtml(data.footer) + '</td></tr>' +
    '</table>');
}

function emailShell(preheader: string, content: string): string {
  return '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>' +
    '<body style="margin:0; padding:0; background:#fbfaf7; font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif; color:#3e3a33;">' +
    '<div style="display:none; max-height:0; overflow:hidden; opacity:0;">' + escHtml(preheader) + '</div>' +
    '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#fbfaf7; padding:28px 16px;"><tr><td align="center">' + content + '</td></tr></table>' +
    '</body></html>';
}

function emailNotice(value: string): string {
  return '<tr><td style="padding:6px 30px 18px;"><div style="border:1px solid #edd2cc; background:#fbefec; color:#7c382f; border-radius:12px; padding:13px 15px; font-size:14px; line-height:1.6;">' + escHtml(value) + '</div></td></tr>';
}

function emailButton(url: string, label: string): string {
  return '<a href="' + escHtml(url) + '" style="display:inline-block; background:#22201c; color:#fffefa; text-decoration:none; border-radius:999px; padding:12px 20px; font-weight:700; font-size:14px;">' + escHtml(label) + '</a>';
}

function renderCustomEmailTemplate(template: string, data: Record<string, string>): string {
  const trustedHtml = new Set(['confirm_button', 'important_notice']);
  return template.replace(/\{\{\s*([a-z_]+)\s*\}\}/g, (_match, key) => {
    if (!(key in data)) return '';
    return trustedHtml.has(key) ? data[key] : escHtml(data[key]).replace(/\n/g, '<br>');
  });
}

function escHtml(value: unknown): string {
  return String(value == null ? '' : value).replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char] || char));
}

async function confirmReminder(db: D1Database, reminder: Reminder, now: Date): Promise<void> {
  const nextRunAt = computeNextRunAt({
    scheduleType: reminder.schedule_type,
    timeOfDay: reminder.time_of_day,
    timezone: reminder.timezone,
    dayOfWeek: reminder.day_of_week,
    dayOfMonth: reminder.day_of_month,
    onceAt: reminder.once_at
  }, new Date(now.getTime() + 1000));

  if (reminder.schedule_type === 'once' || !nextRunAt) {
    await db.prepare('UPDATE reminders SET enabled = 0, confirmed_at = ?, updated_at = strftime(\'%Y-%m-%dT%H:%M:%fZ\', \'now\') WHERE id = ?')
      .bind(now.toISOString(), reminder.id)
      .run();
  } else {
    await db.prepare('UPDATE reminders SET next_run_at = ?, confirmed_at = ?, updated_at = strftime(\'%Y-%m-%dT%H:%M:%fZ\', \'now\') WHERE id = ?')
      .bind(nextRunAt, now.toISOString(), reminder.id)
      .run();
  }
}

type OutgoingEmail = { to: string[]; subject: string; text: string; html: string };

async function sendEmail(settings: EmailSettings, message: OutgoingEmail): Promise<{ ok: boolean; response: string }> {
  const validation = validateEmailSettings(settings);
  if (validation) return { ok: false, response: validation };
  if (!message.to.length) return { ok: false, response: 'Recipient email is invalid' };
  if (settings.provider === 'smtp') return sendViaSmtp(settings, message);
  return sendViaResend(settings, message);
}

async function sendViaResend(settings: EmailSettings, message: OutgoingEmail): Promise<{ ok: boolean; response: string }> {
  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${settings.resend_api_key}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      from: settings.from_email,
      to: message.to,
      subject: message.subject,
      text: message.text,
      html: message.html
    })
  });
  return { ok: response.ok, response: await response.text() };
}

async function sendViaSmtp(settings: EmailSettings, message: OutgoingEmail): Promise<{ ok: boolean; response: string }> {
  const fromAddress = extractSenderAddress(settings.from_email);
  if (!fromAddress) return { ok: false, response: 'From email is invalid' };

  let socket = connect(
    { hostname: settings.smtp_host, port: settings.smtp_port },
    { secureTransport: settings.smtp_secure === 'ssl' ? 'on' : 'starttls', allowHalfOpen: false }
  );
  await socket.opened;

  let reader = socket.readable.getReader();
  let writer = socket.writable.getWriter();
  let buffer = '';

  const close = async () => {
    try { writer.releaseLock(); } catch {}
    try { reader.releaseLock(); } catch {}
    try { await socket.close(); } catch {}
  };

  try {
    await expectSmtp(reader, (value) => (buffer = value), () => buffer, 220);
    await smtpCommand(writer, reader, (value) => (buffer = value), () => buffer, `EHLO ${smtpClientName()}`, 250);

    if (settings.smtp_secure === 'starttls') {
      await smtpCommand(writer, reader, (value) => (buffer = value), () => buffer, 'STARTTLS', 220);
      writer.releaseLock();
      reader.releaseLock();
      socket = socket.startTls();
      await socket.opened;
      reader = socket.readable.getReader();
      writer = socket.writable.getWriter();
      buffer = '';
      await smtpCommand(writer, reader, (value) => (buffer = value), () => buffer, `EHLO ${smtpClientName()}`, 250);
    }

    await smtpCommand(writer, reader, (value) => (buffer = value), () => buffer, 'AUTH LOGIN', 334);
    await smtpCommand(writer, reader, (value) => (buffer = value), () => buffer, smtpBase64(settings.smtp_username), 334);
    await smtpCommand(writer, reader, (value) => (buffer = value), () => buffer, smtpBase64(settings.smtp_password), 235);
    await smtpCommand(writer, reader, (value) => (buffer = value), () => buffer, `MAIL FROM:<${fromAddress}>`, 250);
    for (const recipient of message.to) {
      await smtpCommand(writer, reader, (value) => (buffer = value), () => buffer, `RCPT TO:<${recipient}>`, [250, 251]);
    }
    await smtpCommand(writer, reader, (value) => (buffer = value), () => buffer, 'DATA', 354);
    await smtpWrite(writer, buildSmtpMessage(settings.from_email, message));
    const dataResponse = await expectSmtp(reader, (value) => (buffer = value), () => buffer, 250);
    await smtpCommand(writer, reader, (value) => (buffer = value), () => buffer, 'QUIT', 221).catch(() => undefined);
    return { ok: true, response: dataResponse.text };
  } catch (error) {
    return { ok: false, response: error instanceof Error ? error.message : String(error) };
  } finally {
    await close();
  }
}

async function smtpCommand(
  writer: WritableStreamDefaultWriter<Uint8Array>,
  reader: ReadableStreamDefaultReader<Uint8Array>,
  setBuffer: (value: string) => void,
  getBuffer: () => string,
  command: string,
  expected: number | number[]
): Promise<{ code: number; text: string }> {
  await smtpWrite(writer, `${command}\r\n`);
  return expectSmtp(reader, setBuffer, getBuffer, expected);
}

async function smtpWrite(writer: WritableStreamDefaultWriter<Uint8Array>, text: string): Promise<void> {
  await writer.write(new TextEncoder().encode(text));
}

async function expectSmtp(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  setBuffer: (value: string) => void,
  getBuffer: () => string,
  expected: number | number[]
): Promise<{ code: number; text: string }> {
  const expectedCodes = Array.isArray(expected) ? expected : [expected];
  const decoder = new TextDecoder();
  while (true) {
    const parsed = parseSmtpResponse(getBuffer());
    if (parsed) {
      setBuffer(parsed.rest);
      if (!expectedCodes.includes(parsed.code)) throw new Error(`SMTP expected ${expectedCodes.join('/')} but got ${parsed.text}`);
      return { code: parsed.code, text: parsed.text };
    }
    const chunk = await reader.read();
    if (chunk.done) throw new Error('SMTP connection closed');
    setBuffer(getBuffer() + decoder.decode(chunk.value, { stream: true }));
  }
}

function parseSmtpResponse(buffer: string): { code: number; text: string; rest: string } | null {
  const lines = buffer.split(/\r?\n/);
  const consumed: string[] = [];
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    if (i === lines.length - 1 && !buffer.endsWith('\n')) return null;
    consumed.push(line);
    const match = line.match(/^(\d{3})([ -])(.*)$/);
    if (match && match[2] === ' ') {
      return {
        code: Number(match[1]),
        text: consumed.join('\n'),
        rest: lines.slice(i + 1).join('\n')
      };
    }
  }
  return null;
}

function buildSmtpMessage(from: string, message: OutgoingEmail): string {
  const date = new Date().toUTCString();
  const boundary = `ase-${crypto.randomUUID()}`;
  const textBody = normalizeSmtpBody(message.text || message.subject);
  const htmlBody = normalizeSmtpBody(message.html || escHtml(message.text || message.subject));
  return [
    `From: ${sanitizeHeader(from)}`,
    `To: ${sanitizeHeader(message.to.join(', '))}`,
    `Subject: ${encodeMimeHeader(message.subject)}`,
    `Date: ${date}`,
    'MIME-Version: 1.0',
    `Content-Type: multipart/alternative; boundary="${boundary}"`,
    '',
    `--${boundary}`,
    'Content-Type: text/plain; charset=UTF-8',
    'Content-Transfer-Encoding: 8bit',
    '',
    textBody,
    `--${boundary}`,
    'Content-Type: text/html; charset=UTF-8',
    'Content-Transfer-Encoding: 8bit',
    '',
    htmlBody,
    `--${boundary}--`,
    '.',
    ''
  ].join('\r\n');
}

function normalizeSmtpBody(value: string): string {
  return String(value).replace(/\r?\n/g, '\r\n').split('\r\n').map((line) => line.startsWith('.') ? `.${line}` : line).join('\r\n');
}

function sanitizeHeader(value: string): string {
  return String(value).replace(/[\r\n]+/g, ' ').trim();
}

function encodeMimeHeader(value: string): string {
  const clean = sanitizeHeader(value);
  return /^[\x20-\x7e]*$/.test(clean) ? clean : `=?UTF-8?B?${smtpBase64(clean)}?=`;
}

function smtpBase64(value: string): string {
  let binary = '';
  new TextEncoder().encode(value).forEach((byte) => (binary += String.fromCharCode(byte)));
  return btoa(binary);
}

function extractSenderAddress(value: string): string {
  const match = value.match(/<([^@\s]+@[^@\s]+\.[^@\s]+)>$/);
  return match ? match[1] : '';
}

function parseRecipientEmails(value: string): { value: string[] } | { error: string } {
  const raw = String(value || '').split(/[\s,;，；]+/).map((item) => item.trim()).filter(Boolean);
  const emails = Array.from(new Set(raw.map((item) => normalizeEmail(item))));
  if (raw.length !== emails.length || emails.some((email) => !email)) return { error: 'Recipient email is invalid' };
  if (emails.length > 20) return { error: 'At most 20 recipients are allowed' };
  return { value: emails };
}

function recipientListForReminder(reminder: Reminder): string[] {
  const custom = parseRecipientEmails(reminder.recipient_email);
  if (!('error' in custom) && custom.value.length) return custom.value;
  const owner = normalizeEmail(reminder.owner_email);
  return owner ? [owner] : [];
}

function smtpClientName(): string {
  return 'auto-send-email.local';
}

function defaultSmtpHost(username: string): string {
  const domain = username.split('@')[1]?.toLowerCase() || '';
  if (domain === 'qq.com') return 'smtp.qq.com';
  if (domain === '163.com') return 'smtp.163.com';
  if (domain === '126.com') return 'smtp.126.com';
  if (domain === 'yeah.net') return 'smtp.yeah.net';
  return '';
}

function normalizeEmail(value: unknown): string {
  const email = String(value ?? '').trim().toLowerCase();
  return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) ? email : '';
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8' }
  });
}

function html(content: string): Response {
  return new Response(content, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}

function renderApp(appName: string): string {
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(appName)}</title>
  <style>${styles()}</style>
</head>
<body>
  <main id="app"></main>
  <script>${clientScript()}</script>
</body>
</html>`;
}

function renderMessagePage(appName: string, title: string, message: string): string {
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)} · ${escapeHtml(appName)}</title>
  <style>${styles()}</style>
</head>
<body>
  <main class="auth">
    <section class="auth-hero">
      <div class="brand"><div class="brand-mark"><svg class="svg-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M4 6.5h16v11H4z"></path><path d="m4 7 8 6 8-6"></path></svg></div><div><h1>${escapeHtml(appName)}</h1><p>${escapeHtml(message)}</p></div></div>
      <h1>${escapeHtml(title)}</h1>
      <p>${escapeHtml(message)}</p>
    </section>
  </main>
</body>
</html>`;
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char] || char));
}

function styles(): string {
  return `
:root {
  color-scheme: light;
  --bg: #fbfaf7;
  --paper: #fffefa;
  --surface: #ffffff;
  --surface-soft: #f7f5ef;
  --ink: #22201c;
  --text: #3e3a33;
  --muted: #817a70;
  --faint: #aaa298;
  --line: #e8e1d7;
  --line-strong: #d7cbbd;
  --sage: #7f927f;
  --sage-strong: #5d735f;
  --sage-soft: #edf2eb;
  --rose: #b56d63;
  --rose-soft: #fbefec;
  --amber: #9d7540;
  --amber-soft: #f9f1e4;
  --ok: #5d735f;
  --shadow: 0 18px 50px rgba(70, 58, 42, .08);
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
  font-size: 15px;
}
body:before {
  content: "";
  position: fixed;
  inset: 0;
  pointer-events: none;
  background:
    linear-gradient(90deg, rgba(34, 32, 28, .035) 1px, transparent 1px),
    linear-gradient(180deg, rgba(34, 32, 28, .025) 1px, transparent 1px);
  background-size: 56px 56px;
  mask-image: linear-gradient(180deg, rgba(0,0,0,.75), transparent 70%);
}
button, input, textarea, select { font: inherit; }
button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  min-height: 40px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--surface);
  color: var(--text);
  padding: 0 14px;
  cursor: pointer;
  font-weight: 650;
  transition: background .18s ease, border-color .18s ease, color .18s ease, transform .18s ease;
}
button:hover { border-color: var(--line-strong); background: var(--paper); transform: translateY(-1px); }
button.primary { background: var(--ink); border-color: var(--ink); color: #fffefa; }
button.primary:hover { background: #35312a; border-color: #35312a; }
button.danger { color: var(--rose); background: var(--rose-soft); border-color: #edd2cc; }
button:disabled { cursor: not-allowed; opacity: .6; }
input, textarea, select {
  width: 100%;
  min-height: 44px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: #fffefa;
  color: var(--text);
  padding: 10px 12px;
  outline: none;
  transition: border-color .18s ease, box-shadow .18s ease, background .18s ease;
}
input:focus, textarea:focus, select:focus { border-color: var(--sage); background: #ffffff; box-shadow: 0 0 0 3px rgba(127, 146, 127, .16); }
input[type="checkbox"] { width: 17px; height: 17px; min-height: 0; padding: 0; margin: 0 8px 0 0; vertical-align: -3px; accent-color: var(--sage-strong); }
textarea { min-height: 132px; resize: vertical; line-height: 1.65; }
label { display: grid; gap: 7px; color: #5f574d; font-size: 12px; font-weight: 700; }
.app-shell { position: relative; width: min(1360px, 100%); margin: 0 auto; padding: 26px 32px 64px; }
.topbar { display: flex; align-items: center; justify-content: space-between; gap: 16px 22px; flex-wrap: wrap; margin-bottom: 42px; padding-bottom: 18px; border-bottom: 1px solid var(--line); }
.brand { display: flex; gap: 12px; align-items: center; min-width: 230px; flex: 0 0 auto; }
.brand-mark { width: 34px; height: 34px; display: grid; place-items: center; border-radius: 50%; background: var(--ink); color: #fffefa; flex: 0 0 auto; }
.brand h1 { margin: 0; font-size: 17px; line-height: 1.2; letter-spacing: 0; color: var(--ink); }
.brand p { margin: 3px 0 0; color: var(--muted); line-height: 1.4; font-size: 12px; }
.svg-icon { width: 16px; height: 16px; display: inline-block; flex: 0 0 auto; stroke: currentColor; fill: none; stroke-width: 1.9; stroke-linecap: round; stroke-linejoin: round; }
.brand-mark .svg-icon { width: 18px; height: 18px; }
.userline { display: inline-flex; align-items: center; justify-content: flex-end; gap: 8px; color: var(--muted); white-space: nowrap; flex: 0 1 auto; min-width: 0; }
.language-control { display: inline-flex; align-items: center; gap: 8px; color: var(--muted); font-size: 12px; font-weight: 700; }
.userline .language-control { border: 1px solid var(--line); border-radius: 999px; background: rgba(255,254,250,.82); padding: 4px 4px 4px 12px; }
.auth-brand .language-control { display: inline-flex; }
.user-pill { max-width: 210px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: inline-flex; align-items: center; gap: 7px; border: 1px solid var(--line); border-radius: 999px; background: rgba(255,254,250,.82); padding: 8px 11px; color: var(--text); font-size: 12px; }
.lang-select { width: auto; min-height: 34px; border-radius: 999px; padding: 7px 30px 7px 12px; }
.userline button { border-radius: 999px; background: rgba(255,254,250,.82); }
.tabs { display: inline-flex; align-items: center; justify-content: center; gap: 2px; padding: 4px; border: 1px solid var(--line); border-radius: 999px; background: rgba(255,254,250,.82); max-width: 100%; flex: 1 1 360px; overflow: visible; flex-wrap: wrap; }
.tab { min-height: 34px; border: 0; border-radius: 999px; background: transparent; color: var(--muted); white-space: nowrap; padding: 0 13px; }
.tab:hover { background: var(--surface-soft); color: var(--ink); transform: none; }
.tab.active { background: var(--ink); color: #fffefa; }
.hero { display: grid; grid-template-columns: minmax(0, 1fr) 320px; gap: 28px; align-items: end; margin-bottom: 26px; }
.hero-copy { min-height: 0; padding: 6px 0 24px; border-bottom: 1px solid var(--line); }
.hero-copy h2 { margin: 0; max-width: 640px; color: var(--ink); font-size: clamp(38px, 6vw, 76px); font-weight: 650; line-height: 1.02; letter-spacing: 0; }
.hero-copy p { margin: 18px 0 0; max-width: 560px; color: var(--muted); font-size: 16px; line-height: 1.8; }
.hero-stats { display: flex; flex-wrap: wrap; gap: 9px; margin-top: 28px; }
.stat-pill { display: inline-flex; align-items: center; gap: 8px; min-height: 34px; padding: 0 12px; border-radius: 999px; background: #fffefa; border: 1px solid var(--line); color: var(--text); font-weight: 650; font-size: 13px; }
.stat-pill span { color: var(--sage-strong); }
.side-card, .compose-card, .reminder-list, .panel { background: rgba(255,254,250,.88); border: 1px solid var(--line); border-radius: 8px; box-shadow: none; }
.side-card { padding: 20px; display: grid; align-content: start; gap: 16px; }
.side-card h3, .compose-card h2, .reminder-list h2, .panel h2 { margin: 0; color: var(--ink); letter-spacing: 0; }
.section-head { display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-bottom: 18px; }
.section-head p { margin: 5px 0 0; color: var(--muted); font-size: 13px; line-height: 1.45; }
.home-grid { display: grid; grid-template-columns: minmax(0, 1fr) 320px; gap: 28px; align-items: start; }
.main-stack { display: grid; gap: 22px; min-width: 0; }
.compose-card { padding: 24px; }
.compose-card.editing { border-color: rgba(181, 109, 99, .42); background: rgba(255, 252, 247, .96); }
.composer-top { display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-bottom: 20px; }
.composer-title { display: flex; align-items: center; gap: 12px; }
.composer-icon { width: 36px; height: 36px; border-radius: 50%; display: grid; place-items: center; background: var(--sage-soft); color: var(--sage-strong); flex: 0 0 auto; }
.compose-card.editing .composer-icon { background: var(--rose-soft); color: var(--rose); }
.composer-icon .svg-icon { width: 17px; height: 17px; }
.form-grid { display: grid; gap: 15px; }
.form-grid.compact { gap: 12px; }
.row { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
.row.three { grid-template-columns: 1fr 1fr 1.1fr; }
.inline-setting { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; padding: 12px 0; border-top: 1px solid var(--line); border-bottom: 1px solid var(--line); }
.inline-setting label { display: inline-flex; align-items: center; gap: 8px; }
.interval-field { width: min(220px, 100%); }
.recipient-row { display: grid; grid-template-columns: minmax(0, 1fr); }
.recipient-row textarea { min-height: 76px; }
.template-field textarea { min-height: 220px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 13px; }
.template-layout { display: grid; grid-template-columns: minmax(0, 1fr) minmax(320px, 520px); gap: 22px; align-items: start; }
.preview-frame { width: 100%; height: 620px; border: 1px solid var(--line); border-radius: 8px; background: #fbfaf7; }
.preview-actions { display: flex; justify-content: flex-end; margin-top: 12px; }
.modal-backdrop { position: fixed; inset: 0; z-index: 30; display: grid; place-items: center; padding: 24px; background: rgba(34,32,28,.28); backdrop-filter: blur(10px); }
.modal { width: min(820px, 100%); max-height: min(90vh, 940px); overflow: auto; background: #fffefa; border: 1px solid var(--line); border-radius: 12px; box-shadow: 0 24px 70px rgba(34, 32, 28, .18); padding: 24px; }
.modal .compose-card { border: 0; padding: 0; background: transparent; }
.modal-close { width: 38px; min-height: 38px; padding: 0; border-radius: 50%; }
.form-note { color: var(--muted); font-size: 12px; line-height: 1.5; margin-top: -6px; }
.actions { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
.reminder-list { padding: 22px; }
.list-tools { display: flex; gap: 10px; align-items: center; color: var(--muted); font-size: 13px; }
.list { display: grid; gap: 0; border-top: 1px solid var(--line); background: transparent; }
.item { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 18px; padding: 18px 0; background: transparent; border-bottom: 1px solid var(--line); }
.item:last-child { border-bottom: 0; }
.item:hover { background: rgba(247, 245, 239, .55); }
.item-main { min-width: 0; display: grid; gap: 7px; }
.item-title-row { display: flex; align-items: center; gap: 10px; min-width: 0; }
.item-dot { width: 22px; height: 22px; border-radius: 50%; background: var(--sage-soft); color: var(--sage-strong); flex: 0 0 auto; display: grid; place-items: center; }
.item-dot .svg-icon { width: 12px; height: 12px; stroke-width: 2.2; }
.item-title { font-weight: 700; color: var(--ink); word-break: break-word; font-size: 16px; line-height: 1.35; }
.item-message { color: var(--muted); font-size: 13px; line-height: 1.55; word-break: break-word; }
.item-meta { display: flex; flex-wrap: wrap; gap: 8px 14px; color: var(--muted); font-size: 13px; }
.item-actions { display: flex; align-items: center; gap: 8px; }
.timeline { position: relative; display: grid; gap: 0; padding-left: 15px; }
.timeline:before { content: ""; position: absolute; left: 21px; top: 9px; bottom: 9px; width: 2px; background: var(--line); }
.timeline-item { position: relative; display: grid; grid-template-columns: 24px 1fr; gap: 12px; padding: 0 0 22px; }
.timeline-item:last-child { padding-bottom: 0; }
.timeline-dot { width: 18px; height: 18px; margin-top: 3px; border-radius: 50%; background: #fffefa; color: var(--sage-strong); border: 1px solid var(--sage); z-index: 1; display: grid; place-items: center; }
.timeline-dot .svg-icon { width: 10px; height: 10px; stroke-width: 2.4; }
.timeline-title { color: var(--ink); font-weight: 700; line-height: 1.35; }
.timeline-meta { margin-top: 4px; color: var(--muted); font-size: 13px; line-height: 1.5; }
.promise-card { margin-top: 22px; padding: 20px 0 0; border-top: 1px solid var(--line); }
.promise-card strong { display: block; color: var(--ink); font-size: 17px; margin-bottom: 8px; }
.promise-card p { margin: 0; color: var(--muted); line-height: 1.65; }
.panel { padding: 24px; }
.account-grid { display: grid; gap: 22px; }
.table-wrap { overflow-x: auto; border-top: 1px solid var(--line); background: transparent; }
.table { width: 100%; border-collapse: separate; border-spacing: 0; background: transparent; }
.table th, .table td { text-align: left; border-bottom: 1px solid var(--line); padding: 14px 16px; font-size: 14px; vertical-align: middle; }
.table th { color: var(--muted); font-weight: 700; background: transparent; }
.table tr:last-child td { border-bottom: 0; }
.table tr:hover td { background: rgba(247, 245, 239, .55); }
.meta { color: var(--muted); font-size: 13px; line-height: 1.55; }
.badge { display: inline-flex; align-items: center; min-height: 24px; padding: 2px 9px; border-radius: 999px; background: var(--surface-soft); color: var(--muted); font-size: 12px; font-weight: 700; white-space: nowrap; }
.badge.ok { background: var(--sage-soft); color: var(--ok); }
.badge.warn { background: var(--amber-soft); color: var(--amber); }
.badge.important { background: var(--rose-soft); color: var(--rose); }
.notice { border: 1px dashed var(--line-strong); background: rgba(247,245,239,.72); border-radius: 8px; padding: 24px; color: var(--muted); text-align: center; }
.error { color: var(--rose); font-size: 13px; min-height: 18px; }
.auth { min-height: 100vh; display: grid; grid-template-columns: minmax(0, 1fr) minmax(340px, 430px); gap: 72px; align-items: center; padding: 54px max(28px, calc((100vw - 1120px) / 2)); background: var(--bg); }
.auth-hero { max-width: 650px; }
.auth-hero h1 { margin: 48px 0 18px; color: var(--ink); font-size: clamp(44px, 7vw, 84px); font-weight: 650; line-height: 1.02; letter-spacing: 0; }
.auth-hero .brand h1 { margin: 0; font-size: 17px; line-height: 1.2; font-weight: 650; }
.auth-hero p { margin: 0; max-width: 520px; color: var(--muted); font-size: 17px; line-height: 1.85; }
.auth .panel { width: 100%; padding: 28px; box-shadow: var(--shadow); background: rgba(255,254,250,.92); }
.auth .panel h2 { font-size: 28px; margin: 8px 0 8px; font-weight: 650; }
.auth-brand { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 18px; }
.auth-wordmark { display: flex; align-items: center; gap: 10px; font-weight: 700; }
.hidden { display: none !important; }
@media (max-width: 840px) {
  .app-shell { padding: 18px 14px 38px; }
  .topbar { align-items: flex-start; }
  .brand, .tabs, .userline { width: 100%; }
  .tabs { justify-content: flex-start; border-radius: 14px; }
  .userline { justify-content: flex-start; flex-wrap: wrap; border-radius: 8px; }
  .hero, .home-grid, .auth { grid-template-columns: 1fr; }
  .template-layout { grid-template-columns: 1fr; }
  .preview-frame { height: 520px; }
  .hero { align-items: start; gap: 18px; }
  .hero-copy { padding: 0 0 22px; min-height: auto; }
  .hero-copy h2 { font-size: 42px; }
  .row.three,
  .row { grid-template-columns: 1fr; }
  .item { grid-template-columns: 1fr; }
  .auth { padding: 24px; gap: 24px; }
  .auth-hero h1 { font-size: 42px; }
}
`;
}

function clientScript(): string {
  return `
const state = {
  user: null,
  needsSetup: false,
  reminders: [],
  users: [],
  logs: [],
  settings: defaultSettings(),
  template: defaultTemplate(),
  tab: 'reminders',
  authMode: 'login',
  composing: false,
  editing: null,
  busy: {},
  lang: localStorage.getItem('ase_lang') === 'en' ? 'en' : 'zh'
};

const app = document.getElementById('app');

const I18N = {
  zh: {
    tagline: '把重要的事，准时送到邮箱里',
    heroTitle: '把重要的事交给邮箱',
    heroSubtitle: '设定一次或重复提醒，我们会在正确的时间把它稳稳送到你的邮箱。',
    greeting: '今天想提醒什么？',
    greetingHint: '写下内容，选好时间，剩下的交给邮箱。',
    editing: '编辑中',
    editingHint: '正在修改这条提醒，保存后会重新计算下次发送时间。',
    remindMe: '提醒我',
    recipient: '收件人',
    recipientEmail: '收件邮箱',
    recipientHint: '留空时发送给提醒所属账号；多个邮箱可用逗号、分号、空格或换行分隔，最多 20 个。',
    whenSend: '什么时候发送？',
    deliveryToInbox: '发送到邮箱',
    myReminders: '我的提醒',
    upcomingDelivery: '即将送达',
    deliveryPromiseTitle: '邮件准时送达，安心每一天',
    deliveryPromise: '每条提醒都会按你设置的时间发送到邮箱，适合生日、账单、复盘、学习和生活小事。',
    activeReminders: '启用中',
    nextDelivery: '下一封',
    noUpcoming: '暂无即将送达的提醒。',
    accountAndPrefs: '账户与偏好',
    language: '语言',
    logout: '退出登录',
    tabReminders: '提醒',
    tabTemplate: '邮件模板',
    tabUsers: '用户',
    tabSettings: '设置',
    tabLogs: '日志',
    createFirstAccount: '创建第一个账号',
    createAccount: '创建账号',
    login: '登录',
    firstAccountAdmin: '第一个账号会自动成为管理员。',
    registerHelper: '注册后即可添加提醒。',
    loginHelper: '登录后管理你的提醒。',
    email: '邮箱',
    name: '姓名',
    password: '密码',
    useExistingAccount: '使用已有账号',
    createNewAccount: '创建新账号',
    newReminder: '新建提醒',
    editReminder: '编辑提醒',
    owner: '所属用户',
    title: '标题',
    message: '内容',
    type: '类型',
    time: '时间',
    date: '日期',
    timezone: '时区',
    weekday: '星期',
    monthDay: '每月日期',
    enabled: '启用',
    importantReminder: '重要提醒，需要确认',
    important: '重要',
    resendEvery: '未确认时每隔多少分钟重发',
    resendEveryShort: (item) => '每 ' + item.resend_interval_minutes + ' 分钟重发',
    requiresConfirmation: '发送后需要确认',
    pendingConfirmation: '等待确认',
    confirmedAt: '已确认',
    confirmReminder: '确认',
    save: '保存',
    saveChanges: '保存修改',
    cancelEdit: '取消编辑',
    clear: '清空',
    reminders: '提醒',
    noReminders: '暂无提醒。',
    startNewReminder: '新建提醒',
    noMessage: '无内容',
    paused: '已暂停',
    pause: '暂停',
    resume: '启用',
    next: '下次',
    edit: '编辑',
    delete: '删除',
    deleteReminderConfirm: '确定删除这个提醒？',
    role: '角色',
    user: '普通用户',
    admin: '管理员',
    users: '用户',
    saveRole: '保存角色',
    emailSettings: '邮件设置',
    provider: '发信方式',
    resendApi: 'Resend API',
    smtpMailbox: 'SMTP 邮箱',
    fromEmail: '发件人',
    emailLanguage: '邮件语言',
    emailLanguageZh: '中文',
    emailLanguageEn: 'English',
    emailTemplate: '邮件模板',
    emailTemplateLetter: '信笺风格',
    emailTemplateCard: '卡片风格',
    emailTemplateCustom: '自定义 HTML',
    customEmailHtml: '自定义邮件 HTML',
    customEmailHelp: '支持占位符：{{app_name}}、{{title}}、{{message}}、{{schedule}}、{{important_notice}}、{{confirm_button}}、{{confirm_url}}、{{footer}}。留空时请不要选择自定义模板。',
    emailTemplateTitle: '邮件模板',
    emailTemplateSubtitle: '选择提醒邮件的语言与外观。这个设置只影响你自己的提醒邮件。',
    emailPreview: '邮件预览',
    refreshPreview: '刷新预览',
    saveTemplate: '保存模板',
    templateSaved: '模板已保存。',
    close: '关闭',
    resendApiKey: 'Resend API Key',
    existingResendKey: '已保存 API Key，留空则保持不变。',
    pasteResendKey: '填写 Resend API Key。',
    smtpHost: 'SMTP 主机',
    smtpPort: 'SMTP 端口',
    encryption: '加密方式',
    smtpUsername: 'SMTP 账号',
    smtpPassword: 'SMTP 密码 / 授权码',
    existingSmtpPassword: '已保存密码，留空则保持不变。',
    smtpPasswordHint: '请使用邮箱 SMTP 授权码，不要使用登录密码。',
    smtpHelp: 'QQ、163 等邮箱通常需要先在邮箱安全设置中开启 SMTP，并生成授权码。',
    saveSettings: '保存设置',
    recentSends: '最近发送',
    reminder: '提醒',
    status: '状态',
    response: '响应',
    sent: '已发送',
    failed: '失败',
    noLogs: '暂无发送日志。',
    once: '一次性',
    daily: '每天',
    weekly: '每周',
    monthly: '每月',
    sunday: '周日',
    monday: '周一',
    tuesday: '周二',
    wednesday: '周三',
    thursday: '周四',
    friday: '周五',
    saturday: '周六',
    onceSchedule: (item) => '一次性：' + item.once_at + ' ' + item.time_of_day + ' ' + item.timezone,
    weeklySchedule: (item) => '每周' + weekdayName(item.day_of_week) + ' ' + item.time_of_day + ' ' + item.timezone,
    monthlySchedule: (item) => '每月 ' + item.day_of_month + ' 日 ' + item.time_of_day + ' ' + item.timezone,
    dailySchedule: (item) => '每天 ' + item.time_of_day + ' ' + item.timezone,
    requestFailed: '请求失败',
    invalidCredentials: '邮箱或密码错误',
    duplicateEmail: '该邮箱已注册',
    atLeastOneAdmin: '至少需要保留一个管理员',
    userNotFound: '用户不存在',
    authSecretMissing: 'AUTH_SECRET 未配置，请重新运行部署向导或设置 Worker secret。',
    loginRequired: '请先登录'
  },
  en: {
    tagline: 'Gentle email reminders for the things that matter',
    heroTitle: 'Put important things in your inbox',
    heroSubtitle: 'Create one-time or repeating reminders, and we will deliver them to your email at the right time.',
    greeting: 'What should we remind you about?',
    greetingHint: 'Write the reminder, choose a time, and let email handle the rest.',
    editing: 'Editing',
    editingHint: 'You are editing this reminder. Saving will recalculate the next send time.',
    remindMe: 'Remind me',
    recipient: 'Recipient',
    recipientEmail: 'Recipient emails',
    recipientHint: 'Leave blank to send to the reminder owner. Separate multiple emails with commas, semicolons, spaces, or new lines. Up to 20 recipients.',
    whenSend: 'When should it send?',
    deliveryToInbox: 'Deliver to inbox',
    myReminders: 'My reminders',
    upcomingDelivery: 'Coming up',
    deliveryPromiseTitle: 'Email reminders that arrive on time',
    deliveryPromise: 'Each reminder is sent to your inbox at the time you choose, useful for birthdays, bills, reviews, study, and daily routines.',
    activeReminders: 'Active',
    nextDelivery: 'Next email',
    noUpcoming: 'No upcoming reminders yet.',
    accountAndPrefs: 'Account and preferences',
    language: 'Language',
    logout: 'Log out',
    tabReminders: 'Reminders',
    tabTemplate: 'Email template',
    tabUsers: 'Users',
    tabSettings: 'Settings',
    tabLogs: 'Logs',
    createFirstAccount: 'Create first account',
    createAccount: 'Create account',
    login: 'Log in',
    firstAccountAdmin: 'The first account becomes the admin.',
    registerHelper: 'Register and start adding reminders.',
    loginHelper: 'Log in to manage your reminders.',
    email: 'Email',
    name: 'Name',
    password: 'Password',
    useExistingAccount: 'Use existing account',
    createNewAccount: 'Create new account',
    newReminder: 'New reminder',
    editReminder: 'Edit reminder',
    owner: 'Owner',
    title: 'Title',
    message: 'Message',
    type: 'Type',
    time: 'Time',
    date: 'Date',
    timezone: 'Timezone',
    weekday: 'Weekday',
    monthDay: 'Month day',
    enabled: 'Enabled',
    importantReminder: 'Important reminder, require confirmation',
    important: 'Important',
    resendEvery: 'Resend every N minutes until confirmed',
    resendEveryShort: (item) => 'resends every ' + item.resend_interval_minutes + ' min',
    requiresConfirmation: 'Requires confirmation after sending',
    pendingConfirmation: 'Waiting for confirmation',
    confirmedAt: 'Confirmed',
    confirmReminder: 'Confirm',
    save: 'Save',
    saveChanges: 'Save changes',
    cancelEdit: 'Cancel edit',
    clear: 'Clear',
    reminders: 'Reminders',
    noReminders: 'No reminders yet.',
    startNewReminder: 'New reminder',
    noMessage: 'No message',
    paused: 'Paused',
    pause: 'Pause',
    resume: 'Enable',
    next: 'Next',
    edit: 'Edit',
    delete: 'Delete',
    deleteReminderConfirm: 'Delete this reminder?',
    role: 'Role',
    user: 'User',
    admin: 'Admin',
    users: 'Users',
    saveRole: 'Save role',
    emailSettings: 'Email settings',
    provider: 'Provider',
    resendApi: 'Resend API',
    smtpMailbox: 'SMTP mailbox',
    fromEmail: 'From email',
    emailLanguage: 'Email language',
    emailLanguageZh: '中文',
    emailLanguageEn: 'English',
    emailTemplate: 'Email template',
    emailTemplateLetter: 'Letter',
    emailTemplateCard: 'Card',
    emailTemplateCustom: 'Custom HTML',
    customEmailHtml: 'Custom email HTML',
    customEmailHelp: 'Available placeholders: {{app_name}}, {{title}}, {{message}}, {{schedule}}, {{important_notice}}, {{confirm_button}}, {{confirm_url}}, {{footer}}. Do not select Custom unless this field is filled.',
    emailTemplateTitle: 'Email template',
    emailTemplateSubtitle: 'Choose the language and visual style for your reminder emails. This setting only affects your own reminders.',
    emailPreview: 'Email preview',
    refreshPreview: 'Refresh preview',
    saveTemplate: 'Save template',
    templateSaved: 'Template saved.',
    close: 'Close',
    resendApiKey: 'Resend API key',
    existingResendKey: 'Existing API key saved. Leave blank to keep it.',
    pasteResendKey: 'Paste your Resend API key.',
    smtpHost: 'SMTP host',
    smtpPort: 'SMTP port',
    encryption: 'Encryption',
    smtpUsername: 'SMTP username',
    smtpPassword: 'SMTP password / auth code',
    existingSmtpPassword: 'Existing password saved. Leave blank to keep it.',
    smtpPasswordHint: 'Use the mailbox SMTP authorization code, not the login password.',
    smtpHelp: 'QQ, 163 and similar mailboxes usually require SMTP to be enabled and an authorization code to be generated in the mailbox security settings.',
    saveSettings: 'Save settings',
    recentSends: 'Recent sends',
    reminder: 'Reminder',
    status: 'Status',
    response: 'Response',
    sent: 'Sent',
    failed: 'Failed',
    noLogs: 'No send logs yet.',
    once: 'One time',
    daily: 'Daily',
    weekly: 'Weekly',
    monthly: 'Monthly',
    sunday: 'Sunday',
    monday: 'Monday',
    tuesday: 'Tuesday',
    wednesday: 'Wednesday',
    thursday: 'Thursday',
    friday: 'Friday',
    saturday: 'Saturday',
    onceSchedule: (item) => 'One time at ' + item.once_at + ' ' + item.time_of_day + ' ' + item.timezone,
    weeklySchedule: (item) => 'Weekly on ' + weekdayName(item.day_of_week) + ' at ' + item.time_of_day + ' ' + item.timezone,
    monthlySchedule: (item) => 'Monthly on day ' + item.day_of_month + ' at ' + item.time_of_day + ' ' + item.timezone,
    dailySchedule: (item) => 'Daily at ' + item.time_of_day + ' ' + item.timezone,
    requestFailed: 'Request failed',
    invalidCredentials: 'Invalid email or password',
    duplicateEmail: 'Email is already registered',
    atLeastOneAdmin: 'At least one admin is required',
    userNotFound: 'User not found',
    authSecretMissing: 'AUTH_SECRET is not configured. Run setup again or set the AUTH_SECRET Worker secret.',
    loginRequired: 'Please log in first'
  }
};

init();

async function init() {
  const boot = await api('/api/bootstrap');
  state.needsSetup = boot.needsSetup;
  if (!state.needsSetup) {
    try {
      const me = await api('/api/me');
      state.user = me.user;
      await loadAll();
    } catch (_) {}
  }
  render();
}

async function loadAll() {
  const reminders = await api('/api/reminders');
  state.reminders = reminders.reminders || [];
  const logs = await api('/api/logs');
  state.logs = logs.logs || [];
  const settings = await api('/api/settings');
  state.settings = Object.assign(defaultSettings(), settings.settings || {});
  const template = await api('/api/template');
  state.template = Object.assign(defaultTemplate(), template.template || {});
  if (state.user && state.user.role === 'admin') {
    const users = await api('/api/users');
    state.users = users.users || [];
  } else {
    state.users = [];
  }
}

function defaultTemplate() {
  return {
    email_language: 'zh',
    email_template: 'letter',
    custom_email_html: ''
  };
}

async function api(path, options) {
  const response = await fetch(path, Object.assign({ headers: { 'Content-Type': 'application/json' } }, options || {}));
  const text = await response.text();
  const data = text ? JSON.parse(text) : {};
  if (!response.ok) throw new Error(localizeError(data.error || 'Request failed'));
  return data;
}

async function runOnce(key, target, task) {
  state.busy = state.busy || {};
  if (state.busy[key]) return;
  state.busy[key] = true;
  const scope = target ? target.closest('form') : null;
  const controls = target ? Array.from(new Set([target, ...Array.from(scope ? scope.querySelectorAll('button') : [])])) : [];
  controls.forEach((control) => control.disabled = true);
  try {
    await task();
  } finally {
    delete state.busy[key];
    controls.forEach((control) => control.disabled = false);
  }
}

function icon(name, className) {
  const paths = {
    logo: '<path d="M4 6.5h16v11H4z"></path><path d="m4 7 8 6 8-6"></path><path d="M8.5 16.5h7"></path>',
    bell: '<path d="M6.5 10.5a5.5 5.5 0 0 1 11 0c0 4 1.5 5.2 1.5 5.2H5s1.5-1.2 1.5-5.2"></path><path d="M9.8 18a2.4 2.4 0 0 0 4.4 0"></path>',
    logs: '<path d="M7 7h10"></path><path d="M7 12h10"></path><path d="M7 17h6"></path><path d="M4 5.5v13"></path>',
    template: '<path d="M5 4.5h14v15H5z"></path><path d="M8 8h8"></path><path d="M8 12h8"></path><path d="M8 16h5"></path>',
    users: '<path d="M8.5 11a3 3 0 1 0 0-6 3 3 0 0 0 0 6"></path><path d="M3.5 19a5 5 0 0 1 10 0"></path><path d="M16 8a2.5 2.5 0 0 1 0 5"></path><path d="M17 15a4 4 0 0 1 3.5 4"></path>',
    settings: '<path d="M12 15.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7"></path><path d="M19 12a7.6 7.6 0 0 0-.1-1.1l2-1.5-2-3.5-2.4 1a7.8 7.8 0 0 0-1.9-1.1L14.3 3h-4.6l-.4 2.8a7.8 7.8 0 0 0-1.9 1.1l-2.4-1-2 3.5 2 1.5A7.6 7.6 0 0 0 5 12c0 .4 0 .8.1 1.1l-2 1.5 2 3.5 2.4-1c.6.5 1.2.8 1.9 1.1l.4 2.8h4.6l.4-2.8c.7-.3 1.3-.6 1.9-1.1l2.4 1 2-3.5-2-1.5c.1-.3.1-.7.1-1.1"></path>',
    mail: '<path d="M4 6.5h16v11H4z"></path><path d="m4 7 8 6 8-6"></path>',
    user: '<path d="M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8"></path><path d="M4.5 20a7.5 7.5 0 0 1 15 0"></path>',
    logout: '<path d="M9 5H5.5A1.5 1.5 0 0 0 4 6.5v11A1.5 1.5 0 0 0 5.5 19H9"></path><path d="M14 8l4 4-4 4"></path><path d="M18 12H9"></path>',
    pencil: '<path d="M5 18.5 6.2 14 15.8 4.4a2 2 0 0 1 2.8 2.8L9 16.8z"></path><path d="m14.5 5.7 3.8 3.8"></path>',
    trash: '<path d="M5 7h14"></path><path d="M10 11v6"></path><path d="M14 11v6"></path><path d="M8 7l1-3h6l1 3"></path><path d="M7 7l1 13h8l1-13"></path>',
    dot: '<circle cx="12" cy="12" r="3.5"></circle>'
  };
  return '<svg class="svg-icon ' + (className || '') + '" viewBox="0 0 24 24" aria-hidden="true">' + (paths[name] || paths.dot) + '</svg>';
}

function render() {
  if (!state.user) {
    renderAuth();
    return;
  }
  if (state.user.role !== 'admin' && (state.tab === 'users' || state.tab === 'settings')) state.tab = 'reminders';
  app.className = 'app-shell';
  const usersTab = state.user.role === 'admin' ? '<button class="tab ' + active('users') + '" data-tab="users">' + icon('users') + t('tabUsers') + '</button>' : '';
  const settingsTab = state.user.role === 'admin' ? '<button class="tab ' + active('settings') + '" data-tab="settings">' + icon('settings') + t('tabSettings') + '</button>' : '';
  app.innerHTML =
    '<header class="topbar">' +
      '<div class="brand"><div class="brand-mark">' + icon('logo') + '</div><div><h1>Auto Send Email</h1><p>' + t('tagline') + '</p></div></div>' +
      '<nav class="tabs">' +
      '<button class="tab ' + active('reminders') + '" data-tab="reminders">' + icon('bell') + t('tabReminders') + '</button>' +
      '<button class="tab ' + active('template') + '" data-tab="template">' + icon('template') + t('tabTemplate') + '</button>' +
      usersTab +
      settingsTab +
      '<button class="tab ' + active('logs') + '" data-tab="logs">' + icon('logs') + t('tabLogs') + '</button>' +
    '</nav>' +
      '<div class="userline"><label class="language-control"><span>' + t('language') + '</span><select id="langSelect" class="lang-select"><option value="zh" ' + selected(state.lang === 'zh') + '>中文</option><option value="en" ' + selected(state.lang === 'en') + '>English</option></select></label><span class="user-pill">' + icon('user') + esc(displayName(state.user)) + '</span><button id="logoutBtn">' + icon('logout') + t('logout') + '</button></div>' +
    '</header>' +
    '<section id="content"></section>';
  document.getElementById('logoutBtn').onclick = logout;
  document.getElementById('langSelect').onchange = changeLanguage;
  document.querySelectorAll('[data-tab]').forEach((button) => button.onclick = () => { state.tab = button.dataset.tab; state.editing = null; state.composing = false; render(); });
  if (state.tab === 'users') renderUsers();
  else if (state.tab === 'settings') renderSettings();
  else if (state.tab === 'template') renderTemplate();
  else if (state.tab === 'logs') renderLogs();
  else renderReminders();
}

function renderAuth() {
  app.className = 'auth';
  const isRegister = state.needsSetup || state.authMode === 'register';
  const title = state.needsSetup ? t('createFirstAccount') : isRegister ? t('createAccount') : t('login');
  const helper = state.needsSetup ? t('firstAccountAdmin') : isRegister ? t('registerHelper') : t('loginHelper');
  app.innerHTML =
    '<section class="auth-hero">' +
      '<div class="brand"><div class="brand-mark">' + icon('logo') + '</div><div><h1>Auto Send Email</h1><p>' + t('tagline') + '</p></div></div>' +
      '<h1>' + t('heroTitle') + '</h1>' +
      '<p>' + t('heroSubtitle') + '</p>' +
      '<div class="hero-stats"><span class="stat-pill"><span>01</span> ' + t('newReminder') + '</span><span class="stat-pill"><span>02</span> ' + t('deliveryToInbox') + '</span></div>' +
    '</section>' +
    '<section class="panel">' +
      '<div class="auth-brand"><div class="auth-wordmark"><span class="brand-mark">' + icon('mail') + '</span><span>' + t('deliveryToInbox') + '</span></div><label class="language-control"><span>' + t('language') + '</span><select id="authLangSelect" class="lang-select"><option value="zh" ' + selected(state.lang === 'zh') + '>中文</option><option value="en" ' + selected(state.lang === 'en') + '>English</option></select></label></div>' +
      '<h2>' + title + '</h2>' +
      '<p class="meta">' + helper + '</p>' +
      '<form id="authForm" class="form-grid">' +
        '<label>' + t('email') + '<input name="email" type="email" autocomplete="email" required></label>' +
        '<label class="' + (isRegister ? '' : 'hidden') + '">' + t('name') + '<input name="name" autocomplete="name"></label>' +
        '<label>' + t('password') + '<input name="password" type="password" autocomplete="current-password" minlength="8" required></label>' +
        '<div class="error" id="authError"></div>' +
        '<button class="primary" type="submit">' + (isRegister ? t('createAccount') : t('login')) + '</button>' +
        (state.needsSetup ? '' : '<button type="button" id="switchAuth">' + (isRegister ? t('useExistingAccount') : t('createNewAccount')) + '</button>') +
      '</form>' +
    '</section>';
  const switchAuth = document.getElementById('switchAuth');
  document.getElementById('authLangSelect').onchange = changeLanguage;
  if (switchAuth) switchAuth.onclick = () => { state.authMode = isRegister ? 'login' : 'register'; render(); };
  document.getElementById('authForm').onsubmit = async (event) => {
    event.preventDefault();
    await runOnce('auth', event.currentTarget, async () => {
      const form = new FormData(event.currentTarget);
      const payload = Object.fromEntries(form.entries());
      try {
        const result = await api(isRegister ? '/api/register' : '/api/login', { method: 'POST', body: JSON.stringify(payload) });
        state.user = result.user;
        state.needsSetup = false;
        state.authMode = 'login';
        await loadAll();
        render();
      } catch (error) {
        document.getElementById('authError').textContent = error.message;
      }
    });
  };
}

function renderReminders() {
  const content = document.getElementById('content');
  const current = state.editing;
  const showComposer = state.composing || current;
  const ownerSelect = state.user.role === 'admin'
    ? '<label>' + t('owner') + '<select name="user_id">' + state.users.map((user) => '<option value="' + user.id + '" ' + selected(current && current.user_id === user.id) + '>' + esc(displayName(user)) + '</option>').join('') + '</select></label>'
    : '';
  content.innerHTML =
    '<section class="hero">' +
      '<div class="hero-copy"><h2>' + t('heroTitle') + '</h2><p>' + t('heroSubtitle') + '</p>' +
        '<div class="hero-stats"><span class="stat-pill"><span>' + activeReminderCount() + '</span> ' + t('activeReminders') + '</span><span class="stat-pill"><span>' + esc(nextReminderText()) + '</span> ' + t('nextDelivery') + '</span><button class="primary" type="button" data-new-reminder>' + icon('bell') + t('startNewReminder') + '</button></div>' +
      '</div>' +
      '<aside class="side-card"><div class="section-head"><div><h3>' + t('upcomingDelivery') + '</h3><p>' + t('deliveryToInbox') + '</p></div></div><div class="timeline">' + renderUpcomingItems() + '</div></aside>' +
    '</section>' +
    '<div class="home-grid">' +
      '<div class="main-stack">' +
      (showComposer ? '<div class="modal-backdrop" id="composerModal"><div class="modal"><section id="composer" class="compose-card ' + (current ? 'editing' : '') + '">' +
        '<div class="composer-top"><div class="composer-title"><span class="composer-icon">' + icon(current ? 'pencil' : 'bell') + '</span><div><h2>' + (current ? t('editReminder') : t('greeting')) + '</h2><p class="meta">' + (current ? t('editingHint') : t('greetingHint')) + '</p></div></div><div class="actions">' + (current ? '<span class="badge important">' + t('editing') + '</span>' : '') + '<button type="button" class="modal-close" id="modalClose" aria-label="' + escAttr(t('close')) + '">&times;</button></div></div>' +
        '<form id="reminderForm" class="form-grid">' + ownerSelect +
          '<label>' + t('remindMe') + '<input name="title" required value="' + escAttr(current ? current.title : '') + '" placeholder="' + escAttr(t('title')) + '"></label>' +
          '<div class="recipient-row"><label>' + t('recipientEmail') + '<textarea name="recipient_email" placeholder="' + escAttr(state.user.email) + '">' + esc(current ? current.recipient_email : '') + '</textarea></label><div class="form-note">' + t('recipientHint') + '</div></div>' +
          '<label>' + t('message') + '<textarea name="message" placeholder="' + escAttr(t('greetingHint')) + '">' + esc(current ? current.message : '') + '</textarea></label>' +
          '<div class="row three"><label>' + t('type') + '<select name="schedule_type" id="scheduleType">' + option('once', t('once'), current && current.schedule_type) + option('daily', t('daily'), current && current.schedule_type) + option('weekly', t('weekly'), current && current.schedule_type) + option('monthly', t('monthly'), current && current.schedule_type) + '</select></label>' +
          '<label>' + t('time') + '<input name="time_of_day" type="time" required value="' + escAttr(current ? current.time_of_day : '09:00') + '"></label>' +
          '<label>' + t('timezone') + '<select name="timezone">' + timezoneOptions(current ? current.timezone : 'Asia/Shanghai') + '</select></label></div>' +
          '<div class="row"><label id="onceField">' + t('whenSend') + '<input name="once_at" type="date" value="' + escAttr(current && current.once_at ? current.once_at : today()) + '"></label>' +
          '<div></div></div>' +
          '<div class="row"><label id="weekdayField">' + t('weekday') + '<select name="day_of_week">' + weekdayOptions(current ? current.day_of_week : new Date().getDay()) + '</select></label>' +
          '<label id="monthdayField">' + t('monthDay') + '<input name="day_of_month" type="number" min="1" max="31" value="' + escAttr(current && current.day_of_month ? current.day_of_month : 1) + '"></label></div>' +
          '<div class="inline-setting"><label><span><input id="importantToggle" name="important" type="checkbox" value="1" ' + checked(current && current.important) + '> ' + t('importantReminder') + '</span></label>' +
          '<label id="resendField" class="interval-field">' + t('resendEvery') + '<input name="resend_interval_minutes" type="number" min="5" max="1440" step="5" value="' + escAttr(current && current.resend_interval_minutes ? current.resend_interval_minutes : 30) + '"></label></div>' +
          '<label><span><input name="enabled" type="checkbox" value="1" ' + checked(!current || current.enabled) + '> ' + t('enabled') + '</span></label>' +
          '<div class="error" id="reminderError"></div>' +
          '<div class="actions"><button class="primary" type="submit">' + (current ? t('saveChanges') : t('save')) + '</button><button type="button" id="clearEdit">' + (current ? t('cancelEdit') : t('clear')) + '</button></div>' +
        '</form></section></div></div>' : '') +
      '<section class="reminder-list"><div class="section-head"><div><h2>' + t('myReminders') + '</h2><p>' + t('deliveryPromise') + '</p></div><div class="list-tools">' + state.reminders.length + ' ' + t('reminders') + '</div></div><div class="list">' + renderReminderItems() + '</div></section>' +
      '</div>' +
      '<aside><section class="promise-card"><strong>' + t('deliveryPromiseTitle') + '</strong><p>' + t('deliveryPromise') + '</p></section></aside>' +
    '</div>';
  document.querySelectorAll('[data-new-reminder]').forEach((button) => button.onclick = () => { state.editing = null; state.composing = true; render(); });
  if (showComposer) {
    syncScheduleFields();
    syncImportantFields();
    document.getElementById('scheduleType').onchange = syncScheduleFields;
    document.getElementById('importantToggle').onchange = syncImportantFields;
    document.getElementById('clearEdit').onclick = () => { state.editing = null; state.composing = false; render(); };
    document.getElementById('modalClose').onclick = () => { state.editing = null; state.composing = false; render(); };
    document.getElementById('reminderForm').onsubmit = saveReminder;
  }
  document.querySelectorAll('[data-edit]').forEach((button) => button.onclick = () => { state.editing = state.reminders.find((item) => item.id === Number(button.dataset.edit)); state.composing = false; render(); });
  document.querySelectorAll('[data-delete]').forEach((button) => button.onclick = () => deleteReminder(Number(button.dataset.delete), button));
  document.querySelectorAll('[data-confirm]').forEach((button) => button.onclick = () => confirmReminderInApp(Number(button.dataset.confirm), button));
  document.querySelectorAll('[data-toggle]').forEach((button) => button.onclick = () => toggleReminder(Number(button.dataset.toggle), button));
}

function renderReminderItems() {
  if (!state.reminders.length) return '<div class="notice">' + t('noReminders') + '</div>';
  return state.reminders.map((item) =>
    '<article class="item">' +
      '<div class="item-main">' +
        '<div class="item-title-row"><span class="item-dot">' + icon('bell') + '</span><div class="item-title">' + esc(item.title) + '</div>' + (item.important ? '<span class="badge important">' + t('important') + '</span>' : '') + '<span class="badge ' + (item.enabled ? 'ok' : 'warn') + '">' + (item.enabled ? t('enabled') : t('paused')) + '</span></div>' +
        '<div class="item-message">' + esc(item.message || t('noMessage')) + '</div>' +
        '<div class="item-meta"><span>' + esc(scheduleLabel(item)) + '</span><span>' + t('next') + ': ' + esc(formatDate(item.next_run_at)) + '</span><span>' + t('recipient') + ': ' + esc(item.recipient_email || item.owner_email || '-') + '</span>' + importantStatus(item) + (item.owner_email ? '<span>' + t('owner') + ': ' + esc(item.owner_email) + '</span>' : '') + '</div>' +
      '</div>' +
      '<div class="item-actions">' + confirmButton(item) + '<button data-toggle="' + item.id + '">' + icon('bell') + (item.enabled ? t('pause') : t('resume')) + '</button><button data-edit="' + item.id + '">' + icon('pencil') + t('edit') + '</button><button class="danger" data-delete="' + item.id + '">' + icon('trash') + t('delete') + '</button></div>' +
    '</article>'
  ).join('');
}

function confirmButton(item) {
  return item.important && item.last_sent_at && !item.confirmed_at
    ? '<button class="primary" data-confirm="' + item.id + '">' + icon('bell') + t('confirmReminder') + '</button>'
    : '';
}

function importantStatus(item) {
  if (!item.important) return '';
  if (item.last_sent_at && !item.confirmed_at) return '<span>' + t('pendingConfirmation') + ' · ' + t('resendEveryShort', item) + '</span>';
  if (item.confirmed_at) return '<span>' + t('confirmedAt') + ': ' + esc(formatDate(item.confirmed_at)) + '</span>';
  return '<span>' + t('requiresConfirmation') + '</span>';
}

function renderUsers() {
  const content = document.getElementById('content');
  content.innerHTML =
    '<section class="hero"><div class="hero-copy"><h2>' + t('accountAndPrefs') + '</h2><p>' + t('users') + ' · ' + t('role') + '</p></div><aside class="side-card"><h3>' + t('users') + '</h3><p class="meta">' + t('registerHelper') + '</p></aside></section>' +
    '<section class="panel"><div class="section-head"><div><h2>' + t('users') + '</h2><p>' + t('saveRole') + '</p></div></div><div class="error" id="userError"></div><div class="table-wrap"><table class="table"><thead><tr><th>' + t('email') + '</th><th>' + t('name') + '</th><th>' + t('role') + '</th><th></th></tr></thead><tbody>' +
      state.users.map((user) =>
        '<tr><td>' + esc(user.email) + '</td><td>' + esc(user.name || '-') + '</td><td><select data-role-select="' + user.id + '">' +
          '<option value="user" ' + selected(user.role === 'user') + '>' + t('user') + '</option>' +
          '<option value="admin" ' + selected(user.role === 'admin') + '>' + t('admin') + '</option>' +
        '</select></td><td><button data-save-role="' + user.id + '">' + t('saveRole') + '</button></td></tr>'
      ).join('') +
    '</tbody></table></div></section>';
  document.querySelectorAll('[data-save-role]').forEach((button) => button.onclick = () => saveUserRole(Number(button.dataset.saveRole), button));
}

function renderTemplate() {
  const content = document.getElementById('content');
  const template = state.template || defaultTemplate();
  content.innerHTML =
    '<section class="hero"><div class="hero-copy"><h2>' + t('emailTemplateTitle') + '</h2><p>' + t('emailTemplateSubtitle') + '</p></div><aside class="side-card"><h3>' + t('emailPreview') + '</h3><p class="meta">' + t('customEmailHelp') + '</p></aside></section>' +
    '<section class="template-layout">' +
      '<div class="panel"><div class="section-head"><div><h2>' + t('emailTemplate') + '</h2><p>' + t('emailTemplateSubtitle') + '</p></div></div>' +
        '<form id="templateForm" class="form-grid compact">' +
          '<div class="row"><label>' + t('emailLanguage') + '<select name="email_language" id="templateLanguage">' +
            '<option value="zh" ' + selected((template.email_language || 'zh') === 'zh') + '>' + t('emailLanguageZh') + '</option>' +
            '<option value="en" ' + selected(template.email_language === 'en') + '>' + t('emailLanguageEn') + '</option>' +
          '</select></label>' +
          '<label>' + t('emailTemplate') + '<select name="email_template" id="emailTemplate">' +
            '<option value="letter" ' + selected((template.email_template || 'letter') === 'letter') + '>' + t('emailTemplateLetter') + '</option>' +
            '<option value="card" ' + selected(template.email_template === 'card') + '>' + t('emailTemplateCard') + '</option>' +
            '<option value="custom" ' + selected(template.email_template === 'custom') + '>' + t('emailTemplateCustom') + '</option>' +
          '</select></label></div>' +
          '<div id="customTemplateField" class="template-field"><label>' + t('customEmailHtml') + '<textarea name="custom_email_html" id="customEmailHtml" placeholder="{{title}}&#10;{{message}}&#10;{{schedule}}&#10;{{important_notice}}&#10;{{confirm_button}}">' + esc(template.custom_email_html || '') + '</textarea></label><div class="form-note">' + t('customEmailHelp') + '</div></div>' +
          '<div class="error" id="templateError"></div>' +
          '<div class="actions"><button class="primary" type="submit">' + t('saveTemplate') + '</button><button type="button" id="refreshPreview">' + t('refreshPreview') + '</button></div>' +
        '</form></div>' +
      '<div class="panel"><div class="section-head"><div><h2>' + t('emailPreview') + '</h2><p>' + t('deliveryToInbox') + '</p></div></div><iframe id="templatePreview" class="preview-frame" title="' + escAttr(t('emailPreview')) + '"></iframe><div class="preview-actions"><button type="button" id="refreshPreviewBottom">' + t('refreshPreview') + '</button></div></div>' +
    '</section>';
  syncEmailTemplateFields();
  document.getElementById('emailTemplate').onchange = () => { syncEmailTemplateFields(); refreshTemplatePreview(); };
  document.getElementById('templateLanguage').onchange = refreshTemplatePreview;
  document.getElementById('customEmailHtml').oninput = debouncePreview;
  document.getElementById('refreshPreview').onclick = refreshTemplatePreview;
  document.getElementById('refreshPreviewBottom').onclick = refreshTemplatePreview;
  document.getElementById('templateForm').onsubmit = saveTemplate;
  refreshTemplatePreview();
}

function renderSettings() {
  const content = document.getElementById('content');
  const provider = state.settings.provider || 'resend';
  const resendKeyHint = state.settings.has_resend_api_key ? t('existingResendKey') : t('pasteResendKey');
  const smtpPasswordHint = state.settings.has_smtp_password ? t('existingSmtpPassword') : t('smtpPasswordHint');
  content.innerHTML =
    '<section class="hero"><div class="hero-copy"><h2>' + t('emailSettings') + '</h2><p>' + t('smtpHelp') + '</p></div><aside class="side-card"><h3>' + t('provider') + '</h3><p class="meta">' + (provider === 'smtp' ? t('smtpMailbox') : t('resendApi')) + '</p></aside></section>' +
    '<section class="panel"><div class="section-head"><div><h2>' + t('emailSettings') + '</h2><p>' + t('smtpHelp') + '</p></div></div>' +
      '<form id="settingsForm" class="form-grid compact">' +
        '<label>' + t('provider') + '<select name="provider" id="emailProvider">' +
          '<option value="resend" ' + selected(provider === 'resend') + '>' + t('resendApi') + '</option>' +
          '<option value="smtp" ' + selected(provider === 'smtp') + '>' + t('smtpMailbox') + '</option>' +
        '</select></label>' +
        '<label>' + t('fromEmail') + '<input name="from_email" value="' + escAttr(state.settings.from_email || '') + '" placeholder="Reminders <reminders@your-domain.com>"></label>' +
        '<div id="resendSettings" class="form-grid">' +
          '<label>' + t('resendApiKey') + '<input name="resend_api_key" type="password" autocomplete="off" placeholder="' + escAttr(resendKeyHint) + '"></label>' +
        '</div>' +
        '<div id="smtpSettings" class="form-grid">' +
          '<div class="row"><label>' + t('smtpHost') + '<input name="smtp_host" value="' + escAttr(state.settings.smtp_host || '') + '" placeholder="smtp.qq.com"></label>' +
          '<label>' + t('smtpPort') + '<input name="smtp_port" type="number" min="1" max="65535" value="' + escAttr(state.settings.smtp_port || 465) + '"></label></div>' +
          '<div class="row"><label>' + t('encryption') + '<select name="smtp_secure">' +
            '<option value="ssl" ' + selected((state.settings.smtp_secure || 'ssl') === 'ssl') + '>SSL/TLS 465</option>' +
            '<option value="starttls" ' + selected(state.settings.smtp_secure === 'starttls') + '>STARTTLS 587</option>' +
          '</select></label>' +
          '<label>' + t('smtpUsername') + '<input name="smtp_username" value="' + escAttr(state.settings.smtp_username || '') + '" placeholder="yourname@qq.com"></label></div>' +
          '<label>' + t('smtpPassword') + '<input name="smtp_password" type="password" autocomplete="off" placeholder="' + escAttr(smtpPasswordHint) + '"></label>' +
          '<div class="meta">' + t('smtpHelp') + '</div>' +
        '</div>' +
        '<div class="error" id="settingsError"></div>' +
        '<button class="primary" type="submit">' + t('saveSettings') + '</button>' +
      '</form></section>';
  syncEmailProviderFields();
  document.getElementById('emailProvider').onchange = syncEmailProviderFields;
  document.getElementById('settingsForm').onsubmit = saveSettings;
}

function renderLogs() {
  const content = document.getElementById('content');
  content.innerHTML =
    '<section class="hero"><div class="hero-copy"><h2>' + t('recentSends') + '</h2><p>' + t('deliveryPromise') + '</p></div><aside class="side-card"><h3>' + t('status') + '</h3><p class="meta">' + state.logs.length + ' ' + t('recentSends') + '</p></aside></section>' +
    '<section class="panel"><div class="section-head"><div><h2>' + t('recentSends') + '</h2><p>' + t('deliveryToInbox') + '</p></div></div><div class="table-wrap"><table class="table"><thead><tr><th>' + t('time') + '</th><th>' + t('reminder') + '</th><th>' + t('owner') + '</th><th>' + t('status') + '</th><th>' + t('response') + '</th></tr></thead><tbody>' +
      (state.logs.length ? state.logs.map((log) => '<tr><td>' + esc(formatDate(log.created_at)) + '</td><td>' + esc(log.title || '-') + '</td><td>' + esc(log.owner_email || '-') + '</td><td>' + esc(statusLabel(log.status)) + '</td><td>' + esc(log.response || '') + '</td></tr>').join('') : '<tr><td colspan="5">' + t('noLogs') + '</td></tr>') +
    '</tbody></table></div></section>';
}

async function saveReminder(event) {
  event.preventDefault();
  await runOnce('saveReminder', event.currentTarget, async () => {
    const form = new FormData(event.currentTarget);
    const payload = Object.fromEntries(form.entries());
    payload.enabled = form.has('enabled');
    payload.important = form.has('important');
    payload.user_id = Number(payload.user_id || state.user.id);
    payload.recipient_email = String(payload.recipient_email || '').trim();
    payload.day_of_week = Number(payload.day_of_week || 0);
    payload.day_of_month = Number(payload.day_of_month || 1);
    payload.resend_interval_minutes = Number(payload.resend_interval_minutes || 30);
    try {
      const path = state.editing ? '/api/reminders/' + state.editing.id : '/api/reminders';
      await api(path, { method: state.editing ? 'PUT' : 'POST', body: JSON.stringify(payload) });
      state.editing = null;
      state.composing = false;
      await loadAll();
      render();
    } catch (error) {
      document.getElementById('reminderError').textContent = error.message;
    }
  });
}

async function confirmReminderInApp(id, button) {
  await runOnce('confirm:' + id, button, async () => {
    await api('/api/reminders/' + id + '/confirm', { method: 'POST' });
    await loadAll();
    render();
  });
}

async function toggleReminder(id, button) {
  await runOnce('toggle:' + id, button, async () => {
    await api('/api/reminders/' + id + '/toggle', { method: 'POST' });
    await loadAll();
    render();
  });
}

async function deleteReminder(id, button) {
  if (!confirm(t('deleteReminderConfirm'))) return;
  await runOnce('delete:' + id, button, async () => {
    await api('/api/reminders/' + id, { method: 'DELETE' });
    await loadAll();
    render();
  });
}

async function saveUserRole(id, button) {
  const role = document.querySelector('[data-role-select="' + id + '"]').value;
  await runOnce('saveUserRole:' + id, button, async () => {
    try {
      await api('/api/users/' + id, { method: 'PUT', body: JSON.stringify({ role }) });
      const me = await api('/api/me');
      state.user = me.user;
      await loadAll();
      render();
    } catch (error) {
      document.getElementById('userError').textContent = error.message;
    }
  });
}

async function saveSettings(event) {
  event.preventDefault();
  await runOnce('saveSettings', event.currentTarget, async () => {
    const payload = Object.fromEntries(new FormData(event.currentTarget).entries());
    try {
      const result = await api('/api/settings', { method: 'PUT', body: JSON.stringify(payload) });
      state.settings = result.settings;
      render();
    } catch (error) {
      document.getElementById('settingsError').textContent = error.message;
    }
  });
}

async function saveTemplate(event) {
  event.preventDefault();
  await runOnce('saveTemplate', event.currentTarget, async () => {
    try {
      const result = await api('/api/template', { method: 'PUT', body: JSON.stringify(templatePayload()) });
      state.template = result.template;
      const error = document.getElementById('templateError');
      if (error) error.textContent = t('templateSaved');
      await refreshTemplatePreview();
    } catch (error) {
      document.getElementById('templateError').textContent = error.message;
    }
  });
}

function templatePayload() {
  const form = document.getElementById('templateForm');
  return Object.fromEntries(new FormData(form).entries());
}

let previewTimer = 0;
function debouncePreview() {
  clearTimeout(previewTimer);
  previewTimer = setTimeout(refreshTemplatePreview, 450);
}

async function refreshTemplatePreview() {
  const frame = document.getElementById('templatePreview');
  if (!frame) return;
  try {
    const result = await api('/api/template/preview', { method: 'POST', body: JSON.stringify(templatePayload()) });
    frame.srcdoc = result.html || '';
  } catch (error) {
    frame.srcdoc = '<div style="font-family:sans-serif;padding:24px;color:#b56d63;">' + esc(error.message) + '</div>';
  }
}

async function logout() {
  await runOnce('logout', document.getElementById('logoutBtn'), async () => {
    await api('/api/logout', { method: 'POST' });
    state.user = null;
    state.reminders = [];
    state.users = [];
    state.logs = [];
    state.settings = defaultSettings();
    state.template = defaultTemplate();
    render();
  });
}

function changeLanguage(event) {
  state.lang = event.currentTarget.value === 'en' ? 'en' : 'zh';
  localStorage.setItem('ase_lang', state.lang);
  render();
}

function syncScheduleFields() {
  const type = document.getElementById('scheduleType').value;
  document.getElementById('onceField').classList.toggle('hidden', type !== 'once');
  document.getElementById('weekdayField').classList.toggle('hidden', type !== 'weekly');
  document.getElementById('monthdayField').classList.toggle('hidden', type !== 'monthly');
}

function syncImportantFields() {
  const toggle = document.getElementById('importantToggle');
  const field = document.getElementById('resendField');
  if (toggle && field) field.classList.toggle('hidden', !toggle.checked);
}

function syncEmailProviderFields() {
  const provider = document.getElementById('emailProvider').value;
  document.getElementById('resendSettings').classList.toggle('hidden', provider !== 'resend');
  document.getElementById('smtpSettings').classList.toggle('hidden', provider !== 'smtp');
}

function syncEmailTemplateFields() {
  const template = document.getElementById('emailTemplate');
  const field = document.getElementById('customTemplateField');
  if (template && field) field.classList.toggle('hidden', template.value !== 'custom');
}

function sortedReminders() {
  return [...state.reminders].sort((a, b) => String(a.next_run_at || '').localeCompare(String(b.next_run_at || '')));
}
function upcomingReminders() {
  return sortedReminders().filter((item) => item.enabled).slice(0, 4);
}
function activeReminderCount() {
  return state.reminders.filter((item) => item.enabled).length;
}
function nextReminderText() {
  const next = upcomingReminders()[0];
  return next ? formatDate(next.next_run_at) : '-';
}
function renderUpcomingItems() {
  const items = upcomingReminders();
  if (!items.length) return '<div class="notice">' + t('noUpcoming') + '</div>';
  return items.map((item) =>
    '<div class="timeline-item"><span class="timeline-dot">' + icon('dot') + '</span><div><div class="timeline-title">' + esc(item.title) + '</div><div class="timeline-meta">' + esc(formatDate(item.next_run_at)) + '<br>' + esc(scheduleLabel(item)) + '</div></div></div>'
  ).join('');
}
function active(tab) { return state.tab === tab ? 'active' : ''; }
function selected(value) { return value ? 'selected' : ''; }
function checked(value) { return value ? 'checked' : ''; }
function displayName(user) { return (user.name || user.email) + ' (' + roleLabel(user.role) + ')'; }
function option(value, label, current) { return '<option value="' + value + '" ' + selected((current || 'daily') === value) + '>' + label + '</option>'; }
function weekdayOptions(current) { return weekdayNames().map((name, index) => '<option value="' + index + '" ' + selected(Number(current) === index) + '>' + name + '</option>').join(''); }
function timezoneOptions(current) {
  const zones = [
    ['Asia/Shanghai', 'Asia/Shanghai (UTC+08:00)'],
    ['Asia/Hong_Kong', 'Asia/Hong_Kong (UTC+08:00)'],
    ['Asia/Taipei', 'Asia/Taipei (UTC+08:00)'],
    ['Asia/Tokyo', 'Asia/Tokyo (UTC+09:00)'],
    ['Asia/Seoul', 'Asia/Seoul (UTC+09:00)'],
    ['Asia/Singapore', 'Asia/Singapore (UTC+08:00)'],
    ['Asia/Bangkok', 'Asia/Bangkok (UTC+07:00)'],
    ['Asia/Dubai', 'Asia/Dubai (UTC+04:00)'],
    ['Europe/London', 'Europe/London'],
    ['Europe/Paris', 'Europe/Paris'],
    ['America/New_York', 'America/New_York'],
    ['America/Chicago', 'America/Chicago'],
    ['America/Denver', 'America/Denver'],
    ['America/Los_Angeles', 'America/Los_Angeles'],
    ['Australia/Sydney', 'Australia/Sydney'],
    ['Pacific/Auckland', 'Pacific/Auckland'],
    ['UTC', 'UTC']
  ];
  const hasCurrent = zones.some(([value]) => value === current);
  const options = hasCurrent ? zones : [[current, current], ...zones];
  return options.map(([value, label]) => '<option value="' + escAttr(value) + '" ' + selected(value === current) + '>' + esc(label) + '</option>').join('');
}
function today() { return new Date().toISOString().slice(0, 10); }
function formatDate(value) { return value ? new Date(value).toLocaleString() : '-'; }
function scheduleLabel(item) {
  if (item.schedule_type === 'once') return t('onceSchedule', item);
  if (item.schedule_type === 'weekly') return t('weeklySchedule', item);
  if (item.schedule_type === 'monthly') return t('monthlySchedule', item);
  return t('dailySchedule', item);
}
function weekdayNames() { return [t('sunday'), t('monday'), t('tuesday'), t('wednesday'), t('thursday'), t('friday'), t('saturday')]; }
function weekdayName(index) { return weekdayNames()[Number(index)] || '-'; }
function roleLabel(role) { return role === 'admin' ? t('admin') : t('user'); }
function statusLabel(status) { return status === 'sent' ? t('sent') : status === 'failed' ? t('failed') : status; }
function t(key, arg) {
  const value = (I18N[state.lang] && I18N[state.lang][key]) || I18N.zh[key] || key;
  return typeof value === 'function' ? value(arg) : value;
}
function localizeError(message) {
  const text = String(message || '');
  const map = {
    'Invalid email or password': t('invalidCredentials'),
    'Email is already registered': t('duplicateEmail'),
    'At least one admin is required': t('atLeastOneAdmin'),
    'User not found': t('userNotFound'),
    'Unauthorized': t('loginRequired'),
    'Request failed': t('requestFailed')
  };
  if (text.includes('AUTH_SECRET is not configured')) return t('authSecretMissing');
  return map[text] || text;
}
function defaultSettings() {
  return {
    provider: 'resend',
    from_email: '',
    resend_api_key: '',
    has_resend_api_key: false,
    smtp_host: '',
    smtp_port: 465,
    smtp_secure: 'ssl',
    smtp_username: '',
    smtp_password: '',
    has_smtp_password: false,
    email_language: 'zh',
    email_template: 'letter',
    custom_email_html: ''
  };
}
function esc(value) { return String(value == null ? '' : value).replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char])); }
function escAttr(value) { return esc(value).replace(/\\n/g, ' '); }
`;
}


