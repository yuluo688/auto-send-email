# Auto Send Email

一个定时邮件提醒应用。用户可以自行注册、登录、添加自己的提醒事项；应用部署在 Cloudflare Worker 上，使用 Cloudflare D1 保存数据，通过 Worker Cron 每分钟扫描到期提醒，并支持 Resend API 或 SMTP 邮箱发送邮件。

## 傻瓜式部署

推荐直接使用一键配置脚本。脚本会自动检查 Cloudflare 登录状态、创建或复用 D1 数据库、写入 `wrangler.toml`、设置生产环境密钥、应用数据库迁移并部署 Worker。

1. 安装依赖：

   ```powershell
   npm install
   ```

2. 启动部署向导：

   ```powershell
   npm run setup
   ```

   脚本会把 `wrangler.toml` 中的 D1 `database_id` 和 `APP_URL` 替换成你自己的 Cloudflare 配置。

3. 按提示输入：

   - D1 数据库名称，默认 `auto_send_email`

4. 部署完成后，打开终端输出的 Worker URL。

5. 第一个注册的账号会自动成为管理员。管理员登录后进入 Settings，选择发信方式并填写凭据：

   - Resend API：填写 Resend API Key 和已验证的发件地址。
   - SMTP 邮箱：填写 SMTP host、端口、加密方式、邮箱账号和 SMTP 授权码。QQ/163 等邮箱通常需要先在邮箱后台开启 SMTP，并生成授权码。

   发件地址格式示例：

   ```text
   Reminders <reminders@your-domain.com>
   ```

6. 后续用户可以自行注册、登录并添加自己的提醒。

## 功能

- 用户自行注册和登录
- 普通用户可创建、编辑、启用、暂停、确认和删除自己的提醒
- 第一个注册用户自动成为管理员
- 管理员可在后台配置全局邮件发件方式和凭据
- 管理员可查看用户列表并编辑用户角色
- 支持单个或多个收件邮箱，多个邮箱可用逗号、分号、空格或换行分隔
- 支持一次性、每日、每周、每月提醒
- 支持重要提醒：发送后需要确认，未确认时按设定间隔重复发送
- 支持用户级邮件模板：中文/英文、信笺风格、卡片风格、自定义 HTML
- 支持邮件模板实时预览
- 新建和编辑提醒使用弹窗交互，减少页面常驻表单干扰
- 使用 Cloudflare D1 保存用户、提醒、全局设置和发送日志
- 支持 Resend API 或 SMTP 邮箱发送邮件
- 使用 Cloudflare Worker Cron 每分钟自动检查并发送到期提醒

## 手动配置与部署

如果你不想使用 `npm run setup`，也可以手动部署。

1. 安装依赖：

   ```powershell
   npm install
   ```

2. 创建 D1 数据库，并把命令返回的 `database_id` 填到 `wrangler.toml`：

   ```powershell
   npx wrangler d1 create auto_send_email
   ```

   同时把 `wrangler.toml` 里的 `APP_URL` 改成你的 Worker URL 或自定义域名，例如 `https://your-worker.your-subdomain.workers.dev`。

3. 创建生产环境密钥：

   ```powershell
   npx wrangler secret put AUTH_SECRET
   ```

   `AUTH_SECRET` 应该是一个足够长的随机字符串，用来签发登录 Cookie。使用 `npm run setup` 时会自动生成。

4. 应用 D1 数据库迁移：

   ```powershell
   npm run db:migrate
   ```

5. 部署 Worker：

   ```powershell
   npm run deploy
   ```

6. 登录网站后台，在 Settings 中选择 Resend API 或 SMTP 邮箱并填写发信配置。

## 邮件模板

邮件模板是用户级配置，普通用户也可以自行设置，不需要管理员权限。

- 中文或英文邮件内容
- 信笺风格和卡片风格内置模板
- 自定义 HTML 模板
- 实时预览最终邮件效果

自定义 HTML 支持以下占位符：

```text
{{app_name}}
{{title}}
{{message}}
{{schedule}}
{{important_notice}}
{{confirm_button}}
{{confirm_url}}
{{footer}}
```

## 用户注册与权限

- 所有人都可以在登录页切换到注册模式并创建账号。
- 第一个注册账号自动成为管理员。
- 普通用户只能查看和管理自己的提醒。
- 管理员可以配置全局发信方式、查看用户列表、编辑用户角色，并代用户创建提醒。
- 邮件模板由每个用户独立设置；管理员的 Settings 只负责发信通道和凭据。

## 本地开发

1. 应用本地 D1 迁移：

   ```powershell
   npm run db:migrate:local
   ```

2. 复制 `.dev.vars.example` 为 `.dev.vars`，并填写本地开发用的 `AUTH_SECRET`。

3. 启动本地 Worker：

   ```powershell
   npm run dev
   ```

4. 打开本地地址后注册第一个账号，然后在 Settings 中填写发信配置。

## 常用命令

```powershell
npm run setup            # 交互式部署向导
npm run dev              # 本地开发
npm run typecheck        # TypeScript 类型检查
npm run db:migrate:local # 应用本地 D1 迁移
npm run db:migrate       # 应用远程 D1 迁移
npm run deploy           # 部署到 Cloudflare Workers
```

## 重要说明

- 仓库里的 `wrangler.toml` 使用占位值，不包含作者的 D1 ID 或线上域名；部署前请运行 `npm run setup` 或手动替换。
- Resend API Key、SMTP 密码或授权码都在管理员后台 Settings 中保存；输入框留空保存时会保留旧值。
- SMTP 支持 465 SSL/TLS 和 587 STARTTLS。Cloudflare Workers 禁止连接 SMTP 25 端口，请不要使用 25。
- 使用 QQ、163 等个人邮箱时，通常需要在邮箱设置中开启 SMTP 服务，并使用授权码而不是登录密码。
- Cron 配置在 `wrangler.toml` 中，默认 `* * * * *`，表示每分钟检查一次到期提醒。
- 一次性提醒发送成功后会自动停用；循环提醒发送成功后会计算下一次发送时间。
- 重要提醒发送后，如果没有确认，会按提醒设置的间隔继续重发；确认后本次提醒停止重发。

## 友链

- [LINUX DO](https://linux.do)

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=yuluo688/auto-send-email&type=Date)](https://www.star-history.com/#yuluo688/auto-send-email&Date)

---

# Auto Send Email (English)

A consumer-facing scheduled email reminder app. Users can register, log in, and manage their own reminders. The app runs on Cloudflare Workers, stores data in Cloudflare D1, checks due reminders every minute through Worker Cron, and sends email through Resend API or SMTP mailboxes.

## Guided Deployment

The recommended path is the interactive setup script. It checks Cloudflare login, creates or reuses a D1 database, updates `wrangler.toml`, sets production secrets, applies database migrations, and deploys the Worker.

1. Install dependencies:

   ```powershell
   npm install
   ```

2. Start the setup wizard:

   ```powershell
   npm run setup
   ```

   The script replaces the placeholder D1 `database_id` and `APP_URL` in `wrangler.toml` with your own Cloudflare configuration.

3. Follow the prompts for:

   - D1 database name, default `auto_send_email`

4. After deployment, open the Worker URL printed in the terminal.

5. The first registered account automatically becomes the admin. After logging in, open Settings, choose the email provider, and fill in the credentials:

   - Resend API: enter a Resend API Key and a verified sender.
   - SMTP mailbox: enter SMTP host, port, encryption, username, and SMTP password or authorization code. QQ, 163, and similar mailboxes usually require SMTP to be enabled first.

   Sender format example:

   ```text
   Reminders <reminders@your-domain.com>
   ```

6. Later users can register, log in, and add their own reminders.

## Features

- Self-service registration and login
- Regular users can create, edit, enable, pause, confirm, and delete their own reminders
- The first registered user automatically becomes the admin
- Admins can configure the global email provider and credentials
- Admins can view users and edit user roles
- Single or multiple recipient email addresses per reminder
- One-time, daily, weekly, and monthly reminders
- Important reminders that require confirmation and resend at a chosen interval until confirmed
- Per-user email templates with Chinese/English copy, letter style, card style, and custom HTML
- Live email template preview
- Modal-based reminder creation and editing
- Cloudflare D1 storage for users, reminders, global settings, and send logs
- Resend API or SMTP email delivery
- Cloudflare Worker Cron checks due reminders every minute

## Manual Setup And Deployment

Use this path only if you do not want to run `npm run setup`.

1. Install dependencies:

   ```powershell
   npm install
   ```

2. Create the D1 database, then copy the returned `database_id` into `wrangler.toml`:

   ```powershell
   npx wrangler d1 create auto_send_email
   ```

   Also replace `APP_URL` in `wrangler.toml` with your Worker URL or custom domain, for example `https://your-worker.your-subdomain.workers.dev`.

3. Create production secrets:

   ```powershell
   npx wrangler secret put AUTH_SECRET
   ```

   `AUTH_SECRET` should be a long random string used to sign login cookies. `npm run setup` generates it automatically.

4. Apply the D1 database migration:

   ```powershell
   npm run db:migrate
   ```

5. Deploy the Worker:

   ```powershell
   npm run deploy
   ```

6. Log in to the dashboard and configure Resend API or SMTP delivery in Settings.

## Email Templates

Email templates are per-user settings. Regular users can customize them without admin access.

- Chinese or English email copy
- Built-in letter and card styles
- Custom HTML templates
- Live preview of the final email

Custom HTML supports these placeholders:

```text
{{app_name}}
{{title}}
{{message}}
{{schedule}}
{{important_notice}}
{{confirm_button}}
{{confirm_url}}
{{footer}}
```

## Registration And Permissions

- Anyone can switch to registration mode on the login page and create an account.
- The first registered account automatically becomes the admin.
- Regular users can only view and manage their own reminders.
- Admins can configure global email delivery, view users, and create reminders for users.
- Email templates are configured independently by each user. Admin Settings only manages the delivery provider and credentials.

## Local Development

1. Apply local D1 migrations:

   ```powershell
   npm run db:migrate:local
   ```

2. Copy `.dev.vars.example` to `.dev.vars`, then fill in a local value for `AUTH_SECRET`.

3. Start the local Worker:

   ```powershell
   npm run dev
   ```

4. Open the local URL, register the first account, then configure email delivery in Settings.

## Common Commands

```powershell
npm run setup            # Interactive deployment wizard
npm run dev              # Local development
npm run typecheck        # TypeScript type checking
npm run db:migrate:local # Apply local D1 migrations
npm run db:migrate       # Apply remote D1 migrations
npm run deploy           # Deploy to Cloudflare Workers
```

## Notes

- The committed `wrangler.toml` uses placeholders and does not contain the author's D1 ID or production domain. Run `npm run setup` or replace them manually before deploying.
- Resend API keys and SMTP passwords or authorization codes are saved from the admin Settings page. Leaving a secret field blank keeps the existing value.
- SMTP supports 465 SSL/TLS and 587 STARTTLS. Cloudflare Workers cannot connect to SMTP port 25, so do not use port 25.
- QQ, 163, and similar personal mailboxes usually require SMTP to be enabled in mailbox settings and require an authorization code instead of the login password.
- Cron is configured in `wrangler.toml`. The default `* * * * *` checks due reminders every minute.
- One-time reminders are disabled after a successful send. Recurring reminders compute their next send time after each successful send.
- Important reminders keep resending at the configured interval until the current occurrence is confirmed.

## Links

- [LINUX DO](https://linux.do)

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=yuluo688/auto-send-email&type=Date)](https://www.star-history.com/#yuluo688/auto-send-email&Date)
