# How to Run the Bot on Railway

This guide explains how to deploy **Rise Tweaks Anti-Nuke Bot** from GitHub to Railway.

The bot is a long-running Discord worker. It does **not** need a website, public domain, database, or Railway cron job.

## 1. Prepare the Discord bot

1. Open the Discord Developer Portal: https://discord.com/developers/applications
2. Select your bot application.
3. Open **Bot** in the left menu.
4. Under **Privileged Gateway Intents**, enable:
   - **Server Members Intent**
5. Save the changes.
6. Copy or reset the bot token. Keep it private—you will add it to Railway later.

### Invite the bot to your server

Use Discord's **OAuth2 > URL Generator** page.

Select these scopes:

- `bot`
- `applications.commands`

Give the bot these permissions:

- View Audit Log
- Manage Roles
- Manage Channels
- Manage Webhooks
- Moderate Members
- Ban Members
- Kick Members
- View Channels
- Send Messages
- Embed Links

After inviting the bot, move its Discord role **above the quarantine role and every role it needs to remove or restore**. Discord will not allow the bot to manage roles above its own highest role.

## 2. Create the Discord IDs used by the bot

In Discord, open **User Settings > Advanced** and enable **Developer Mode**.

Right-click the correct item and choose **Copy ID** for each value:

- Your server: `GUILD_ID`
- Your Discord account: `OWNER_ID`
- Your owner role: `OWNER_ROLE_ID`
- Your staff role: `STAFF_ROLE_ID`
- Your security-log channel: `LOG_CHANNEL_ID`
- Your quarantine role: `QUARANTINE_ROLE_ID`
- A trusted moderation bot, when used: `TRUSTED_MOD_BOT_ID`

Use `0` for `TRUSTED_MOD_BOT_ID` when you do not have another moderation bot to exempt.

## 3. Upload the repository to GitHub

Make sure the repository contains at least:

```text
bot.py
requirements.txt
Procfile
.env.example
.gitignore
```

Do **not** upload a real `.env` file or put your Discord token directly in `bot.py`.

From a terminal inside the project folder, you can upload changes with:

```bash
git add .
git commit -m "Add Railway deployment setup"
git push
```

## 4. Create the Railway project

1. Sign in at https://railway.com
2. Choose **New Project**.
3. Choose **Deploy from GitHub repo**.
4. Connect GitHub when prompted.
5. Select your `rise-tweaks-anti-nuke-bot` repository.
6. Choose **Add Variables** before the first deployment when that option appears.

Railway will build the Python project from `requirements.txt`. The included `Procfile` tells Railway to run the bot as a worker.

## 5. Add the Railway variables

Open your Railway service and select **Variables**. Add each variable below.

```env
DISCORD_TOKEN=your_real_discord_bot_token
GUILD_ID=your_server_id
OWNER_ID=your_user_id
OWNER_ROLE_ID=your_owner_role_id
STAFF_ROLE_ID=your_staff_role_id
TRUSTED_MOD_BOT_ID=0
LOG_CHANNEL_ID=your_security_log_channel_id
QUARANTINE_ROLE_ID=your_quarantine_role_id
```

Important:

- Do not add quotation marks around the values.
- Do not add spaces before or after the values.
- Never post `DISCORD_TOKEN` in GitHub, Discord, screenshots, or support messages.
- When a token is exposed, reset it immediately in the Discord Developer Portal and replace the Railway variable.

After saving the variables, Railway should create a new deployment automatically. Otherwise, press **Deploy** or **Redeploy**.

## 6. Check the start command

The repository includes this `Procfile`:

```text
worker: python bot.py
```

When Railway does not detect it, open:

**Service > Settings > Deploy > Start Command**

Set the command to:

```bash
python bot.py
```

Do not configure the service as a cron job. A Discord bot must remain running continuously.

## 7. Add persistent storage

The bot stores configuration, incidents, lockdown information, and backups inside the local `data` folder. Without a Railway volume, those files can disappear during a redeploy or service replacement.

To preserve them:

1. Open the bot service in Railway.
2. Open **Settings**.
3. Find **Volumes** and choose **Add Volume**.
4. Set the mount path to:

```text
/app/data
```

5. Redeploy the service.

The current bot code uses `Path("data")`, so mounting the volume at `/app/data` preserves that folder in Railway's normal application working directory.

## 8. Verify that the bot started

Open the latest Railway deployment and select **View Logs**.

A successful startup should include a message similar to:

```text
Rise Tweaks Security online as YourBotName
```

The bot does not need a Railway-generated domain because it connects outward to Discord.

## 9. Finish setup in Discord

After the bot appears online, run:

```text
/securitysetup
```

Confirm that every check is green. Then configure or verify the main protection:

```text
/antinuke enabled:true profile:balanced
```

Recommended first checks:

```text
/securitystatus
/securitytest
/syncquarantine
/backupcreate
```

Test the bot in a private test server before enabling the strict profile or panic mode in an active community.

## Updating the bot later

When Railway is connected to the GitHub repository, pushing a new commit normally triggers a new deployment automatically.

```bash
git add .
git commit -m "Update anti-nuke bot"
git push
```

Watch the Railway deployment logs after every update.

## Common problems

### `DISCORD_TOKEN is missing`

The `DISCORD_TOKEN` Railway variable is absent, empty, or misspelled. Add the exact variable name and redeploy.

### The bot is offline or the deployment crashes

Open **View Logs** in Railway and read the last error. Confirm that the Start Command is `python bot.py` and that `requirements.txt` is in the selected repository root.

### Privileged intent or gateway error

Enable **Server Members Intent** under the bot's settings in the Discord Developer Portal, save, and redeploy.

### Slash commands do not appear

Confirm that:

- `GUILD_ID` is the correct server ID.
- The bot was invited with the `applications.commands` scope.
- The bot is already a member of that server.
- Railway was redeployed after changing the ID.

Guild commands usually appear quickly because this bot syncs commands directly to the configured server.

### The bot cannot remove roles or quarantine a member

Move the bot's Discord role above the quarantine, staff, and other roles it needs to manage. Also confirm that the bot has **Manage Roles**.

### Deleted channels or roles are not restored

Confirm that the bot has **View Audit Log**, **Manage Channels**, and **Manage Roles**. Run `/securitysetup` to see which permission is missing.

### Settings or backups disappear after redeploying

Add a Railway volume mounted at `/app/data`, then redeploy.

### The build cannot find `bot.py` or `requirements.txt`

Your Railway **Root Directory** is probably incorrect. Leave it empty when these files are at the repository root. When the project is inside a subfolder, set Root Directory to that subfolder.

## Security reminder

No anti-nuke bot can guarantee complete protection. Keep trusted administrator accounts secured with two-factor authentication, limit dangerous permissions, keep the bot role high enough to act, and maintain external backups of important server information.
