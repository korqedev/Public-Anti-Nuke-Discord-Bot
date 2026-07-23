# Rise Tweaks Anti-Nuke Bot

A free, open-source Discord anti-nuke bot built with `discord.py`. It watches audit-log activity, applies configurable rate limits, quarantines suspicious actors, restores deleted channels and roles, detects join raids, and stores server-structure backups.

> This version is designed for **one Discord server per bot deployment**. Each deployment uses the IDs in its environment variables.

## Features

- Channel create, update, and delete protection
- Role create, update, and delete protection
- Mass-ban and mass-kick detection
- Unauthorized webhook and bot-add protection
- Dangerous permission assignment detection
- Cross-action risk scoring
- Join-raid lockdown with automatic unlock
- Quarantine role synchronization
- Non-destructive channel and role backups
- Owner-only setup, recovery, and panic commands
- Staff `/ban` and `/kick` commands

## Requirements

- Python 3.11 or newer
- A Discord bot application
- The **Server Members Intent** enabled in the Discord Developer Portal
- A bot role placed above every role it needs to remove, restore, or quarantine

## Setup

1. Clone the repository.
2. Create a virtual environment.
3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Copy `.env.example` to `.env` and fill in every required value.
5. Enable **Server Members Intent** for the bot in the Discord Developer Portal.
6. Invite the bot with these permissions:
   - View Audit Log
   - Manage Roles
   - Manage Channels
   - Manage Webhooks
   - Moderate Members
   - Ban Members
   - Kick Members
7. Start the bot:

```bash
python bot.py
```

Run `/securitysetup` after the bot comes online.

## Environment variables

| Variable | Required | Purpose |
|---|---:|---|
| `DISCORD_TOKEN` | Yes | Bot token. Never commit this value. |
| `GUILD_ID` | Yes | Server where slash commands are registered. |
| `OWNER_ID` | Yes | User exempt from automatic enforcement. |
| `OWNER_ROLE_ID` | Yes | Role whose members are treated as owners. |
| `STAFF_ROLE_ID` | No | Role allowed to use the bot's staff ban/kick commands. |
| `TRUSTED_MOD_BOT_ID` | No | Another moderation bot exempt from enforcement. Use `0` if unused. |
| `LOG_CHANNEL_ID` | Yes | Channel for security logs. |
| `QUARANTINE_ROLE_ID` | Yes | Role applied to suspicious actors. |

## Important commands

- `/securitysetup` — verify permissions and configured roles/channels
- `/antinuke` — enable or disable a security profile
- `/securitystatus` — show current protections and thresholds
- `/setlimit` — change an action threshold
- `/setsecuritylog` — set the log channel
- `/setquarantinerole` — set and synchronize the quarantine role
- `/lockdown` and `/unlockdown` — manually lock or restore the server
- `/backupcreate`, `/backuplist`, `/backuprestore` — manage structure backups
- `/panic confirm:true` — enable strict protection and strip dangerous roles

## Railway deployment

1. Push these files to GitHub.
2. Create a Railway project from the repository.
3. Add the environment variables from `.env.example` in Railway's Variables tab.
4. Set the start command to `python bot.py` if Railway does not detect the included `Procfile`.
5. Use a persistent volume mounted to `/app/data` if you need incidents, settings, and backups to survive redeployments.

## Security notes

- Never commit `.env` or your Discord token.
- Test with a separate server before using strict or panic mode.
- Discord role hierarchy still applies; the bot cannot edit roles above its highest role.
- Audit log entries can arrive with a delay. The bot retries briefly, but an unknown actor is logged rather than punished automatically.
- This software reduces risk but cannot guarantee complete protection against every attack or Discord outage.

## License

MIT. See [LICENSE](LICENSE).
