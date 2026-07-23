import asyncio
import json
import os
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import discord
from discord import app_commands
from discord.ext import commands, tasks
from dotenv import load_dotenv

load_dotenv()

def env_int(name: str, default: int = 0) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be a Discord snowflake ID.") from exc


TOKEN = os.getenv("DISCORD_TOKEN")
GUILD_ID = env_int("GUILD_ID")
OWNER_ID = env_int("OWNER_ID")
OWNER_ROLE_ID = env_int("OWNER_ROLE_ID")
STAFF_ROLE_ID = env_int("STAFF_ROLE_ID")
TRUSTED_MOD_BOT_ID = env_int("TRUSTED_MOD_BOT_ID")
LOG_CHANNEL_ID = env_int("LOG_CHANNEL_ID")
QUARANTINE_ROLE_ID = env_int("QUARANTINE_ROLE_ID")


DATA_DIR = Path("data")
CONFIG_FILE = DATA_DIR / "security_config.json"
INCIDENT_FILE = DATA_DIR / "incidents.json"
LOCKDOWN_FILE = DATA_DIR / "lockdown_backup.json"
RAID_LOCKDOWN_FILE = DATA_DIR / "raid_lockdown_backup.json"
BACKUPS_FILE = DATA_DIR / "server_backups.json"
RUNTIME_FILE = DATA_DIR / "runtime_state.json"
DATA_DIR.mkdir(exist_ok=True)

if not TOKEN:
    raise RuntimeError("DISCORD_TOKEN is missing.")

required_ids = {
    "GUILD_ID": GUILD_ID,
    "OWNER_ID": OWNER_ID,
    "OWNER_ROLE_ID": OWNER_ROLE_ID,
    "LOG_CHANNEL_ID": LOG_CHANNEL_ID,
    "QUARANTINE_ROLE_ID": QUARANTINE_ROLE_ID,
}
missing_ids = [name for name, value in required_ids.items() if value <= 0]
if missing_ids:
    raise RuntimeError(f"Missing required environment variable(s): {', '.join(missing_ids)}")


GUILD_OBJECT = discord.Object(id=GUILD_ID)

DANGEROUS_PERMISSIONS = {
    "administrator", "manage_guild", "manage_roles", "manage_channels",
    "manage_webhooks", "ban_members", "kick_members", "moderate_members",
}

DEFAULT_CONFIG = {
    "enabled": True,
    "auto_restore_channels": True,
    "auto_restore_roles": True,
    "dm_owner": True,
    "log_channel_id": LOG_CHANNEL_ID,
    "quarantine_role_id": QUARANTINE_ROLE_ID,
    "security_profile": "balanced",
    "ai_detection": True,
    "ai_score_threshold": 8,
    "join_raid": {
        "enabled": True,
        "count": 10,
        "seconds": 20,
        "lock_minutes": 5
    },
    "protections": {
        "channel_delete": True, "channel_create": True, "channel_update": False,
        "role_delete": True, "role_create": True, "role_update": True,
        "ban": True, "kick": True, "webhook": True, "bot_add": True,
        "dangerous_role_add": True, "guild_update": True,
    },
    "limits": {
        "channel_delete": {"count": 1, "seconds": 10},
        "channel_create": {"count": 3, "seconds": 5},
        "channel_update": {"count": 3, "seconds": 10},
        "role_delete": {"count": 2, "seconds": 5},
        "role_create": {"count": 4, "seconds": 10},
        "role_update": {"count": 2, "seconds": 10},
        "ban": {"count": 3, "seconds": 5},
        "kick": {"count": 5, "seconds": 10},
        "webhook": {"count": 2, "seconds": 15},
        "bot_add": {"count": 1, "seconds": 10},
        "dangerous_role_add": {"count": 1, "seconds": 30},
        "guild_update": {"count": 1, "seconds": 20},
    },
}

SECURITY_PROFILES = {
    "balanced": {
        "channel_delete": {"count": 1, "seconds": 10},
        "channel_create": {"count": 3, "seconds": 5},
        "channel_update": {"count": 3, "seconds": 10},
        "role_delete": {"count": 2, "seconds": 5},
        "role_create": {"count": 4, "seconds": 10},
        "role_update": {"count": 2, "seconds": 10},
        "ban": {"count": 3, "seconds": 5},
        "kick": {"count": 5, "seconds": 10},
        "webhook": {"count": 2, "seconds": 15},
        "bot_add": {"count": 1, "seconds": 10},
        "dangerous_role_add": {"count": 1, "seconds": 30},
        "guild_update": {"count": 1, "seconds": 20},
    },
    "strict": {
        "channel_delete": {"count": 1, "seconds": 15},
        "channel_create": {"count": 3, "seconds": 10},
        "channel_update": {"count": 2, "seconds": 10},
        "role_delete": {"count": 1, "seconds": 15},
        "role_create": {"count": 3, "seconds": 10},
        "role_update": {"count": 2, "seconds": 10},
        "ban": {"count": 2, "seconds": 10},
        "kick": {"count": 3, "seconds": 10},
        "webhook": {"count": 1, "seconds": 15},
        "bot_add": {"count": 1, "seconds": 30},
        "dangerous_role_add": {"count": 1, "seconds": 30},
        "guild_update": {"count": 1, "seconds": 20},
    },
    "relaxed": {
        "channel_delete": {"count": 3, "seconds": 15},
        "channel_create": {"count": 8, "seconds": 15},
        "channel_update": {"count": 6, "seconds": 15},
        "role_delete": {"count": 3, "seconds": 15},
        "role_create": {"count": 8, "seconds": 15},
        "role_update": {"count": 5, "seconds": 15},
        "ban": {"count": 5, "seconds": 15},
        "kick": {"count": 6, "seconds": 15},
        "webhook": {"count": 4, "seconds": 20},
        "bot_add": {"count": 2, "seconds": 45},
        "dangerous_role_add": {"count": 1, "seconds": 30},
        "guild_update": {"count": 3, "seconds": 30},
    },
}

def save_json(path: Path, data) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    tmp.replace(path)

def load_json(path: Path, default):
    if not path.exists():
        save_json(path, default)
        return json.loads(json.dumps(default))
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return json.loads(json.dumps(default))

config = load_json(CONFIG_FILE, DEFAULT_CONFIG)
incidents = load_json(INCIDENT_FILE, [])
server_backups = load_json(BACKUPS_FILE, [])
runtime_state = load_json(RUNTIME_FILE, {"raid_mode_until": 0, "started_at": int(time.time())})

# Apply the requested default profile once, even when Railway already has an older config file.
CONFIG_VERSION = 7
if int(config.get("config_version", 0)) < CONFIG_VERSION:
    config["enabled"] = True
    config["protections"] = json.loads(json.dumps(DEFAULT_CONFIG["protections"]))
    config["limits"] = json.loads(json.dumps(DEFAULT_CONFIG["limits"]))
    config["auto_restore_channels"] = True
    config["auto_restore_roles"] = True
    config["config_version"] = CONFIG_VERSION

for key, value in DEFAULT_CONFIG.items():
    config.setdefault(key, value)
for action, value in DEFAULT_CONFIG["protections"].items():
    config["protections"].setdefault(action, value)
for action, value in DEFAULT_CONFIG["limits"].items():
    config["limits"].setdefault(action, value)
save_json(CONFIG_FILE, config)

@dataclass
class AuditResult:
    actor: Optional[discord.Member]
    entry: Optional[discord.AuditLogEntry]

intents = discord.Intents.default()
intents.guilds = True
intents.members = True
intents.moderation = True
intents.webhooks = True

class RiseTweaksSecurity(commands.Bot):
    def __init__(self):
        super().__init__(command_prefix="!", intents=intents)

    async def setup_hook(self):
        await self.tree.sync(guild=GUILD_OBJECT)

bot = RiseTweaksSecurity()
action_windows = defaultdict(deque)
recent_audit_ids = {}
self_action_until = defaultdict(float)
join_window = deque()
ai_action_windows = defaultdict(deque)
AI_ACTION_WEIGHTS = {
    "channel_delete": 5, "channel_create": 2, "channel_update": 1,
    "role_delete": 5, "role_create": 2, "role_update": 3,
    "ban": 3, "kick": 2, "webhook": 4, "bot_add": 6,
    "dangerous_role_add": 8, "guild_update": 5,
}

def has_owner_role(member) -> bool:
    return (
        isinstance(member, discord.Member)
        and any(role.id == OWNER_ROLE_ID for role in member.roles)
    )


def is_owner_exempt(member) -> bool:
    if member is None:
        return False
    return member.id == OWNER_ID or has_owner_role(member)


def owner_only():
    async def predicate(interaction: discord.Interaction):
        if not is_owner_exempt(interaction.user):
            raise app_commands.CheckFailure("Rise Tweaks owner role only.")
        return True
    return app_commands.check(predicate)

def is_exempt_actor(actor) -> bool:
    if actor is None:
        return False
    bot_id = bot.user.id if bot.user else 0
    return is_owner_exempt(actor) or actor.id in {bot_id, TRUSTED_MOD_BOT_ID}


def is_staff_or_owner(member: discord.Member) -> bool:
    return is_owner_exempt(member) or any(role.id == STAFF_ROLE_ID for role in member.roles)


def staff_or_owner_only():
    async def predicate(interaction: discord.Interaction):
        if not isinstance(interaction.user, discord.Member) or not is_staff_or_owner(interaction.user):
            raise app_commands.CheckFailure("Staff or owner only.")
        return True
    return app_commands.check(predicate)

def enabled(action: str) -> bool:
    return bool(config["enabled"] and config["protections"].get(action, False))

def get_limit(action: str):
    item = config["limits"].get(action, {"count": 1, "seconds": 10})
    return max(1, int(item["count"])), max(1, int(item["seconds"]))

def register(actor_id: int, action: str):
    count, seconds = get_limit(action)
    now = time.monotonic()
    q = action_windows[(actor_id, action)]
    while q and now - q[0] > seconds:
        q.popleft()
    q.append(now)
    return len(q) >= count, len(q), count, seconds


def register_ai_risk(actor_id: int, action: str):
    """Cross-action heuristic detection. Different suspicious actions add risk together."""
    if not config.get("ai_detection", True):
        return False, 0, int(config.get("ai_score_threshold", 8))

    now = time.monotonic()
    window = ai_action_windows[actor_id]
    while window and now - window[0][0] > 30:
        window.popleft()

    window.append((now, AI_ACTION_WEIGHTS.get(action, 1), action))
    score = sum(item[1] for item in window)
    threshold = max(3, int(config.get("ai_score_threshold", 8)))
    return score >= threshold, score, threshold


def raid_mode_active() -> bool:
    return int(runtime_state.get("raid_mode_until", 0)) > int(time.time())


def audit_seen(entry):
    if not entry:
        return False
    now = time.monotonic()
    for key, ts in list(recent_audit_ids.items()):
        if now - ts > 30:
            recent_audit_ids.pop(key, None)
    if entry.id in recent_audit_ids:
        return True
    recent_audit_ids[entry.id] = now
    return False

def dangerous_names(perms: discord.Permissions):
    return [name.replace("_", " ").title() for name in DANGEROUS_PERMISSIONS if getattr(perms, name, False)]

def dangerous_role(role: discord.Role):
    return bool(dangerous_names(role.permissions))

async def log(guild, title, description, color=discord.Color.red()):
    channel = guild.get_channel(int(config.get("log_channel_id", LOG_CHANNEL_ID)))
    if not isinstance(channel, discord.TextChannel):
        return
    embed = discord.Embed(title=title, description=description, color=color, timestamp=discord.utils.utcnow())
    embed.set_footer(text="Rise Tweaks Security • Anti-Nuke")
    try:
        await channel.send(embed=embed)
    except discord.HTTPException:
        pass


async def notify_owner(guild, title, description, color=discord.Color.red()):
    if not config.get("dm_owner", True):
        return
    user = guild.get_member(OWNER_ID) or bot.get_user(OWNER_ID)
    if not user:
        try:
            user = await bot.fetch_user(OWNER_ID)
        except discord.HTTPException:
            return
    try:
        await user.send(
            embed=discord.Embed(
                title=title,
                description=description,
                color=color,
                timestamp=discord.utils.utcnow(),
            )
        )
    except discord.HTTPException:
        pass

def record(guild, actor, action, target, result):
    incidents.append({
        "timestamp": int(time.time()), "guild_id": str(guild.id),
        "actor_id": str(actor.id) if actor else None,
        "actor": str(actor) if actor else "Unknown",
        "action": action, "target": target, "result": result,
    })
    del incidents[:-1000]
    save_json(INCIDENT_FILE, incidents)

async def fetch_audit(guild, action, target_id=None, retries=4):
    for attempt in range(retries):
        if attempt:
            await asyncio.sleep(0.8)
        try:
            async for entry in guild.audit_logs(limit=8, action=action):
                if (discord.utils.utcnow() - entry.created_at).total_seconds() > 15:
                    continue
                if target_id is not None and getattr(entry.target, "id", None) != target_id:
                    continue
                actor = guild.get_member(entry.user.id) if entry.user else None
                return AuditResult(actor, entry)
        except (discord.Forbidden, discord.HTTPException):
            break
    return AuditResult(None, None)

async def strip_roles(member):
    me = member.guild.me
    if not me:
        return []
    roles = [r for r in member.roles if r != member.guild.default_role and r.id != int(config["quarantine_role_id"]) and r < me.top_role and not r.managed]
    removed = []
    for role in roles:
        try:
            self_action_until["member_role_update"] = time.monotonic() + 5
            await member.remove_roles(role, reason="Rise Tweaks Security quarantine")
            removed.append(role.name)
        except discord.HTTPException:
            pass
    return removed

async def dm_quarantined_user(member, action, target, details):
    embed = discord.Embed(
        title="🚨 Rise Tweaks Security — You Have Been Quarantined",
        description=(
            "Suspicious administrative activity was detected.\n\n"
            f"**Server:** {member.guild.name}\n"
            f"**Detected Action:** `{action}`\n"
            f"**Target:** {target}\n"
            f"**Details:** {details}\n\n"
            "Your server roles were removed where possible and the quarantine role was applied. "
            "Contact the server owner if you believe this was a mistake."
        ),
        color=discord.Color.red(),
        timestamp=discord.utils.utcnow(),
    )
    embed.set_footer(text="Rise Tweaks Security • Anti-Nuke Protection")
    try:
        await member.send(embed=embed)
        return True
    except discord.HTTPException:
        return False


async def quarantine(guild, actor, action, target, details):
    if actor is None:
        text = f"**Action:** `{action}`\n**Target:** {target}\n**Actor:** Unknown\n**Details:** {details}"
        record(guild, None, action, target, "Unknown actor")
        await log(guild, "⚠️ Incident — Actor Unknown", text)
        await notify_owner(guild, "⚠️ Incident — Actor Unknown", text)
        return False
    if is_exempt_actor(actor):
        return False

    dm_sent = await dm_quarantined_user(actor, action, target, details)

    removed = await strip_roles(actor)
    role = guild.get_role(int(config["quarantine_role_id"]))
    added = False
    if role and guild.me and role < guild.me.top_role:
        try:
            self_action_until["member_role_update"] = time.monotonic() + 5
            await actor.add_roles(role, reason=f"Rise Tweaks Security: {action}")
            added = True
        except discord.HTTPException:
            pass

    result = f"Removed={removed}; quarantine={added}"
    record(guild, actor, action, target, result)
    text = (
        f"**Attacker:** {actor.mention} (`{actor.id}`)\n"
        f"**Action:** `{action}`\n**Target:** {target}\n"
        f"**Removed Roles:** {', '.join(removed) if removed else 'None removable'}\n"
        f"**Quarantine Added:** `{added}`\n"
        f"**User DM Sent:** `{dm_sent}`\n"
        f"**Details:** {details}"
    )
    await log(guild, "🚨 User Quarantined", text)
    await notify_owner(guild, "🚨 Rise Tweaks Security Quarantine", text)
    return added or bool(removed)

async def process(guild, actor, action, target, details, entry=None):
    if not enabled(action) or audit_seen(entry):
        return False
    if actor is None:
        await quarantine(guild, None, action, target, details)
        return False
    if is_exempt_actor(actor):
        return False

    triggered, current, threshold, seconds = register(actor.id, action)
    ai_triggered, ai_score, ai_threshold = register_ai_risk(actor.id, action)

    await log(
        guild, "🛡️ Security Action Observed",
        f"**Actor:** {actor.mention}\n**Action:** `{action}`\n**Target:** {target}\n"
        f"**Window:** `{current}/{threshold}` in `{seconds}s`\n"
        f"**Cross-Action Risk:** `{ai_score}/{ai_threshold}`\n**Details:** {details}",
        discord.Color.orange(),
    )

    if triggered or ai_triggered:
        reason = (
            f"{details} | action threshold {current}/{threshold} in {seconds}s"
            if triggered
            else f"{details} | cross-action risk score {ai_score}/{ai_threshold}"
        )
        return await quarantine(guild, actor, action, target, reason)
    return False



async def apply_quarantine_overwrite(channel: discord.abc.GuildChannel, role: discord.Role) -> bool:
    """Deny the quarantine role all channel visibility and interaction."""
    overwrite = channel.overwrites_for(role)
    overwrite.view_channel = False
    overwrite.send_messages = False
    overwrite.add_reactions = False
    overwrite.create_public_threads = False
    overwrite.create_private_threads = False
    overwrite.send_messages_in_threads = False
    overwrite.attach_files = False
    overwrite.embed_links = False
    overwrite.use_application_commands = False
    overwrite.use_external_emojis = False
    overwrite.use_external_stickers = False
    overwrite.connect = False
    overwrite.speak = False
    overwrite.stream = False
    overwrite.use_voice_activation = False
    overwrite.request_to_speak = False
    try:
        await channel.set_permissions(
            role,
            overwrite=overwrite,
            reason="Rise Tweaks Security quarantine visibility lockdown",
        )
        return True
    except (discord.Forbidden, discord.HTTPException):
        return False


async def sync_quarantine_role_permissions(guild: discord.Guild, role: discord.Role) -> tuple[int, int]:
    updated = 0
    failed = 0
    for channel in guild.channels:
        if await apply_quarantine_overwrite(channel, role):
            updated += 1
        else:
            failed += 1
    return updated, failed

async def restore_channel(channel):
    if not config.get("auto_restore_channels", True):
        return None
    guild = channel.guild
    category = guild.get_channel(channel.category_id) if channel.category_id else None
    self_action_until["channel_create"] = time.monotonic() + 5
    try:
        if isinstance(channel, discord.TextChannel):
            return await guild.create_text_channel(
                channel.name, category=category, topic=channel.topic, position=channel.position,
                slowmode_delay=channel.slowmode_delay, nsfw=channel.nsfw, overwrites=channel.overwrites,
                reason="Rise Tweaks Security channel restore",
            )
        if isinstance(channel, discord.VoiceChannel):
            return await guild.create_voice_channel(
                channel.name, category=category, position=channel.position,
                bitrate=channel.bitrate, user_limit=channel.user_limit, overwrites=channel.overwrites,
                reason="Rise Tweaks Security channel restore",
            )
        if isinstance(channel, discord.CategoryChannel):
            return await guild.create_category(channel.name, position=channel.position, overwrites=channel.overwrites, reason="Rise Tweaks Security category restore")
        if isinstance(channel, discord.ForumChannel):
            return await guild.create_forum(
                channel.name, category=category, topic=channel.topic, position=channel.position,
                slowmode_delay=channel.slowmode_delay, nsfw=channel.nsfw, overwrites=channel.overwrites,
                reason="Rise Tweaks Security forum restore",
            )
    except (discord.Forbidden, discord.HTTPException) as e:
        await log(guild, "❌ Channel Restore Failed", f"`{channel.name}`\n`{e}`")
    return None

async def restore_role(role):
    if not config.get("auto_restore_roles", True):
        return None
    self_action_until["role_create"] = time.monotonic() + 5
    try:
        restored = await role.guild.create_role(
            name=role.name, permissions=role.permissions, colour=role.colour,
            hoist=role.hoist, mentionable=role.mentionable, reason="Rise Tweaks Security role restore",
        )
        try:
            await restored.edit(position=min(role.position, role.guild.me.top_role.position - 1))
        except discord.HTTPException:
            pass
        return restored
    except (discord.Forbidden, discord.HTTPException) as e:
        await log(role.guild, "❌ Role Restore Failed", f"`{role.name}`\n`{e}`")
        return None


def serialize_overwrites(channel):
    result = {}
    for target, overwrite in channel.overwrites.items():
        result[str(target.id)] = {
            "type": "role" if isinstance(target, discord.Role) else "member",
            "allow": overwrite.pair()[0].value,
            "deny": overwrite.pair()[1].value,
        }
    return result


async def create_server_backup(guild: discord.Guild, label: str):
    backup = {
        "id": str(int(time.time())),
        "label": label[:80],
        "created_at": int(time.time()),
        "guild": {
            "name": guild.name,
            "verification_level": str(guild.verification_level),
        },
        "roles": [],
        "channels": [],
    }

    for role in sorted(guild.roles, key=lambda r: r.position):
        if role == guild.default_role or role.managed:
            continue
        backup["roles"].append({
            "id": str(role.id),
            "name": role.name,
            "permissions": role.permissions.value,
            "colour": role.colour.value,
            "hoist": role.hoist,
            "mentionable": role.mentionable,
            "position": role.position,
        })

    for channel in sorted(guild.channels, key=lambda c: c.position):
        item = {
            "id": str(channel.id),
            "name": channel.name,
            "position": channel.position,
            "category_id": str(channel.category_id) if channel.category_id else None,
            "overwrites": serialize_overwrites(channel),
        }
        if isinstance(channel, discord.CategoryChannel):
            item["type"] = "category"
        elif isinstance(channel, discord.TextChannel):
            item.update({
                "type": "text", "topic": channel.topic,
                "slowmode_delay": channel.slowmode_delay, "nsfw": channel.nsfw,
            })
        elif isinstance(channel, discord.VoiceChannel):
            item.update({
                "type": "voice", "bitrate": channel.bitrate,
                "user_limit": channel.user_limit,
            })
        else:
            continue
        backup["channels"].append(item)

    server_backups.append(backup)
    del server_backups[:-10]
    save_json(BACKUPS_FILE, server_backups)
    return backup


def build_overwrites_from_backup(guild: discord.Guild, data: dict, role_id_map: dict | None = None):
    overwrites = {}
    role_id_map = role_id_map or {}
    for target_id, item in data.items():
        if item.get("type") == "role":
            mapped_id = role_id_map.get(str(target_id), int(target_id))
            target = guild.get_role(int(mapped_id))
        else:
            target = guild.get_member(int(target_id))
        if target is None:
            continue
        allow = discord.Permissions(int(item.get("allow", 0)))
        deny = discord.Permissions(int(item.get("deny", 0)))
        overwrites[target] = discord.PermissionOverwrite.from_pair(allow, deny)
    return overwrites


async def restore_server_backup(guild: discord.Guild, backup: dict):
    """Non-destructive recovery: recreate missing roles/channels without deleting current ones."""
    created_roles = 0
    created_channels = 0
    failed = 0
    role_id_map = {}

    existing_role_names = {role.name for role in guild.roles}
    for role_data in backup.get("roles", []):
        if role_data["name"] in existing_role_names:
            match = discord.utils.find(lambda r: r.name == role_data["name"], guild.roles)
            if match:
                role_id_map[role_data["id"]] = match.id
            continue
        try:
            role = await guild.create_role(
                name=role_data["name"],
                permissions=discord.Permissions(int(role_data["permissions"])),
                colour=discord.Colour(int(role_data["colour"])),
                hoist=bool(role_data["hoist"]),
                mentionable=bool(role_data["mentionable"]),
                reason="Rise Tweaks Security backup recovery",
            )
            role_id_map[role_data["id"]] = role.id
            existing_role_names.add(role.name)
            created_roles += 1
        except discord.HTTPException:
            failed += 1

    category_map = {}
    existing_categories = {category.name: category for category in guild.categories}
    for channel_data in backup.get("channels", []):
        if channel_data.get("type") != "category":
            continue
        category = existing_categories.get(channel_data["name"])
        if category is None:
            try:
                category = await guild.create_category(
                    channel_data["name"],
                    overwrites=build_overwrites_from_backup(guild, channel_data.get("overwrites", {}), role_id_map),
                    reason="Rise Tweaks Security backup recovery",
                )
                existing_categories[category.name] = category
                created_channels += 1
            except discord.HTTPException:
                failed += 1
                continue
        category_map[channel_data["id"]] = category

    existing_names = {(type(c).__name__, c.name) for c in guild.channels}
    for channel_data in backup.get("channels", []):
        channel_type = channel_data.get("type")
        if channel_type == "category":
            continue
        class_name = "TextChannel" if channel_type == "text" else "VoiceChannel"
        if (class_name, channel_data["name"]) in existing_names:
            continue

        category = category_map.get(channel_data.get("category_id"))
        overwrites = build_overwrites_from_backup(guild, channel_data.get("overwrites", {}), role_id_map)
        try:
            if channel_type == "text":
                await guild.create_text_channel(
                    channel_data["name"],
                    category=category,
                    topic=channel_data.get("topic"),
                    slowmode_delay=int(channel_data.get("slowmode_delay", 0)),
                    nsfw=bool(channel_data.get("nsfw", False)),
                    overwrites=overwrites,
                    reason="Rise Tweaks Security backup recovery",
                )
            elif channel_type == "voice":
                await guild.create_voice_channel(
                    channel_data["name"],
                    category=category,
                    bitrate=min(int(channel_data.get("bitrate", 64000)), guild.bitrate_limit),
                    user_limit=int(channel_data.get("user_limit", 0)),
                    overwrites=overwrites,
                    reason="Rise Tweaks Security backup recovery",
                )
            else:
                continue
            created_channels += 1
            existing_names.add((class_name, channel_data["name"]))
        except discord.HTTPException:
            failed += 1

    return created_roles, created_channels, failed


async def emergency_lock_guild(
    guild: discord.Guild,
    reason: str,
    backup_file: Path = LOCKDOWN_FILE,
):
    if not backup_file.exists():
        backup = {}
        for channel in guild.channels:
            overwrite = channel.overwrites_for(guild.default_role)
            backup[str(channel.id)] = {
                "send_messages": overwrite.send_messages,
                "add_reactions": overwrite.add_reactions,
                "connect": overwrite.connect,
                "speak": overwrite.speak,
            }
        save_json(backup_file, backup)

    changed = 0
    for channel in guild.channels:
        overwrite = channel.overwrites_for(guild.default_role)
        if isinstance(channel, (discord.TextChannel, discord.ForumChannel)):
            overwrite.send_messages = False
            overwrite.add_reactions = False
        elif isinstance(channel, (discord.VoiceChannel, discord.StageChannel)):
            overwrite.connect = False
            overwrite.speak = False
        else:
            continue
        try:
            await channel.set_permissions(guild.default_role, overwrite=overwrite, reason=reason)
            changed += 1
        except discord.HTTPException:
            pass
    return changed


async def restore_lockdown_backup(guild: discord.Guild, backup_file: Path):
    backup = load_json(backup_file, {})
    if not backup:
        return 0, 0

    restored = 0
    failed = 0
    for channel_id, values in backup.items():
        channel = guild.get_channel(int(channel_id))
        if channel is None:
            continue
        overwrite = channel.overwrites_for(guild.default_role)
        overwrite.send_messages = values.get("send_messages")
        overwrite.add_reactions = values.get("add_reactions")
        overwrite.connect = values.get("connect")
        overwrite.speak = values.get("speak")
        try:
            await channel.set_permissions(
                guild.default_role,
                overwrite=overwrite,
                reason="Rise Tweaks Security lockdown restore",
            )
            restored += 1
        except discord.HTTPException:
            failed += 1

    backup_file.unlink(missing_ok=True)
    return restored, failed


async def activate_join_raid_mode(guild: discord.Guild, count: int, seconds: int):
    if raid_mode_active():
        return
    minutes = max(1, int(config.get("join_raid", {}).get("lock_minutes", 5)))
    runtime_state["raid_mode_until"] = int(time.time()) + minutes * 60
    save_json(RUNTIME_FILE, runtime_state)
    changed = await emergency_lock_guild(
        guild,
        "Rise Tweaks Security automatic join-raid lockdown",
        RAID_LOCKDOWN_FILE,
    )
    text = (
        f"**Detected:** `{count}` joins within `{seconds}` seconds\n"
        f"**Raid Mode:** `{minutes}` minutes\n"
        f"**Channels Locked:** `{changed}`"
    )
    await log(guild, "🚨 Join Raid Mode Activated", text, discord.Color.red())
    await notify_owner(guild, "🚨 Join Raid Mode Activated", text)


@tasks.loop(seconds=30)
async def raid_mode_watcher():
    until = int(runtime_state.get("raid_mode_until", 0))
    if until <= 0 or until > int(time.time()):
        return

    guild = bot.get_guild(GUILD_ID)
    if guild is None:
        return

    restored, failed = await restore_lockdown_backup(guild, RAID_LOCKDOWN_FILE)
    runtime_state["raid_mode_until"] = 0
    save_json(RUNTIME_FILE, runtime_state)
    text = f"**Channels restored:** `{restored}`\n**Failed:** `{failed}`"
    await log(guild, "✅ Join Raid Mode Ended", text, discord.Color.green())
    await notify_owner(guild, "✅ Join Raid Mode Ended", text, discord.Color.green())


@raid_mode_watcher.before_loop
async def before_raid_mode_watcher():
    await bot.wait_until_ready()


@bot.event
async def on_ready():
    if not raid_mode_watcher.is_running():
        raid_mode_watcher.start()
    print(f"Rise Tweaks Security online as {bot.user}")

@bot.event
async def on_guild_channel_delete(channel):
    result = await fetch_audit(channel.guild, discord.AuditLogAction.channel_delete, channel.id)
    # The configured owner can delete channels freely. Do not restore them.
    if result.actor and is_exempt_actor(result.actor):
        await log(channel.guild, "✅ Owner Channel Deletion Allowed", f"**Owner:** {result.actor.mention}\n**Channel:** `#{channel.name}`", discord.Color.green())
        return
    await process(channel.guild, result.actor, "channel_delete", f"`#{channel.name}`", "Channel deleted.", result.entry)
    restored = await restore_channel(channel)
    if restored:
        await log(channel.guild, "♻️ Channel Restored", f"`#{channel.name}` restored as {restored.mention}", discord.Color.green())

@bot.event
async def on_guild_channel_create(channel):
    # Always apply quarantine deny permissions to newly created channels.
    quarantine_role = channel.guild.get_role(int(config.get("quarantine_role_id") or QUARANTINE_ROLE_ID))
    if quarantine_role:
        await apply_quarantine_overwrite(channel, quarantine_role)

    if time.monotonic() < self_action_until["channel_create"]:
        return
    result = await fetch_audit(channel.guild, discord.AuditLogAction.channel_create, channel.id)
    triggered = await process(channel.guild, result.actor, "channel_create", f"`#{channel.name}`", "Channel created.", result.entry)
    if triggered:
        try:
            await channel.delete(reason="Rise Tweaks Security removed suspicious channel")
        except discord.HTTPException:
            pass

@bot.event
async def on_guild_channel_update(before, after):
    result = await fetch_audit(after.guild, discord.AuditLogAction.channel_update, after.id)
    await process(after.guild, result.actor, "channel_update", f"`#{after.name}`", "Channel settings changed.", result.entry)

@bot.event
async def on_guild_role_delete(role):
    result = await fetch_audit(role.guild, discord.AuditLogAction.role_delete, role.id)
    # The configured owner can delete roles freely. Do not restore them.
    if result.actor and is_exempt_actor(result.actor):
        await log(role.guild, "✅ Owner Role Deletion Allowed", f"**Owner:** {result.actor.mention}\n**Role:** `@{role.name}`", discord.Color.green())
        return
    await process(role.guild, result.actor, "role_delete", f"`@{role.name}`", "Role deleted.", result.entry)
    restored = await restore_role(role)
    if restored:
        await log(role.guild, "♻️ Role Restored", f"`@{role.name}` restored as {restored.mention}", discord.Color.green())

@bot.event
async def on_guild_role_create(role):
    if time.monotonic() < self_action_until["role_create"]:
        return
    result = await fetch_audit(role.guild, discord.AuditLogAction.role_create, role.id)
    triggered = await process(role.guild, result.actor, "role_create", f"`@{role.name}`", f"Dangerous: {dangerous_names(role.permissions) or 'None'}", result.entry)
    if (triggered or dangerous_role(role)) and result.actor and not is_exempt_actor(result.actor):
        try:
            await role.delete(reason="Rise Tweaks Security suspicious role")
        except discord.HTTPException:
            pass

@bot.event
async def on_guild_role_update(before, after):
    before_d = set(dangerous_names(before.permissions))
    after_d = set(dangerous_names(after.permissions))
    added = sorted(after_d - before_d)
    result = await fetch_audit(after.guild, discord.AuditLogAction.role_update, after.id)
    triggered = await process(after.guild, result.actor, "role_update", f"`@{after.name}`", f"New dangerous permissions: {added or 'None'}", result.entry)
    if added and result.actor and not is_exempt_actor(result.actor) and not triggered:
        triggered = await quarantine(
            after.guild,
            result.actor,
            "role_update",
            after.mention,
            f"Added: {', '.join(added)}",
        )
    if triggered and after.guild.me and after < after.guild.me.top_role:
        try:
            self_action_until["role_update"] = time.monotonic() + 5
            await after.edit(permissions=before.permissions, colour=before.colour, hoist=before.hoist, mentionable=before.mentionable, reason="Rise Tweaks Security revert")
        except discord.HTTPException:
            pass

@bot.event
async def on_member_ban(guild, user):
    result = await fetch_audit(guild, discord.AuditLogAction.ban, user.id)
    triggered = await process(guild, result.actor, "ban", f"`{user}`", "Member banned.", result.entry)
    if triggered:
        try:
            await guild.unban(user, reason="Rise Tweaks Security reversed suspected mass-ban")
        except discord.HTTPException:
            pass

@bot.event
async def on_member_remove(member):
    result = await fetch_audit(member.guild, discord.AuditLogAction.kick, member.id, retries=3)
    if result.entry:
        await process(member.guild, result.actor, "kick", f"`{member}`", "Member kicked.", result.entry)

@bot.event
async def on_member_join(member):
    if member.bot:
        result = await fetch_audit(member.guild, discord.AuditLogAction.bot_add, member.id)
        triggered = await process(member.guild, result.actor, "bot_add", f"`{member}`", "Bot added.", result.entry)
        if triggered:
            try:
                await member.kick(reason="Rise Tweaks Security unauthorized bot")
            except discord.HTTPException:
                pass
        return

    join_config = config.get("join_raid", {})
    if not join_config.get("enabled", True):
        return

    now = time.monotonic()
    seconds = max(2, int(join_config.get("seconds", 20)))
    threshold = max(3, int(join_config.get("count", 10)))
    while join_window and now - join_window[0] > seconds:
        join_window.popleft()
    join_window.append(now)

    if len(join_window) >= threshold:
        await activate_join_raid_mode(member.guild, len(join_window), seconds)

@bot.event
async def on_member_update(before, after):
    if time.monotonic() < self_action_until["member_role_update"]:
        return

    added = [r for r in after.roles if r not in before.roles and dangerous_role(r)]
    if not added:
        return

    result = await fetch_audit(
        after.guild,
        discord.AuditLogAction.member_role_update,
        after.id,
    )
    actor = result.actor
    names = ", ".join(r.name for r in added)

    # The configured owner is always allowed to assign admin/dangerous roles.
    # Never remove a role when the audit-log actor cannot be confirmed.
    if actor is None:
        await log(
            after.guild,
            "⚠️ Dangerous Role Assignment — Actor Unknown",
            f"**Member:** {after.mention} (`{after.id}`)\n"
            f"**Roles Added:** {names}\n"
            "No role was removed because Rise Tweaks Security could not confirm who assigned it.",
            discord.Color.orange(),
        )
        await notify_owner(
            after.guild,
            "⚠️ Dangerous Role Assignment — Actor Unknown",
            f"**Member:** {after.mention} (`{after.id}`)\n"
            f"**Roles Added:** {names}\n"
            "No automatic removal was performed.",
            discord.Color.orange(),
        )
        return

    if is_owner_exempt(actor) or (bot.user and actor.id == bot.user.id):
        await log(
            after.guild,
            "✅ Owner Role Assignment Allowed",
            f"**Assigned By:** {actor.mention} (`{actor.id}`)\n"
            f"**Member:** {after.mention} (`{after.id}`)\n"
            f"**Roles Added:** {names}",
            discord.Color.green(),
        )
        return

    await quarantine(
        after.guild,
        actor,
        "dangerous_role_add",
        after.mention,
        f"Assigned dangerous roles: {names}",
    )

    removable = [
        r for r in added
        if after.guild.me and r < after.guild.me.top_role and not r.managed
    ]
    if removable:
        try:
            self_action_until["member_role_update"] = time.monotonic() + 5
            await after.remove_roles(
                *removable,
                reason="Rise Tweaks Security unauthorized dangerous role removal",
            )
        except discord.HTTPException:
            pass

@bot.event
async def on_webhooks_update(channel):
    for audit_action in (discord.AuditLogAction.webhook_create, discord.AuditLogAction.webhook_update, discord.AuditLogAction.webhook_delete):
        result = await fetch_audit(channel.guild, audit_action, retries=2)
        if not result.entry:
            continue
        triggered = await process(channel.guild, result.actor, "webhook", f"`#{channel.name}`", f"`{audit_action.name}`", result.entry)
        if triggered and audit_action == discord.AuditLogAction.webhook_create:
            try:
                webhook = discord.utils.get(await channel.webhooks(), id=getattr(result.entry.target, "id", None))
                if webhook:
                    await webhook.delete(reason="Rise Tweaks Security suspicious webhook")
            except discord.HTTPException:
                pass
        break

@bot.event
async def on_guild_update(before, after):
    result = await fetch_audit(after, discord.AuditLogAction.guild_update)
    await process(after, result.actor, "guild_update", f"`{after.name}`", f"Guild changed from `{before.name}` to `{after.name}`.", result.entry)

ACTION_CHOICES = [
    app_commands.Choice(name=x.replace("_", " ").title(), value=x)
    for x in DEFAULT_CONFIG["protections"]
]

@bot.tree.command(name="securitysetup", description="Validate Rise Tweaks Security setup.", guild=GUILD_OBJECT)
@app_commands.default_permissions(administrator=True)
@owner_only()
async def securitysetup(interaction):
    guild = interaction.guild
    me = guild.me
    p = me.guild_permissions
    checks = {
        "View Audit Log": p.view_audit_log, "Manage Roles": p.manage_roles,
        "Manage Channels": p.manage_channels, "Manage Webhooks": p.manage_webhooks,
        "Moderate Members": p.moderate_members, "Ban Members": p.ban_members,
        "Kick Members": p.kick_members,
    }
    role = guild.get_role(int(config["quarantine_role_id"]))
    channel = guild.get_channel(int(config["log_channel_id"]))
    lines = [f"{'✅' if ok else '❌'} **{name}**" for name, ok in checks.items()]
    lines += [
        f"{'✅' if role else '❌'} **Quarantine role found**",
        f"{'✅' if channel else '❌'} **Log channel found**",
        f"{'✅' if role and role < me.top_role else '❌'} **Bot role above quarantine role**",
    ]
    await interaction.response.send_message(embed=discord.Embed(title="🛡️ Setup Check", description="\n".join(lines), color=discord.Color.blue()), ephemeral=True)

@bot.tree.command(name="securitystatus", description="Show protections and limits.", guild=GUILD_OBJECT)
@app_commands.default_permissions(administrator=True)
@owner_only()
async def securitystatus(interaction):
    text = f"**Master:** `{config['enabled']}`\n\n"
    for action, state in config["protections"].items():
        limit = config["limits"][action]
        text += f"**{action.replace('_',' ').title()}** — `{'ON' if state else 'OFF'}` — `{limit['count']}` / `{limit['seconds']}s`\n"
    await interaction.response.send_message(embed=discord.Embed(title="🛡️ Security Status", description=text[:4096], color=discord.Color.blue()), ephemeral=True)

@bot.tree.command(name="antinuke", description="Enable anti-nuke with an automatic security profile.", guild=GUILD_OBJECT)
@app_commands.choices(profile=[
    app_commands.Choice(name="Balanced (recommended)", value="balanced"),
    app_commands.Choice(name="Strict", value="strict"),
    app_commands.Choice(name="Relaxed", value="relaxed"),
])
@app_commands.default_permissions(administrator=True)
@owner_only()
async def antinuke(
    interaction: discord.Interaction,
    enabled: bool,
    profile: app_commands.Choice[str] | None = None,
):
    selected = profile.value if profile else "balanced"
    config["enabled"] = enabled

    if enabled:
        config["security_profile"] = selected
        # Enable every protection module and apply a complete preset automatically.
        for action in config["protections"]:
            config["protections"][action] = True
        # Channel update protection is intentionally off by default to avoid false positives
        # from normal permission and channel edits.
        if selected == "balanced":
            config["protections"]["channel_update"] = False
        config["limits"] = json.loads(json.dumps(SECURITY_PROFILES[selected]))
        config["auto_restore_channels"] = True
        config["auto_restore_roles"] = True
        action_windows.clear()

    save_json(CONFIG_FILE, config)

    if enabled:
        await interaction.response.send_message(
            f"✅ Anti-nuke enabled with the **{selected.title()}** profile.\n"
            "All protection modules and automatic channel/role restoration are enabled.\n"
            f"The configured owner <@{OWNER_ID}> is fully exempt from every automatic action.",
            ephemeral=True,
        )
    else:
        await interaction.response.send_message("✅ Anti-nuke protection disabled.", ephemeral=True)

@bot.tree.command(name="protection", description="Toggle one protection.", guild=GUILD_OBJECT)
@app_commands.choices(action=ACTION_CHOICES)
@app_commands.default_permissions(administrator=True)
@owner_only()
async def protection(interaction, action: app_commands.Choice[str], enabled: bool):
    config["protections"][action.value] = enabled
    save_json(CONFIG_FILE, config)
    await interaction.response.send_message(f"✅ `{action.value}` set to `{enabled}`.", ephemeral=True)

@bot.tree.command(name="setlimit", description="Set action threshold.", guild=GUILD_OBJECT)
@app_commands.choices(action=ACTION_CHOICES)
@app_commands.default_permissions(administrator=True)
@owner_only()
async def setlimit(interaction, action: app_commands.Choice[str], count: app_commands.Range[int,1,25], seconds: app_commands.Range[int,1,300]):
    config["limits"][action.value] = {"count": int(count), "seconds": int(seconds)}
    action_windows.clear()
    save_json(CONFIG_FILE, config)
    await interaction.response.send_message(f"✅ `{action.value}` triggers at `{count}` in `{seconds}s`.", ephemeral=True)

@bot.tree.command(name="setsecuritylog", description="Set security log channel.", guild=GUILD_OBJECT)
@app_commands.default_permissions(administrator=True)
@owner_only()
async def setsecuritylog(interaction, channel: discord.TextChannel):
    config["log_channel_id"] = channel.id
    save_json(CONFIG_FILE, config)
    await interaction.response.send_message(f"✅ Logs set to {channel.mention}.", ephemeral=True)

async def configure_quarantine_role(interaction: discord.Interaction, role: discord.Role):
    if role >= interaction.guild.me.top_role:
        return await interaction.response.send_message("❌ Role must be below the bot role.", ephemeral=True)
    config["quarantine_role_id"] = role.id
    save_json(CONFIG_FILE, config)
    await interaction.response.defer(ephemeral=True)
    updated, failed = await sync_quarantine_role_permissions(interaction.guild, role)
    await interaction.followup.send(
        f"✅ Quarantine role set to {role.mention}.\n"
        f"Denied access in `{updated}` channel(s). Failed: `{failed}`.",
        ephemeral=True,
    )


@bot.tree.command(name="quarantinerole", description="Set and fully lock down the quarantine role.", guild=GUILD_OBJECT)
@app_commands.default_permissions(administrator=True)
@owner_only()
async def quarantinerole_command(interaction: discord.Interaction, role: discord.Role):
    await configure_quarantine_role(interaction, role)


@bot.tree.command(name="setquarantinerole", description="Set and fully lock down the quarantine role.", guild=GUILD_OBJECT)
@app_commands.default_permissions(administrator=True)
@owner_only()
async def setquarantinerole(interaction: discord.Interaction, role: discord.Role):
    await configure_quarantine_role(interaction, role)


@bot.tree.command(name="syncquarantine", description="Reapply quarantine denies to every channel.", guild=GUILD_OBJECT)
@app_commands.default_permissions(administrator=True)
@owner_only()
async def syncquarantine(interaction: discord.Interaction):
    role = interaction.guild.get_role(int(config.get("quarantine_role_id") or QUARANTINE_ROLE_ID))
    if not role:
        return await interaction.response.send_message("❌ Quarantine role not found.", ephemeral=True)
    await interaction.response.defer(ephemeral=True)
    updated, failed = await sync_quarantine_role_permissions(interaction.guild, role)
    await interaction.followup.send(
        f"✅ Quarantine permissions synced across `{updated}` channel(s). Failed: `{failed}`.",
        ephemeral=True,
    )

@bot.tree.command(name="quarantine", description="Manually quarantine a member.", guild=GUILD_OBJECT)
@app_commands.default_permissions(administrator=True)
@owner_only()
async def quarantine_command(interaction, member: discord.Member, reason: str = "Manual quarantine"):
    if is_owner_exempt(member):
        return await interaction.response.send_message("❌ Owner is exempt.", ephemeral=True)
    await interaction.response.defer(ephemeral=True)
    ok = await quarantine(interaction.guild, member, "manual", member.mention, reason)
    await interaction.followup.send(f"{'✅' if ok else '⚠️'} Quarantine finished.", ephemeral=True)

@bot.tree.command(name="unquarantine", description="Remove quarantine role.", guild=GUILD_OBJECT)
@app_commands.default_permissions(administrator=True)
@owner_only()
async def unquarantine(interaction, member: discord.Member):
    role = interaction.guild.get_role(int(config["quarantine_role_id"]))
    if not role:
        return await interaction.response.send_message("❌ Role not found.", ephemeral=True)
    await member.remove_roles(role, reason="Owner unquarantine")
    await interaction.response.send_message(f"✅ Unquarantined {member.mention}. Removed roles are not restored.", ephemeral=True)

@bot.tree.command(name="restoreprotection", description="Toggle automatic restoration.", guild=GUILD_OBJECT)
@app_commands.default_permissions(administrator=True)
@owner_only()
async def restoreprotection(interaction, channels: bool, roles: bool):
    config["auto_restore_channels"] = channels
    config["auto_restore_roles"] = roles
    save_json(CONFIG_FILE, config)
    await interaction.response.send_message(f"✅ Channels `{channels}`; roles `{roles}`.", ephemeral=True)

@bot.tree.command(name="incidentlog", description="Show recent incidents.", guild=GUILD_OBJECT)
@app_commands.default_permissions(administrator=True)
@owner_only()
async def incidentlog(interaction, amount: app_commands.Range[int,1,20] = 10):
    rows = list(reversed(incidents[-int(amount):]))
    if not rows:
        return await interaction.response.send_message("No incidents.", ephemeral=True)
    text = "\n".join(f"<t:{r['timestamp']}:R> — **{r['action']}** — `{r['actor']}` — {r['target']}" for r in rows)
    await interaction.response.send_message(embed=discord.Embed(title="🚨 Incidents", description=text[:4096], color=discord.Color.red()), ephemeral=True)

@bot.tree.command(name="clearincidents", description="Clear incident history.", guild=GUILD_OBJECT)
@app_commands.default_permissions(administrator=True)
@owner_only()
async def clearincidents(interaction):
    incidents.clear()
    save_json(INCIDENT_FILE, incidents)
    await interaction.response.send_message("✅ Cleared.", ephemeral=True)

@bot.tree.command(name="lockdown", description="Lock all text and voice channels.", guild=GUILD_OBJECT)
@app_commands.default_permissions(administrator=True)
@owner_only()
async def lockdown(interaction):
    guild = interaction.guild
    backup = {}
    await interaction.response.defer(ephemeral=True)
    changed = failed = 0
    for channel in guild.channels:
        ow = channel.overwrites_for(guild.default_role)
        backup[str(channel.id)] = {
            "send_messages": ow.send_messages, "add_reactions": ow.add_reactions,
            "connect": ow.connect, "speak": ow.speak,
        }
        if isinstance(channel, (discord.TextChannel, discord.ForumChannel)):
            ow.send_messages = False
            ow.add_reactions = False
        elif isinstance(channel, (discord.VoiceChannel, discord.StageChannel)):
            ow.connect = False
            ow.speak = False
        else:
            continue
        try:
            await channel.set_permissions(guild.default_role, overwrite=ow, reason="Rise Tweaks Security lockdown")
            changed += 1
        except discord.HTTPException:
            failed += 1
    save_json(LOCKDOWN_FILE, backup)
    await interaction.followup.send(f"🔒 Locked `{changed}`; failed `{failed}`.", ephemeral=True)

@bot.tree.command(name="unlockdown", description="Restore pre-lockdown permissions.", guild=GUILD_OBJECT)
@app_commands.default_permissions(administrator=True)
@owner_only()
async def unlockdown(interaction):
    if not LOCKDOWN_FILE.exists():
        return await interaction.response.send_message("❌ No backup found.", ephemeral=True)
    await interaction.response.defer(ephemeral=True)
    restored, failed = await restore_lockdown_backup(interaction.guild, LOCKDOWN_FILE)
    await interaction.followup.send(f"🔓 Restored `{restored}`; failed `{failed}`.", ephemeral=True)

@bot.tree.command(name="securitytest", description="Send a test alert.", guild=GUILD_OBJECT)
@app_commands.default_permissions(administrator=True)
@owner_only()
async def securitytest(interaction):
    await interaction.response.send_message("✅ Test sent.", ephemeral=True)
    text = f"Test by {interaction.user.mention}; nobody was punished."
    await log(interaction.guild, "🧪 Test Alert", text, discord.Color.blue())
    await notify_owner(interaction.guild, "🧪 Test Alert", text)



@bot.tree.command(name="backupcreate", description="Create a server structure backup.", guild=GUILD_OBJECT)
@app_commands.default_permissions(administrator=True)
@owner_only()
async def backupcreate(interaction: discord.Interaction, label: str = "Manual backup"):
    await interaction.response.defer(ephemeral=True)
    backup = await create_server_backup(interaction.guild, label)
    await interaction.followup.send(
        f"✅ Backup `{backup['id']}` created with `{len(backup['roles'])}` roles and `{len(backup['channels'])}` channels.",
        ephemeral=True,
    )


@bot.tree.command(name="backuplist", description="List saved server backups.", guild=GUILD_OBJECT)
@app_commands.default_permissions(administrator=True)
@owner_only()
async def backuplist(interaction: discord.Interaction):
    if not server_backups:
        return await interaction.response.send_message("No backups saved.", ephemeral=True)
    lines = [
        f"`{item['id']}` — **{item.get('label', 'Backup')}** — <t:{item['created_at']}:R> "
        f"— `{len(item.get('roles', []))}` roles / `{len(item.get('channels', []))}` channels"
        for item in reversed(server_backups)
    ]
    await interaction.response.send_message(
        embed=discord.Embed(title="💾 Rise Tweaks Security Backups", description="\n".join(lines)[:4096], color=discord.Color.blue()),
        ephemeral=True,
    )


@bot.tree.command(name="backuprestore", description="Recreate missing roles and channels from a backup.", guild=GUILD_OBJECT)
@app_commands.default_permissions(administrator=True)
@owner_only()
async def backuprestore(interaction: discord.Interaction, backup_id: str):
    backup = next((item for item in server_backups if item.get("id") == backup_id), None)
    if backup is None:
        return await interaction.response.send_message("❌ Backup ID not found.", ephemeral=True)
    await interaction.response.defer(ephemeral=True)
    roles, channels, failed = await restore_server_backup(interaction.guild, backup)
    await interaction.followup.send(
        f"✅ Recovery finished. Created `{roles}` roles and `{channels}` channels; failed `{failed}` operations.",
        ephemeral=True,
    )


@bot.tree.command(name="backupdelete", description="Delete a saved backup.", guild=GUILD_OBJECT)
@app_commands.default_permissions(administrator=True)
@owner_only()
async def backupdelete(interaction: discord.Interaction, backup_id: str):
    before = len(server_backups)
    server_backups[:] = [item for item in server_backups if item.get("id") != backup_id]
    if len(server_backups) == before:
        return await interaction.response.send_message("❌ Backup ID not found.", ephemeral=True)
    save_json(BACKUPS_FILE, server_backups)
    await interaction.response.send_message(f"✅ Deleted backup `{backup_id}`.", ephemeral=True)


@bot.tree.command(name="panic", description="Emergency hardening: strict profile, lockdown, and remove dangerous staff roles.", guild=GUILD_OBJECT)
@app_commands.default_permissions(administrator=True)
@owner_only()
async def panic(interaction: discord.Interaction, confirm: bool):
    if not confirm:
        return await interaction.response.send_message(
            "❌ Run the command again with `confirm:true`. Panic mode locks the server and strips dangerous roles from non-owner members.",
            ephemeral=True,
        )

    await interaction.response.defer(ephemeral=True)
    config["enabled"] = True
    config["security_profile"] = "strict"
    config["limits"] = json.loads(json.dumps(SECURITY_PROFILES["strict"]))
    config["protections"] = {key: True for key in config["protections"]}
    save_json(CONFIG_FILE, config)

    changed = await emergency_lock_guild(interaction.guild, "Rise Tweaks Security owner panic mode")
    affected = 0
    for member in interaction.guild.members:
        if is_owner_exempt(member) or member.bot:
            continue
        dangerous = [role for role in member.roles if role != interaction.guild.default_role and dangerous_role(role)]
        removable = [role for role in dangerous if interaction.guild.me and role < interaction.guild.me.top_role and not role.managed]
        if not removable:
            continue
        try:
            await member.remove_roles(*removable, reason="Rise Tweaks Security panic mode", atomic=True)
            affected += 1
        except discord.HTTPException:
            pass

    await interaction.followup.send(
        f"🚨 Panic mode active. Locked `{changed}` channels and stripped dangerous roles from `{affected}` member(s).",
        ephemeral=True,
    )
    await notify_owner(
        interaction.guild,
        "🚨 Panic Mode Activated",
        f"**Channels locked:** `{changed}`\n**Members stripped:** `{affected}`",
    )


@bot.tree.command(name="aidetection", description="Configure cross-action intelligent detection.", guild=GUILD_OBJECT)
@app_commands.default_permissions(administrator=True)
@owner_only()
async def aidetection(interaction: discord.Interaction, enabled: bool, threshold: app_commands.Range[int, 3, 30] = 8):
    config["ai_detection"] = enabled
    config["ai_score_threshold"] = int(threshold)
    save_json(CONFIG_FILE, config)
    ai_action_windows.clear()
    await interaction.response.send_message(
        f"✅ AI-style cross-action detection set to `{enabled}` with threshold `{threshold}`.",
        ephemeral=True,
    )


@bot.tree.command(name="joinraid", description="Configure mass-join raid protection.", guild=GUILD_OBJECT)
@app_commands.default_permissions(administrator=True)
@owner_only()
async def joinraid(
    interaction: discord.Interaction,
    enabled: bool,
    count: app_commands.Range[int, 3, 100] = 10,
    seconds: app_commands.Range[int, 5, 300] = 20,
    lock_minutes: app_commands.Range[int, 1, 60] = 5,
):
    config["join_raid"] = {
        "enabled": enabled,
        "count": int(count),
        "seconds": int(seconds),
        "lock_minutes": int(lock_minutes),
    }
    save_json(CONFIG_FILE, config)
    join_window.clear()
    await interaction.response.send_message(
        f"✅ Join raid protection `{enabled}`: `{count}` joins in `{seconds}s` triggers a `{lock_minutes}` minute lockdown.",
        ephemeral=True,
    )


@bot.tree.command(name="raidstatus", description="Show or disable automatic raid mode.", guild=GUILD_OBJECT)
@app_commands.default_permissions(administrator=True)
@owner_only()
async def raidstatus(interaction: discord.Interaction, disable: bool = False):
    if disable:
        await interaction.response.defer(ephemeral=True)
        restored, failed = await restore_lockdown_backup(interaction.guild, RAID_LOCKDOWN_FILE)
        runtime_state["raid_mode_until"] = 0
        save_json(RUNTIME_FILE, runtime_state)
        return await interaction.followup.send(
            f"✅ Raid mode disabled. Restored `{restored}` channel(s); failed `{failed}`.",
            ephemeral=True,
        )

    until = int(runtime_state.get("raid_mode_until", 0))
    status = f"Active until <t:{until}:R>" if until > int(time.time()) else "Inactive"
    await interaction.response.send_message(f"🛡️ Raid mode: **{status}**", ephemeral=True)





@bot.tree.error
async def command_error(interaction, error):
    message = "❌ Owner only." if isinstance(error, app_commands.CheckFailure) else f"❌ `{error}`"
    try:
        if interaction.response.is_done():
            await interaction.followup.send(message, ephemeral=True)
        else:
            await interaction.response.send_message(message, ephemeral=True)
    except discord.HTTPException:
        pass


@bot.tree.command(name="ban", description="Ban a member using Rise Tweaks Security.", guild=GUILD_OBJECT)
@app_commands.default_permissions(ban_members=True)
@staff_or_owner_only()
async def staff_ban(
    interaction: discord.Interaction,
    member: discord.Member,
    reason: str = "No reason provided",
):
    if is_owner_exempt(member):
        return await interaction.response.send_message("❌ The configured owner cannot be banned.", ephemeral=True)
    if interaction.guild.me and member.top_role >= interaction.guild.me.top_role:
        return await interaction.response.send_message("❌ My role is not high enough to ban that member.", ephemeral=True)
    await interaction.response.defer(ephemeral=True)
    try:
        await member.send(embed=discord.Embed(
            title="🔨 You Have Been Banned",
            description=f"**Server:** {interaction.guild.name}\n**Reason:** {reason}",
            color=discord.Color.red(),
        ))
    except discord.HTTPException:
        pass
    await interaction.guild.ban(member, reason=f"{reason} | By {interaction.user}")
    await interaction.followup.send(f"✅ Banned {member.mention}.", ephemeral=True)
    await log(interaction.guild, "🔨 Staff Ban", f"**Member:** `{member}` (`{member.id}`)\n**Staff:** {interaction.user.mention}\n**Reason:** {reason}", discord.Color.red())


@bot.tree.command(name="kick", description="Kick a member using Rise Tweaks Security.", guild=GUILD_OBJECT)
@app_commands.default_permissions(kick_members=True)
@staff_or_owner_only()
async def staff_kick(
    interaction: discord.Interaction,
    member: discord.Member,
    reason: str = "No reason provided",
):
    if is_owner_exempt(member):
        return await interaction.response.send_message("❌ The configured owner cannot be kicked.", ephemeral=True)
    if interaction.guild.me and member.top_role >= interaction.guild.me.top_role:
        return await interaction.response.send_message("❌ My role is not high enough to kick that member.", ephemeral=True)
    await interaction.response.defer(ephemeral=True)
    try:
        await member.send(embed=discord.Embed(
            title="👢 You Have Been Kicked",
            description=f"**Server:** {interaction.guild.name}\n**Reason:** {reason}",
            color=discord.Color.orange(),
        ))
    except discord.HTTPException:
        pass
    await member.kick(reason=f"{reason} | By {interaction.user}")
    await interaction.followup.send(f"✅ Kicked `{member}`.", ephemeral=True)
    await log(interaction.guild, "👢 Staff Kick", f"**Member:** `{member}` (`{member.id}`)\n**Staff:** {interaction.user.mention}\n**Reason:** {reason}", discord.Color.orange())


if __name__ == "__main__":
    bot.run(TOKEN)
