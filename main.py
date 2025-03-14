
# main.py

import discord
import asyncio
import sqlite3
from discord.ext import commands
import os
from flask import Flask, render_template, request, jsonify
import threading
import datetime
import time

# Bot Configuration
intents = discord.Intents.all()
bot = commands.Bot(command_prefix="!", intents=intents)

# Flask Dashboard
app = Flask(__name__)

# Database Setup
conn = sqlite3.connect("bot_data.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS admin_list (
    user_id TEXT PRIMARY KEY
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT,
    user TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS deleted_channels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    channel_id TEXT,
    channel_name TEXT,
    channel_type TEXT,
    position INTEGER,
    category_id TEXT,
    permissions TEXT,
    deleted_by TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS deleted_roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role_id TEXT,
    role_name TEXT,
    color INTEGER,
    permissions INTEGER,
    position INTEGER,
    deleted_by TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS join_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT,
    username TEXT,
    join_time DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS server_settings (
    key TEXT PRIMARY KEY,
    value TEXT
)
""")

# Insert default settings if they don't exist
cursor.execute("INSERT OR IGNORE INTO server_settings (key, value) VALUES (?, ?)", ("join_rate_limit", "10"))
cursor.execute("INSERT OR IGNORE INTO server_settings (key, value) VALUES (?, ?)", ("join_rate_window", "60"))
cursor.execute("INSERT OR IGNORE INTO server_settings (key, value) VALUES (?, ?)", ("min_account_age", "14"))
cursor.execute("INSERT OR IGNORE INTO server_settings (key, value) VALUES (?, ?)", ("lockdown_active", "false"))
cursor.execute("INSERT OR IGNORE INTO server_settings (key, value) VALUES (?, ?)", ("invites_enabled", "true"))

# Add default trusted admins if they don't exist
default_admins = [
    "718077967502278732",  # Rhys
    "977963761627447388",  # Bx
    "1220738458520387777", # Jordan
    "1062619190063808532"  # Hybridz
]

for admin_id in default_admins:
    cursor.execute("INSERT OR IGNORE INTO admin_list (user_id) VALUES (?)", (admin_id,))

conn.commit()

# Trusted Admin Check
def is_trusted_admin(user_id):
    cursor.execute("SELECT user_id FROM admin_list WHERE user_id = ?", (str(user_id),))
    return cursor.fetchone() is not None

# Log Administrative Actions
async def log_action(action, user):
    cursor.execute("INSERT INTO logs (action, user) VALUES (?, ?)", (action, str(user)))
    conn.commit()

# Get setting from database
def get_setting(key, default=None):
    cursor.execute("SELECT value FROM server_settings WHERE key = ?", (key,))
    result = cursor.fetchone()
    if result:
        return result[0]
    return default

# Update setting in database
def update_setting(key, value):
    cursor.execute("UPDATE server_settings SET value = ? WHERE key = ?", (value, key))
    conn.commit()

# Join Rate Tracking
join_timestamps = []
async def check_raid_status(guild):
    global join_timestamps
    
    # Remove timestamps older than the window
    join_window = int(get_setting("join_rate_window", "60"))
    current_time = time.time()
    join_timestamps = [t for t in join_timestamps if current_time - t < join_window]
    
    # Check if the join rate exceeds the limit
    join_rate_limit = int(get_setting("join_rate_limit", "10"))
    if len(join_timestamps) >= join_rate_limit:
        # Server is being raided, trigger lockdown
        await lockdown_server(guild, "AUTO", "Raid detection: Excessive join rate detected")
        
        # Get the security logs channel
        alert_channel = discord.utils.get(guild.channels, name="security-logs")
        if alert_channel:
            exec_role = discord.utils.get(guild.roles, name="Executive")
            foundation_role = discord.utils.get(guild.roles, name="Foundation")
            
            alert_msg = "🚨 **RAID DETECTED!** 🚨\n"
            alert_msg += f"Detected {len(join_timestamps)} joins in {join_window} seconds.\n"
            alert_msg += "Server has been automatically locked down."
            await alert_channel.send(alert_msg)
            
            if exec_role and foundation_role:
                await alert_channel.send(f"<@&{exec_role.id}> <@&{foundation_role.id}> - Urgent action required!")

# Bot Ready Event
@bot.event
async def on_ready():
    print(f"{bot.user.name} is online and ready!")
    await log_action("Bot started", bot.user.name)

# Auto-Kick Suspicious Users
@bot.event
async def on_member_join(member):
    # Log the join in the database
    cursor.execute("INSERT INTO join_logs (user_id, username) VALUES (?, ?)", 
                   (str(member.id), member.name))
    conn.commit()
    
    # Add timestamp to track join rate
    global join_timestamps
    join_timestamps.append(time.time())
    
    # Check for raid
    await check_raid_status(member.guild)
    
    # Check for suspicious accounts
    account_age_days = (datetime.datetime.now(datetime.timezone.utc) - member.created_at).days
    min_account_age = int(get_setting("min_account_age", "14"))
    
    is_suspicious = False
    suspicious_reasons = []
    
    if account_age_days < min_account_age:
        is_suspicious = True
        suspicious_reasons.append(f"Account age: {account_age_days} days")
    
    if member.avatar is None:
        is_suspicious = True
        suspicious_reasons.append("No profile picture")
    
    if is_suspicious:
        try:
            await member.kick(reason="Suspicious account detected")
            
            # Alert in security logs
            alert_channel = discord.utils.get(member.guild.channels, name="security-logs")
            if alert_channel:
                exec_role = discord.utils.get(member.guild.roles, name="Executive")
                foundation_role = discord.utils.get(member.guild.roles, name="Foundation")
                
                alert_msg = f"🚨 **Suspicious account kicked** 🚨\n"
                alert_msg += f"User: {member.name} (ID: {member.id})\n"
                alert_msg += f"Reasons: {', '.join(suspicious_reasons)}"
                await alert_channel.send(alert_msg)
                
                if exec_role and foundation_role:
                    await alert_channel.send(f"<@&{exec_role.id}> <@&{foundation_role.id}> - Please review.")
            
            await log_action(f"Kicked suspicious user: {member.name} ({', '.join(suspicious_reasons)})", "SYSTEM")
        except discord.Forbidden:
            await log_action(f"Failed to kick suspicious user {member.name} - Missing permissions", "SYSTEM")

# Monitor Channel Deletions
@bot.event
async def on_guild_channel_delete(channel):
    # Get the audit log for the deletion
    try:
        guild = channel.guild
        async for entry in guild.audit_logs(limit=1, action=discord.AuditLogAction.channel_delete):
            deleted_by = entry.user
            
            # Save channel data for potential restoration
            cursor.execute("""
            INSERT INTO deleted_channels 
            (channel_id, channel_name, channel_type, position, category_id, deleted_by) 
            VALUES (?, ?, ?, ?, ?, ?)
            """, (str(channel.id), channel.name, str(channel.type), 
                 channel.position, str(channel.category_id) if channel.category_id else None,
                 f"{deleted_by.name}#{deleted_by.discriminator} ({deleted_by.id})"))
            conn.commit()
            
            # Alert in security logs
            alert_channel = discord.utils.get(guild.channels, name="security-logs")
            if alert_channel:
                exec_role = discord.utils.get(guild.roles, name="Executive")
                foundation_role = discord.utils.get(guild.roles, name="Foundation")
                
                alert_msg = f"⚠️ **Channel Deleted** ⚠️\n"
                alert_msg += f"Channel: #{channel.name}\n"
                alert_msg += f"Deleted by: {deleted_by.mention} ({deleted_by.name})"
                await alert_channel.send(alert_msg)
                
                if not is_trusted_admin(deleted_by.id):
                    if exec_role and foundation_role:
                        await alert_channel.send(f"<@&{exec_role.id}> <@&{foundation_role.id}> - Unauthorized channel deletion!")
    
            await log_action(f"Channel deleted: #{channel.name} by {deleted_by.name}", f"{deleted_by.id}")
    except Exception as e:
        print(f"Error tracking channel deletion: {e}")

# Monitor Role Deletions
@bot.event
async def on_guild_role_delete(role):
    # Get the audit log for the deletion
    try:
        guild = role.guild
        async for entry in guild.audit_logs(limit=1, action=discord.AuditLogAction.role_delete):
            deleted_by = entry.user
            
            # Save role data for potential restoration
            cursor.execute("""
            INSERT INTO deleted_roles 
            (role_id, role_name, color, permissions, position, deleted_by) 
            VALUES (?, ?, ?, ?, ?, ?)
            """, (str(role.id), role.name, role.color.value, role.permissions.value, 
                 role.position, f"{deleted_by.name}#{deleted_by.discriminator} ({deleted_by.id})"))
            conn.commit()
            
            # Alert in security logs
            alert_channel = discord.utils.get(guild.channels, name="security-logs")
            if alert_channel:
                exec_role = discord.utils.get(guild.roles, name="Executive")
                foundation_role = discord.utils.get(guild.roles, name="Foundation")
                
                alert_msg = f"⚠️ **Role Deleted** ⚠️\n"
                alert_msg += f"Role: {role.name}\n"
                alert_msg += f"Deleted by: {deleted_by.mention} ({deleted_by.name})"
                await alert_channel.send(alert_msg)
                
                if not is_trusted_admin(deleted_by.id):
                    if exec_role and foundation_role:
                        await alert_channel.send(f"<@&{exec_role.id}> <@&{foundation_role.id}> - Unauthorized role deletion!")
    
            await log_action(f"Role deleted: {role.name} by {deleted_by.name}", f"{deleted_by.id}")
    except Exception as e:
        print(f"Error tracking role deletion: {e}")

# Lockdown Command
@bot.command()
async def lockdown(ctx):
    if not is_trusted_admin(ctx.author.id):
        return await ctx.send("❌ You are not authorized to use this command.")
    
    await lockdown_server(ctx.guild, ctx.author.name, "Manual lockdown")
    await ctx.send("🔒 Server is now in lockdown mode. All channels are restricted, trusted admins are exempt.")

# Shared lockdown function
async def lockdown_server(guild, triggered_by, reason):
    update_setting("lockdown_active", "true")
    update_setting("invites_enabled", "false")
    
    # Disable all invites
    try:
        for invite in await guild.invites():
            await invite.delete(reason="Server lockdown")
    except:
        pass
    
    for channel in guild.channels:
        try:
            overwrite = discord.PermissionOverwrite()
            overwrite.send_messages = False
            overwrite.read_message_history = True  # Allow reading, just not sending
            overwrite.add_reactions = False
            
            await channel.set_permissions(guild.default_role, overwrite=overwrite)
        except:
            continue
            
    # Allow trusted admins to bypass
    for channel in guild.channels:
        for member in guild.members:
            if is_trusted_admin(member.id):
                try:
                    admin_overwrite = discord.PermissionOverwrite()
                    admin_overwrite.send_messages = True
                    admin_overwrite.read_message_history = True
                    admin_overwrite.add_reactions = True
                    
                    await channel.set_permissions(member, overwrite=admin_overwrite)
                except:
                    continue
    
    # Log the action
    await log_action(f"Server lockdown activated - {reason}", triggered_by)
    
    # Try to send a notification to the security logs
    alert_channel = discord.utils.get(guild.channels, name="security-logs")
    if alert_channel:
        await alert_channel.send(f"🔒 **SERVER LOCKDOWN ACTIVATED** 🔒\nTriggered by: {triggered_by}\nReason: {reason}")

# Unlock Command
@bot.command()
async def unlock(ctx):
    if not is_trusted_admin(ctx.author.id):
        return await ctx.send("❌ You are not authorized to use this command.")
    
    await unlock_server(ctx.guild, ctx.author.name)
    await ctx.send("🔓 Lockdown lifted. All channels are open.")

# Shared unlock function
async def unlock_server(guild, triggered_by):
    update_setting("lockdown_active", "false")
    update_setting("invites_enabled", "true")
    
    for channel in guild.channels:
        try:
            # Reset permissions for the default role
            overwrite = discord.PermissionOverwrite()
            overwrite.send_messages = None  # Reset to default
            overwrite.read_message_history = None  # Reset to default
            overwrite.add_reactions = None  # Reset to default
            
            await channel.set_permissions(guild.default_role, overwrite=overwrite)
        except:
            continue
            
    # Reset admin permissions
    for channel in guild.channels:
        for member in guild.members:
            if is_trusted_admin(member.id):
                try:
                    # Reset to default
                    await channel.set_permissions(member, overwrite=None)
                except:
                    continue
    
    # Log the action
    await log_action("Server lockdown deactivated", triggered_by)
    
    # Try to send a notification to the security logs
    alert_channel = discord.utils.get(guild.channels, name="security-logs")
    if alert_channel:
        await alert_channel.send(f"🔓 **SERVER LOCKDOWN DEACTIVATED** 🔓\nTriggered by: {triggered_by}")

# Add Trusted Admin
@bot.command()
async def add_admin(ctx, member: discord.Member):
    if not is_trusted_admin(ctx.author.id):
        return await ctx.send("❌ You are not authorized to add admins.")

    cursor.execute("INSERT OR IGNORE INTO admin_list (user_id) VALUES (?)", (str(member.id),))
    conn.commit()
    await log_action(f"Added trusted admin: {member.name}", ctx.author.name)
    await ctx.send(f"✅ {member.mention} added as a trusted admin.")

# Remove Trusted Admin
@bot.command()
async def remove_admin(ctx, member: discord.Member):
    if not is_trusted_admin(ctx.author.id):
        return await ctx.send("❌ You are not authorized to remove admins.")

    cursor.execute("DELETE FROM admin_list WHERE user_id = ?", (str(member.id),))
    conn.commit()
    await log_action(f"Removed trusted admin: {member.name}", ctx.author.name)
    await ctx.send(f"✅ {member.mention} removed from trusted admins.")

# List Trusted Admins
@bot.command()
async def list_admins(ctx):
    if not is_trusted_admin(ctx.author.id):
        return await ctx.send("❌ You are not authorized to view admin list.")
    
    cursor.execute("SELECT user_id FROM admin_list")
    admins = cursor.fetchall()
    
    if not admins:
        return await ctx.send("No trusted admins found.")
    
    admin_list = "**Trusted Admins:**\n"
    for admin_id in admins:
        user = bot.get_user(int(admin_id[0]))
        admin_list += f"- {user.mention if user else admin_id[0]}\n"
    
    await ctx.send(admin_list)

# Change Join Rate Limit
@bot.command()
async def set_join_limit(ctx, rate: int, window: int = 60):
    if not is_trusted_admin(ctx.author.id):
        return await ctx.send("❌ You are not authorized to change settings.")
    
    if rate < 1 or window < 10:
        return await ctx.send("❌ Rate must be at least 1 and window at least 10 seconds.")
    
    update_setting("join_rate_limit", str(rate))
    update_setting("join_rate_window", str(window))
    
    await log_action(f"Updated join rate limit: {rate} joins per {window} seconds", ctx.author.name)
    await ctx.send(f"✅ Join rate limit updated to {rate} joins per {window} seconds.")

# Set Minimum Account Age
@bot.command()
async def set_min_age(ctx, days: int):
    if not is_trusted_admin(ctx.author.id):
        return await ctx.send("❌ You are not authorized to change settings.")
    
    if days < 0:
        return await ctx.send("❌ Minimum account age must be a positive number.")
    
    update_setting("min_account_age", str(days))
    
    await log_action(f"Updated minimum account age: {days} days", ctx.author.name)
    await ctx.send(f"✅ Minimum account age updated to {days} days.")

# Restore Deleted Channel
@bot.command()
async def restore_channel(ctx, channel_id: str = None):
    if not is_trusted_admin(ctx.author.id):
        return await ctx.send("❌ You are not authorized to restore channels.")
    
    if channel_id:
        cursor.execute("SELECT * FROM deleted_channels WHERE channel_id = ?", (channel_id,))
    else:
        cursor.execute("SELECT * FROM deleted_channels ORDER BY timestamp DESC LIMIT 1")
    
    channel_data = cursor.fetchone()
    
    if not channel_data:
        return await ctx.send("❌ No deleted channel found to restore.")
    
    # Create a new channel with the same name and type
    channel_name = channel_data[2]
    channel_type_str = channel_data[3]
    
    channel_type = discord.ChannelType.text
    if "voice" in channel_type_str.lower():
        channel_type = discord.ChannelType.voice
    elif "category" in channel_type_str.lower():
        channel_type = discord.ChannelType.category
    
    try:
        if channel_type == discord.ChannelType.category:
            new_channel = await ctx.guild.create_category(name=channel_name)
        elif channel_type == discord.ChannelType.voice:
            new_channel = await ctx.guild.create_voice_channel(name=channel_name)
        else:
            new_channel = await ctx.guild.create_text_channel(name=channel_name)
        
        await log_action(f"Restored deleted channel: {channel_name}", ctx.author.name)
        await ctx.send(f"✅ Channel {channel_name} has been restored.")
    except Exception as e:
        await ctx.send(f"❌ Failed to restore channel: {str(e)}")

# Dashboard Routes
@app.route("/")
def index():
    cursor.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100")
    logs = cursor.fetchall()
    
    cursor.execute("SELECT * FROM join_logs ORDER BY join_time DESC LIMIT 50")
    join_data = cursor.fetchall()
    
    cursor.execute("SELECT * FROM server_settings")
    settings = {row[0]: row[1] for row in cursor.fetchall()}
    
    cursor.execute("SELECT COUNT(*) FROM admin_list")
    admin_count = cursor.fetchone()[0]
    
    return render_template("index.html", 
                           logs=logs, 
                           join_data=join_data, 
                           settings=settings,
                           admin_count=admin_count)

# Check if user is a trusted admin for dashboard routes
def is_dashboard_authorized(request):
    # In a production environment, you would use proper sessions
    # For now, let's use a simple admin code in the request
    admin_id = request.args.get('admin_id')
    if admin_id:
        return is_trusted_admin(admin_id)
    return False

@app.route("/lockdown", methods=["POST"])
def dashboard_lockdown():
    if not is_dashboard_authorized(request):
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
        
    asyncio.run_coroutine_threadsafe(lockdown_server(bot.guilds[0], "WEB_DASHBOARD", "Triggered from dashboard"), bot.loop)
    return jsonify({"status": "success", "message": "Server is now in lockdown."})

@app.route("/unlock", methods=["POST"])
def dashboard_unlock():
    if not is_dashboard_authorized(request):
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
        
    asyncio.run_coroutine_threadsafe(unlock_server(bot.guilds[0], "WEB_DASHBOARD"), bot.loop)
    return jsonify({"status": "success", "message": "Lockdown lifted."})

@app.route("/api/logs")
def api_logs():
    cursor.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100")
    logs = cursor.fetchall()
    logs_data = []
    for log in logs:
        logs_data.append({
            "id": log[0],
            "action": log[1],
            "user": log[2],
            "timestamp": log[3]
        })
    return jsonify(logs_data)

@app.route("/api/settings", methods=["GET", "POST"])
def api_settings():
    if request.method == "POST":
        if not is_dashboard_authorized(request):
            return jsonify({"status": "error", "message": "Unauthorized"}), 403
            
        settings = request.json
        for key, value in settings.items():
            update_setting(key, value)
        return jsonify({"status": "success"})
    else:
        cursor.execute("SELECT * FROM server_settings")
        settings = {row[0]: row[1] for row in cursor.fetchall()}
        return jsonify(settings)

@app.route("/api/admins", methods=["GET", "POST", "DELETE"])
def api_admins():
    if request.method == "POST":
        if not is_dashboard_authorized(request):
            return jsonify({"status": "error", "message": "Unauthorized"}), 403
            
        admin_data = request.json
        user_id = admin_data.get('user_id')
        if not user_id:
            return jsonify({"status": "error", "message": "No user ID provided"}), 400
        
        cursor.execute("INSERT OR IGNORE INTO admin_list (user_id) VALUES (?)", (user_id,))
        conn.commit()
        asyncio.run_coroutine_threadsafe(log_action(f"Added trusted admin: {user_id}", "WEB_DASHBOARD"), bot.loop)
        return jsonify({"status": "success"})
    
    elif request.method == "DELETE":
        if not is_dashboard_authorized(request):
            return jsonify({"status": "error", "message": "Unauthorized"}), 403
            
        admin_data = request.json
        user_id = admin_data.get('user_id')
        if not user_id:
            return jsonify({"status": "error", "message": "No user ID provided"}), 400
        
        cursor.execute("DELETE FROM admin_list WHERE user_id = ?", (user_id,))
        conn.commit()
        asyncio.run_coroutine_threadsafe(log_action(f"Removed trusted admin: {user_id}", "WEB_DASHBOARD"), bot.loop)
        return jsonify({"status": "success"})
    
    else:
        cursor.execute("SELECT user_id FROM admin_list")
        admins = [row[0] for row in cursor.fetchall()]
        return jsonify({"admins": admins})

# Server information APIs
@app.route("/api/server")
def api_server():
    if not is_dashboard_authorized(request):
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    
    if not bot.guilds:
        return jsonify({"status": "error", "message": "Bot not connected to any server"}), 404
    
    guild = bot.guilds[0]
    
    # Basic server info
    server_info = {
        "id": str(guild.id),
        "name": guild.name,
        "icon_url": str(guild.icon.url) if guild.icon else None,
        "member_count": guild.member_count,
        "created_at": guild.created_at.isoformat(),
        "owner_id": str(guild.owner_id) if guild.owner_id else None,
        "description": guild.description
    }
    
    return jsonify(server_info)

@app.route("/api/members")
def api_members():
    if not is_dashboard_authorized(request):
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    
    if not bot.guilds:
        return jsonify({"status": "error", "message": "Bot not connected to any server"}), 404
    
    guild = bot.guilds[0]
    members_data = []
    
    # Get up to 100 members (for performance)
    for member in list(guild.members)[:100]:
        member_info = {
            "id": str(member.id),
            "name": member.name,
            "display_name": member.display_name,
            "avatar_url": str(member.avatar.url) if member.avatar else None,
            "bot": member.bot,
            "roles": [str(role.id) for role in member.roles[1:]],  # Skip @everyone
            "joined_at": member.joined_at.isoformat() if member.joined_at else None,
            "created_at": member.created_at.isoformat()
        }
        members_data.append(member_info)
    
    return jsonify(members_data)

@app.route("/api/channels")
def api_channels():
    if not is_dashboard_authorized(request):
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    
    if not bot.guilds:
        return jsonify({"status": "error", "message": "Bot not connected to any server"}), 404
    
    guild = bot.guilds[0]
    channels_data = []
    
    for channel in guild.channels:
        channel_info = {
            "id": str(channel.id),
            "name": channel.name,
            "type": str(channel.type),
            "position": channel.position,
            "category_id": str(channel.category_id) if channel.category_id else None,
            "nsfw": getattr(channel, 'nsfw', None)
        }
        channels_data.append(channel_info)
    
    return jsonify(channels_data)

@app.route("/api/roles")
def api_roles():
    if not is_dashboard_authorized(request):
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    
    if not bot.guilds:
        return jsonify({"status": "error", "message": "Bot not connected to any server"}), 404
    
    guild = bot.guilds[0]
    roles_data = []
    
    for role in guild.roles:
        role_info = {
            "id": str(role.id),
            "name": role.name,
            "color": role.color.value,
            "position": role.position,
            "mentionable": role.mentionable,
            "hoist": role.hoist,  # Displays separately in member list
            "managed": role.managed,  # Managed by integration
            "permissions": role.permissions.value
        }
        roles_data.append(role_info)
    
    return jsonify(roles_data)

# Run Flask in a Thread
def run_dashboard():
    app.run(host="0.0.0.0", port=8080)

threading.Thread(target=run_dashboard).start()

# Start the Bot
token = os.getenv("DISCORD_TOKEN")
secret_key = os.getenv("SECRET_KEY")

# Set the secret key for Flask
app.secret_key = secret_key

bot.run(token)
