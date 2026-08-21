import discord
from discord.ext import commands
from discord import app_commands
import asyncio
import io
import traceback
import logging
from pathlib import Path

from deobfuscator import DeobfuscatorEngine, ObfuscatorType, DeobfError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("luraph-bot")

MAX_FILE_SIZE = 512 * 1024  # 512 KB
MAX_OUTPUT_SIZE = 1900       # Discord message char limit with breathing room

intents = discord.Intents.default()
intents.message_content = True

bot = commands.Bot(command_prefix="!", intents=intents)
engine = DeobfuscatorEngine()


# ── Helpers ──────────────────────────────────────────────────────────────────

def truncate(text: str, limit: int = MAX_OUTPUT_SIZE) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 40] + "\n... [truncated — download full output]"


async def read_attachment(attachment: discord.Attachment) -> str:
    if attachment.size > MAX_FILE_SIZE:
        raise ValueError(f"File too large ({attachment.size // 1024} KB). Max 512 KB.")
    data = await attachment.read()
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


async def send_result(
    interaction: discord.Interaction,
    result: str,
    filename: str,
    obf_type: str,
    elapsed: float,
) -> None:
    header = f"✅ **Deobfuscated** | Type: `{obf_type}` | Time: `{elapsed:.2f}s`\n"

    if len(result) <= MAX_OUTPUT_SIZE - len(header):
        await interaction.followup.send(
            header + f"```lua\n{result}\n```"
        )
    else:
        buf = io.BytesIO(result.encode("utf-8"))
        buf.seek(0)
        file = discord.File(buf, filename=f"deobf_{filename}")
        await interaction.followup.send(
            header + "Output too large for inline display — attached as file.",
            file=file,
        )


# ── Slash Commands ────────────────────────────────────────────────────────────

@bot.tree.command(name="deobf", description="Deobfuscate a Lua/LuaU script (attach file or paste code)")
@app_commands.describe(
    file="Upload a .lua file to deobfuscate",
    code="Paste raw Lua code directly (ignored if file attached)",
    obfuscator="Force a specific obfuscator type (auto-detected by default)",
)
@app_commands.choices(obfuscator=[
    app_commands.Choice(name="Auto-detect",     value="auto"),
    app_commands.Choice(name="Luraph 14.x",     value="luraph14"),
    app_commands.Choice(name="LuaU VMP",        value="luauvmp"),
    app_commands.Choice(name="Luraph (legacy)", value="luraph_legacy"),
    app_commands.Choice(name="Prometheus",      value="prometheus"),
    app_commands.Choice(name="MoonSec V2",      value="moonsec2"),
    app_commands.Choice(name="MoonSec V3",      value="moonsec3"),
    app_commands.Choice(name="IronBrew 2",      value="ironbrew2"),
])
async def cmd_deobf(
    interaction: discord.Interaction,
    file: discord.Attachment | None = None,
    code: str | None = None,
    obfuscator: str = "auto",
):
    await interaction.response.defer(thinking=True)

    source = None
    filename = "input.lua"

    if file is not None:
        try:
            source = await read_attachment(file)
            filename = file.filename
        except ValueError as e:
            await interaction.followup.send(f"❌ {e}")
            return
    elif code:
        source = code
    else:
        await interaction.followup.send("❌ Provide either a file attachment or paste code with `code:`.")
        return

    obf_hint = None if obfuscator == "auto" else ObfuscatorType(obfuscator)

    import time
    t0 = time.perf_counter()
    try:
        result, detected_type = await asyncio.get_event_loop().run_in_executor(
            None, engine.deobfuscate, source, obf_hint
        )
        elapsed = time.perf_counter() - t0
        await send_result(interaction, result, filename, detected_type.value, elapsed)
    except DeobfError as e:
        await interaction.followup.send(f"❌ Deobfuscation failed: `{e}`")
    except Exception:
        log.exception("Unhandled deobf error")
        await interaction.followup.send("❌ Internal error — check bot logs.")


@bot.tree.command(name="detect", description="Detect which obfuscator was used on a script")
@app_commands.describe(
    file="Upload a .lua file",
    code="Paste code directly",
)
async def cmd_detect(
    interaction: discord.Interaction,
    file: discord.Attachment | None = None,
    code: str | None = None,
):
    await interaction.response.defer(thinking=True)

    if file is not None:
        try:
            source = await read_attachment(file)
        except ValueError as e:
            await interaction.followup.send(f"❌ {e}")
            return
    elif code:
        source = code
    else:
        await interaction.followup.send("❌ Provide a file or paste code.")
        return

    detected, confidence = engine.detect(source)
    embed = discord.Embed(
        title="🔍 Obfuscator Detection",
        color=discord.Color.blurple(),
    )
    embed.add_field(name="Detected Type", value=f"`{detected.value}`", inline=True)
    embed.add_field(name="Confidence",    value=f"`{confidence:.0%}`",  inline=True)
    await interaction.followup.send(embed=embed)


@bot.tree.command(name="help", description="Show supported obfuscators and usage")
async def cmd_help(interaction: discord.Interaction):
    embed = discord.Embed(
        title="📖 Luraph / LuaU Deobfuscator",
        description="Reverse Luraph 14.x, LuaU VMP, and several other obfuscators.",
        color=discord.Color.green(),
    )
    embed.add_field(
        name="Supported Obfuscators",
        value=(
            "• Luraph 14.x (current)\n"
            "• LuaU VMP\n"
            "• Luraph legacy (≤13.x)\n"
            "• Prometheus / MoonSec V2 / V3\n"
            "• IronBrew 2"
        ),
        inline=False,
    )
    embed.add_field(
        name="Commands",
        value=(
            "`/deobf` — deobfuscate a file or pasted code\n"
            "`/detect` — identify which obfuscator was used\n"
            "`/help` — this message"
        ),
        inline=False,
    )
    embed.add_field(name="Max File Size", value="`512 KB`", inline=True)
    embed.set_footer(text="Auto-detection runs first unless you force a specific type.")
    await interaction.response.send_message(embed=embed)


# ── Lifecycle ─────────────────────────────────────────────────────────────────

@bot.event
async def on_ready():
    log.info(f"Logged in as {bot.user} ({bot.user.id})")
    try:
        synced = await bot.tree.sync()
        log.info(f"Synced {len(synced)} slash commands.")
    except Exception:
        log.exception("Failed to sync slash commands")


@bot.event
async def on_error(event: str, *args, **kwargs):
    log.error(f"Event error in {event}: {traceback.format_exc()}")


# ── Entry ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import os
    token = os.environ.get("DISCORD_TOKEN")
    if not token:
        raise RuntimeError("DISCORD_TOKEN environment variable not set.")
    bot.run(token, log_handler=None)
