# Luraph / LuaU-VMP Discord Deobfuscator Bot

Supports: **Luraph 14.x**, **LuaU VMP**, Luraph legacy, Prometheus, MoonSec V2/V3, IronBrew 2.

## Commands

| Command   | Description                                              |
|-----------|----------------------------------------------------------|
| `/deobf`  | Deobfuscate a file or pasted code (optional force type) |
| `/detect` | Identify which obfuscator was used                       |
| `/help`   | Show supported types and usage                           |

Max file size: **512 KB**. Long output is sent as a file attachment.

---

## Local Setup

```bash
pip install -r requirements.txt
export DISCORD_TOKEN="your_bot_token_here"
python bot.py
```

---

## Deploy to Railway (Recommended – Free)

1. Go to [railway.app](https://railway.app) and sign in with GitHub
2. Click **New Project** → **Deploy from GitHub repo** (or **Empty Project**)
3. If empty project:
   - Click **Add Service** → **Empty Service**
   - Go to **Settings** → **Source** → connect your GitHub repo that contains these files
4. Add the environment variable:
   - Key: `DISCORD_TOKEN`
   - Value: your bot token (from Discord Developer Portal)
5. Railway will auto-detect Python and run `python bot.py`
6. After deploy, the bot will come online

**Optional:** Add a `Procfile` (already included) so Railway knows the start command.

---

## Deploy to Render (Free)

1. Go to [render.com](https://render.com) and sign in
2. Click **New** → **Web Service**
3. Connect your GitHub repo (or upload the files)
4. Settings:
   - **Runtime**: Python 3
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `python bot.py`
5. Add Environment Variable:
   - Key: `DISCORD_TOKEN`
   - Value: your bot token
6. Click **Create Web Service**

> Note: Free Render services spin down after ~15 minutes of inactivity.  
> The bot will take ~30–60 seconds to wake up the first time someone uses a command.

---

## Important Notes

- **Never** share your bot token publicly.
- If your token was exposed, go to the [Discord Developer Portal](https://discord.com/developers/applications) → Bot → **Reset Token**.
- Make sure the bot has these intents enabled in the Developer Portal:
  - Message Content Intent
- Invite the bot with both `bot` and `applications.commands` scopes.

## Files

- `bot.py` – Discord slash command bot
- `deobfuscator.py` – Core deobfuscation engine
- `requirements.txt` – Dependencies
- `Procfile` – Start command for Railway/Heroku-style platforms
