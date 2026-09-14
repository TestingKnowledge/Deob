# Lua Obfuscator / Deobfuscator — Discord Bot (single-file edition)

Same bot as the main project — **packed into one `bot.py`** (both engines
inlined) so it can be uploaded to GitHub **from a phone**, where folder
uploads don't work. Five flat files, no folders.

| Command | Aliases | What to do |
|---|---|---|
| `.obfuscate` | `.obf`, `.protect` | attach a `.lua`/`.txt` file → get the obfuscated `.lua` back |
| `.deobfuscate` | `.deobf`, `.decode`, `.unobfuscate`, `.unobf` | attach an obfuscated file → get the decoded `.lua` **and** a full reverse-engineering report `.txt` |
| `.ping` | — | gateway latency |
| `.stats` | — | session statistics |
| `.help` | — | command list |

## Files

| File | Purpose |
|---|---|
| `bot.py` | the whole bot + both engines (obfuscator & deobfuscator) in one file |
| `requirements.txt` | `discord.py` + `python-dotenv` |
| `render.yaml` | Render blueprint — **no editing needed** (token goes in Render's dashboard) |
| `.env.example` | template for **local** runs only (skip on Render) |
| `README.md` | this file |

## Deploy steps (short version — full detail in DEPLOY-MOBILE.md)

1. **Discord**: create the app → Bot tab → **Reset Token** → enable **MESSAGE CONTENT INTENT** → OAuth2 URL Generator → invite the bot.
2. **GitHub**: create a **Private** repo → **Add file → Upload files** → upload these 5 files (no folders, phone-friendly).
3. **Render**: log in **With GitHub** → **New + → Web Service** → pick the repo → Render reads `render.yaml` → when it asks for **DISCORD_TOKEN** (because of `sync: false`), **paste your token there** → Apply.
4. **UptimeRobot**: add an **HTTP(s)** monitor on `https://<service-name>.onrender.com/health`, **5-minute** interval — keeps the free service awake 24/7.

## Environment variables (Render dashboard)

| Key | Value |
|---|---|
| `DISCORD_TOKEN` | your bot token (entered at the sync: false prompt / Environment tab) |
| `MAX_FILE_KB` | `200` (optional, already set by render.yaml) |
| `PROCESS_TIMEOUT` | `25` (optional, already set by render.yaml) |
| `BANNER` | `v1.0.1` (optional, already set by render.yaml) |

Render injects `PORT` automatically (the bot's health server binds it).
Set `KEEP_ALIVE_URL` only if you want the built-in self-ping instead of
UptimeRobot (you don't — you're using UptimeRobot).

## Running locally instead (optional)

```
pip install -r requirements.txt
cp .env.example .env      # paste your token
python bot.py
```

The `tests/` folder of the main project is not needed on Render — the
bot is self-contained. See the main repo's README for engine internals,
troubleshooting, and Docker/VPS hosting.
