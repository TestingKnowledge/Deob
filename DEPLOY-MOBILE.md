# Deploy from your Phone — GitHub → Render → UptimeRobot

> **5 flat files. No folders. No file editing.** The token goes into
> **Render's Environment Variables** (dashboard), not into any file.
> Total time: ~10 minutes.

---

## Part A — Discord setup (~3 min)

1. Open **https://discord.com/developers/applications** (phone browser,
   request **desktop site** if buttons misbehave).
2. **New Application** → name it (e.g. `Lua Obfuscator Bot`) → Create.
3. Open the **Bot** tab → click **Reset Token** → **Copy**. ⚠️ You'll need
   it in Part D — it is shown only once. Save it in a notes app for now.
4. Same **Bot** tab → **Privileged Gateway Intents** → enable **MESSAGE
   CONTENT INTENT** → **Save Changes**.
5. **OAuth2 → URL Generator** → tick scope **`bot`** → tick permissions
   *View Channels, Send Messages, Attach Files, Embed Links* → open the
   generated URL → pick your server → **Authorize**.

---

## Part B — Upload to GitHub from your phone (~2 min)

1. Unzip `lua-bot-mobile.zip` **on your phone** (Android file manager or
   iOS Files app both work — the zip holds 5 flat files).
2. Go to **https://github.com/new**
3. Repository name: `lua-obfuscator-bot` (anything works).
4. Choose **Private** → do **not** add README/license → **Create repository**.
5. On the empty-repo page tap **"uploading an existing file"**.
6. Tap **choose your files** → select all 5 files:
   `bot.py` • `requirements.txt` • `render.yaml` • `.env.example` • `README.md`
   (`.env.example` may be hidden in your phone's file picker — if you
   can't select it, skip it; it's only for local runs, Render doesn't
   need it.)
7. Commit message: `Lua obfuscator/deobfuscator Discord bot` → tap
   **Commit changes**.

---

## Part C — Render (~3 min) — token goes in the ENVIRONMENT VARIABLES

1. Open **https://render.com** (phone browser, desktop site) → **Get
   Started** → log in **With GitHub** → authorize (grant the repo).
2. Dashboard → **New +** → **Web Service** → pick `lua-obfuscator-bot`.
3. Render auto-detects `render.yaml` and pre-fills everything. Verify
   only: **Instance type = Free**, **Branch = main**.
4. ⚠️ **THE ONE MANUAL STEP** — because `render.yaml` marks the token as
   `sync: false`, Render now **prompts you for the DISCORD_TOKEN value**.
   **Paste your bot token** (from Part A) into that field. This is the
   "environment variable" step — the token lives in Render's dashboard
   only, never in GitHub.
   *(If you missed the prompt: create the service anyway, then go to
   service → **Environment** → **Add Environment Variable** → Key
   `DISCORD_TOKEN`, Value = your token → Save — Render redeploys.)*
5. Tap **Apply / Create Web Service**.
6. Watch **Logs** — within ~1 second of startup:

   ```
   [keep-alive] health server listening on 0.0.0.0:10000/health
   ```

   → then Discord gateway lines → service goes **Live** (green).
7. **Verify**: in Discord type `.ping` → `Gateway latency: ~100 ms` 🎉

---

## Part D — UptimeRobot (~2 min) — so the free service never sleeps

1. Open **https://uptimerobot.com** → **Sign Up** (free).
2. Verify email → **Add New Monitor**:
   | Field | Value |
   |---|---|
   | Type | **HTTP(s)** |
   | Friendly Name | `lua-obfuscator-bot` |
   | URL | `https://<your-service-name>.onrender.com/health` |
   | Interval | **5 minutes** |
3. **Create Monitor**. While it's Active (green), the bot never sleeps —
   Render's free tier sleeps after ~15 min without traffic, UptimeRobot
   pings `/health` every 5 min.
4. Also open `https://<service-name>.onrender.com/health` yourself once —
   you should see JSON `{"status": "ok", ...}`.

**Done — 24/7 bot, free, token only in Render's dashboard.**

---

## Troubleshooting

- **Deploy fails / "port not open"** → Logs must show
  `[keep-alive] health server listening on 0.0.0.0:10000/health`; start
  command must be `python bot.py` (it is).
- **Deploys but bot offline in Discord** → missing token: service →
  **Environment** → check `DISCORD_TOKEN` is set (from the `sync: false`
  prompt or added manually) → **Manual Deploy → Deploy latest commit**.
- **Bot offline after ~15 min** → UptimeRobot monitor must be **Active**,
  5-min interval, URL ends in **`/health`**.
- **UptimeRobot says down** → URL must be exactly
  `https://<service-name>.onrender.com/health` — the service name is on
  the Render dashboard top-left.
- **Repo not in Render's list** → **Configure account** → GitHub →
  **Install** → grant the repo → refresh.
- **Uploaded fewer than 5 files / `.env.example` missing** → fine to skip
  `.env.example` (local-run template only); `bot.py`, `requirements.txt`,
  `render.yaml` are the required ones. `README.md` is documentation.
- **pip install fails** → `requirements.txt` didn't upload — re-upload it.
- **Edits later** → edit `bot.py` on GitHub's web editor → commit →
  auto-redeploy (`autoDeploy: true`).

---

## Why single-file `bot.py`?

GitHub's mobile upload can't create folders. This edition inlines both
engines (obfuscator + deobfuscator) into `bot.py`, so everything is flat
and phone-uploadable. Functionally identical to the multi-file project:
same commands, same engines, same verified round-trips
(`FULLY RECOVERED` on VM samples).
