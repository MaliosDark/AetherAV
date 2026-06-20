# Client auto-update (always current)

So AetherAV never falls behind, run the signed-feed updater automatically. The
update is safe over any transport because every feed is **Ed25519-signed**: a
forged or rolled-back feed is rejected (see `apply_signed`).

## Option A - systemd timer (recommended, headless/servers)

```bash
sudo install -m755 target/release/aether /usr/local/bin/
sudo mkdir -p /opt/aetherav && sudo cp -r assets aether.toml /opt/aetherav/
# set update.url in /opt/aetherav/aether.toml to your published feed
sudo cp deploy/aether-update.{service,timer} /etc/systemd/system/
sudo systemctl enable --now aether-update.timer
```

Checks hourly (and right after boot); `Persistent=true` catches missed runs.

## Option B - long-running watcher

```bash
aether -c aether.toml update --watch            # uses update.interval_hours
aether update --url https://feeds.example/aether.json --watch --interval 1800
```

## Option C - desktop app

The desktop already auto-refreshes intel on a schedule and shows
**Auto Updates: ON**. Point `update.url` at your feed to also pull the signed
feed.

## Config (`aether.toml`)

```toml
[update]
enabled = true
url = "https://feeds.example.com/aether.json"   # your published SIGNED feed
interval_hours = 1
```

Integrity comes from the signature, not the transport - but use HTTPS anyway for
privacy.
