# Staging baseline

The staging service starts the real Discord application from a locally built
image, but it is deliberately unable to place live orders:

- `TRADING_DISABLED=true` rejects every command that explicitly requests a
  non-dry transaction (`... false`) before any brokerage login starts.
- `StockOrder` remains dry by default.
- The staging Compose file overrides every supported brokerage credential and
  account-selection variable with an empty value. It does not mount `creds/`.
- Watchtower and the Docker socket are not part of the staging service.
- The health check imports the installed application and exercises its CLI
  entry point without contacting Discord or a brokerage.

This is a startup/integration baseline, not a brokerage sandbox. Dry commands
will fail at brokerage initialization because the container intentionally has
no brokerage credentials.

## Required inputs

Copy `.env.staging.example` to `.env.staging` on the staging host. The only
secret required to start the bot is `DISCORD_TOKEN`, which must belong to a
dedicated staging-only Discord bot. `DISCORD_CHANNEL` is the numeric ID of a
dedicated staging-only channel and is not a secret. The bot must have Discord's
message-content intent and permission to read and send messages in that
channel.

Do not add brokerage usernames, passwords, API tokens, TOTP seeds, account
numbers, or cached browser/session files. The normal application supports
those through broker-specific environment variables in `.env` and files under
`creds/`; staging intentionally supplies neither.

## Build and start

```bash
cp .env.staging.example .env.staging
# Set DISCORD_TOKEN and DISCORD_CHANNEL on the host, then:
docker compose -f docker-compose.staging.yml config
docker compose -f docker-compose.staging.yml build
docker compose -f docker-compose.staging.yml up -d
docker compose -f docker-compose.staging.yml ps
```

Use `!ping` (or the configured prefix) as the first external smoke test. A live
request such as `!rsa-staging buy 1 AAPL all false` must be rejected with
`Live trading is disabled by TRADING_DISABLED` before broker initialization.

## Host decision still required

Before deployment, choose the staging host and secret-delivery mechanism. The
host must support Docker Compose and the image's target architecture, and it
must provide `.env.staging` outside source control with file access limited to
the service operator. Also select the dedicated staging Discord bot/channel;
production Discord credentials or any brokerage credential are not acceptable
staging inputs.
