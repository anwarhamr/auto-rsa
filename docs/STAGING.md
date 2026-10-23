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

Install `.env.staging.example` outside the release tree as a mode-0600 file,
then set its absolute path through `RSA_STAGING_ENV_FILE`. The only secret
required to start the bot is `DISCORD_TOKEN`, which must belong to a dedicated
staging-only Discord bot. `DISCORD_CHANNEL` is the numeric ID of a dedicated
staging-only channel and is not a secret. The bot must have Discord's
message-content intent and permission to read and send messages in that
channel.

Do not add brokerage usernames, passwords, API tokens, TOTP seeds, account
numbers, or cached browser/session files. The normal application supports
those through broker-specific environment variables in `.env` and files under
`creds/`; staging intentionally supplies neither.

## Build and start manually

```bash
release_commit="$(git rev-parse HEAD)"
export RSA_IMAGE="auto-rsa:staging-${release_commit}"
export RSA_STAGING_ENV_FILE=/etc/rsa-auto-trader/staging.env
docker build --pull --tag "$RSA_IMAGE" .
docker compose -f docker-compose.staging.yml config --quiet
docker compose -f docker-compose.staging.yml up -d --no-build
docker compose -f docker-compose.staging.yml ps
```

The deployment configuration deliberately has no image-tag or config-path
fallback. Both values must be explicit so a release cannot silently use a
mutable image or project-local credential file.

## Linux boot service

The appliance layout is:

- immutable releases: `/opt/rsa-auto-trader/staging/releases/<git-commit>`
- active release symlink: `/opt/rsa-auto-trader/staging/current`
- staging application config: `/etc/rsa-auto-trader/staging.env`
- deployment config: `/etc/rsa-auto-trader/staging-deploy.env`
- systemd unit: `/etc/systemd/system/rsa-auto-trader-staging.service`

Install the two config files with mode `0600`. Set `RSA_IMAGE` in the deployment
config to the exact image tag built from the release and keep
`RSA_STAGING_ENV_FILE=/etc/rsa-auto-trader/staging.env`. Install
`deploy/systemd/rsa-auto-trader-staging.service`, reload systemd, and enable the
service only after the dedicated staging Discord token and channel are present.
The unit starts the prebuilt image with `--no-build` and recovers it after a
reboot.

Use `!ping` (or the configured prefix) as the first external smoke test. A live
request such as `!rsa-staging buy 1 AAPL all false` must be rejected with
`Live trading is disabled by TRADING_DISABLED` before broker initialization.

## Host requirements

The host must support Docker Compose and the image's target architecture, and
it must provide the two external configuration files with access limited to
the service operator. Also select the dedicated staging Discord bot/channel;
production Discord credentials or any brokerage credential are not acceptable
staging inputs.
