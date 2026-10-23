# Staging baseline

Review the authentication inventory and connectivity gates in
[Credential and session security](CREDENTIAL-SECURITY.md) before adding any
brokerage configuration.

The first staging phase runs the real application image as an isolated,
CLI-only container. It does not connect to Discord, a brokerage, or any
network, and it is deliberately unable to place live orders:

- `TRADING_DISABLED=true` rejects every command that explicitly requests a
  non-dry transaction (`... false`) before any brokerage login starts.
- `StockOrder` remains dry by default.
- The staging Compose file overrides every supported brokerage credential and
  account-selection variable with an empty value. It does not mount `creds/`.
- Watchtower and the Docker socket are not part of the staging service.
- `docker-compose.staging-cli.yml` removes networking, drops Linux
  capabilities, makes the root filesystem read-only, and keeps the container
  available only for operator-invoked CLI checks.
- The health check imports the installed application and exercises its CLI
  entry point without contacting Discord or a brokerage.

This is a startup/integration baseline, not a brokerage sandbox. Dry commands
will fail at brokerage initialization because the container intentionally has
no brokerage credentials.

## Required inputs

Install `.env.staging.example` outside the release tree as a mode-0600 file,
then set its absolute path through `RSA_STAGING_ENV_FILE`. Keep
`DISCORD_TOKEN` and `DISCORD_CHANNEL` empty during the CLI-only phase, so it
requires no secret. A later Discord phase requires a dedicated staging-only bot
and channel plus an approved token-delivery design.

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
docker compose -f docker-compose.staging.yml -f docker-compose.staging-cli.yml config --quiet
docker compose -f docker-compose.staging.yml -f docker-compose.staging-cli.yml up -d --no-build
docker compose -f docker-compose.staging.yml -f docker-compose.staging-cli.yml ps
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
service. The unit combines the base and CLI-only Compose files, starts the
prebuilt image with `--no-build`, and recovers it after a reboot.

Use `docker compose exec auto-rsa-staging auto_rsa_bot healthcheck` as the
first smoke test. An explicit non-dry CLI request must be run only as a bounded
negative test and must fail with `Live trading is disabled by
TRADING_DISABLED` before broker initialization. Add Discord only in a later,
separately reviewed phase.

## Host requirements

The host must support Docker Compose and the image's target architecture, and
it must provide the two external configuration files with access limited to
the service operator. The CLI-only phase accepts no Discord or brokerage
credential and no cached brokerage session data.

## Later Chase credential trial

Do not enable this during the CLI-only baseline. A separately authorized,
network-enabled one-shot Chase trial must pass credentials through
`RSA_BROKER_CREDENTIALS_FILE` using the exact version-1 JSON contract in
[Credential and session security](CREDENTIAL-SECURITY.md). The path must be
absolute and must name a mode-0600 FIFO or a mode-0600 regular file on `tmpfs`;
the application consumes and unlinks it when possible. Keep `CHASE` empty and
do not set `RSA_ALLOW_LEGACY_ENV_CREDENTIALS`.

Run an authorized Chase trial only from an interactive command/CLI terminal.
If Chase requests MFA, the application reads the 8-digit code locally with
masked, non-echoed input; the prompt supports `cancel` and expires after five
minutes. Do not send Chase codes through Discord: that path is disabled.

Chase browser state is temporary and deleted after each run by default,
including MFA cancellation, timeout, and error. Do not set
`RSA_CHASE_PROFILE_DIR` in staging. A durable profile is rejected unless
`RSA_CHASE_ALLOW_DURABLE_PROFILE=true`, and that exception requires a separately
reviewed, existing absolute directory owned by the service user with mode 0700
and no symlink components. `TRADING_DISABLED=true` remains mandatory and its
pre-login rejection behavior is unchanged by the Chase credential loader.
