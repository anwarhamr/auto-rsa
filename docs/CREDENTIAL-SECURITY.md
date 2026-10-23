# Credential and session security

This document records the source audit for brokerage authentication before any
brokerage is enabled in staging or production. It contains no secret values.

## Current trust model

Most brokerages still read one colon-delimited environment variable. Chase is
the first hardened exception: it consumes a versioned JSON payload from a
protected file/FIFO, and its old environment format is disabled by default.
Other values may contain usernames, passwords, API keys, refresh tokens,
trading PINs, phone selectors, and TOTP seeds. `python-dotenv` also loads a local
`.env` file. The default Compose deployment mounts `./creds` at `/app/creds`.

The current Discord control path is not an authorization boundary:

- every non-bot user in `DISCORD_CHANNEL` can invoke trading and restart
  commands (`src/auto_rsa.py:417-489`);
- OTP and other interactive input accept the next matching message from any
  non-bot user in that channel (`src/helper_api.py:601-669`);
- OTP values are ordinary channel messages and therefore remain in Discord
  history unless separately removed.

`TRADING_DISABLED=true` currently prevents non-dry orders before brokerage
initialization. It must remain enabled until command authorization and a
separate per-order approval boundary exist.

## Brokerage inventory

A fresh run means the documented environment credential is supplied but no
prior `creds/` state exists. Source inspection did not contact any brokerage.

- **BBAE** — username/password, CAPTCHA, and email/SMS OTP. The dependency
  writes unencrypted cookie pickle files below `creds/`. The wrapper also logs
  raw challenge/login responses and can leave `captcha.png`
  (`src/brokerages/bbae_api.py:17-185`).
- **Chase** — username/password, phone last four, and an 8-digit OTP. Credentials
  now use the typed, consumed input described below. Browser state is ephemeral
  by default; debug is a JSON boolean. Durable browser state and legacy
  colon-delimited environment credentials each require a separate explicit
  opt-in.
- **dSPAC** — username/password, CAPTCHA, and email/SMS OTP. The dependency
  writes unencrypted cookie pickle files below `creds/`; raw challenge/login
  responses and CAPTCHA files can be logged or left on disk
  (`src/brokerages/dspac_api.py:17-193`).
- **Fennel** — long-lived personal access token. No application-configured disk
  state; the token remains in the process environment and memory
  (`src/brokerages/fennel_api.py:16-58`).
- **Fidelity** — username/password plus optional TOTP seed or interactive OTP.
  Playwright storage state is written below `creds/`
  (`src/brokerages/fidelity_api.py:25-124`).
- **Firstrade** — username/password plus PIN, phone, email, or TOTP seed. The
  dependency can load session material from the configured `creds/` path;
  saving behavior is dependency-controlled (`src/brokerages/firstrade_api.py:23-69`).
- **Public** — long-lived API key. No application-configured disk state; derived
  access tokens remain in memory (`src/brokerages/public_api.py:22-59`).
- **Robinhood** — username/password and phone-app verification. The documented
  TOTP field is not consumed by the wrapper. Access, refresh, and device tokens
  are stored unencrypted for 30-day sessions below `creds/`
  (`src/brokerages/robinhood_api.py:16-75`). Cached tokens take precedence on
  subsequent holdings and order operations (`src/brokerages/robinhood_api.py:80-118`).
- **Schwab** — username/password plus optional TOTP seed. Session cookies and
  credential/TOTP hashes are stored in `creds/schwabN.json`
  (`src/brokerages/schwab_api.py:22-84`).
- **SoFi** — username/password plus optional TOTP seed or SMS OTP. Browser
  cookies are saved as pickle files below `creds/` and reused
  (`src/brokerages/sofi_api.py:19-205`, `385-475`).
- **Tastytrade** — OAuth client secret and refresh token. The application keeps
  derived session tokens in memory and does not configure disk persistence
  (`src/brokerages/tasty_api.py:43-70`).
- **Tornado** — email/password through Selenium. No application-configured
  durable session state (`src/brokerages/tornado_api.py:28-92`).
- **Tradier** — long-lived bearer token. No application-configured disk state;
  the token remains in the process environment and request headers
  (`src/brokerages/tradier_api.py:19-78`).
- **Vanguard** — username/password, phone last four, and interactive OTP.
  Browser storage state is written below `creds/`
  (`src/brokerages/vanguard_api.py:22-96`).
- **Webull** — username/password, device ID, and trading PIN. The wrapper logs
  in on every run and keeps derived access/trade tokens in memory; it does not
  request dependency token persistence (`src/brokerages/webull_api.py:37-95`).
- **Wells Fargo** — username/password, phone last four, and interactive OTP via
  Selenium. No application-configured durable session state
  (`src/brokerages/wellsfargo_api.py:33-130`).

The broker libraries generally create files with the process umask and do not
apply an application-level encryption or permission policy. Persisted cookies,
browser storage, access tokens, and refresh tokens must therefore be treated as
credentials, not harmless cache.

## Risk conclusions

1. A persistent `.env` file does not meet the requirement to avoid stored
   brokerage credentials.
2. A persistent 1Password service-account or Connect token would merely replace
   stored broker credentials with a stored credential able to retrieve them
   unattended; it does not provide per-run human authorization.
3. TOTP seeds are durable second-factor bypass material. They must never be
   supplied to an always-on service if each run is intended to require human
   approval.
4. The existing Discord bot cannot safely be connected to brokerage accounts:
   channel membership currently implies trade, restart, OTP, and prompt-input
   authority.
5. Reusing `creds/` across runs can silently select cached identities and grants
   unattended session reuse. Session state needs an explicit per-broker policy,
   owner, expiry, and revocation procedure.
6. Broad tracebacks, raw broker responses, and CAPTCHA artifacts create a
   secondary secret-exposure path through logs and working directories.

## Recommended staged design

Use two separately deployable components:

1. **Request and approval service** — accepts a proposed immutable trade plan,
   expands the default to one share of each ticker in every selected account,
   displays the exact broker/account/ticker/quantity/order type, records one
   human approval, and issues a short-lived single-use execution grant bound to
   the plan digest. It never receives brokerage credentials.
2. **Ephemeral execution worker** — starts only for an approved grant, receives
   broker credentials from an interactive 1Password session, executes exactly
   the bound plan, emits a redacted result, and exits. Credentials and broker
   session state live only in memory or a worker-scoped tmpfs unless a specific
   broker is explicitly approved for durable session reuse.

The practical remote-first flow is for 1Password CLI on an operator-controlled
machine to require the operator's normal unlock/biometric approval, retrieve
only the selected brokerage item, and stream a structured secret payload over
SSH directly into the one-shot worker. Do not place the payload in command-line
arguments, shell history, a remote persistent file, Docker metadata, a ticket,
Discord, or application logs. Chase now implements the first typed,
worker-scoped credential-file path; the other brokerages still require this
migration.

## Chase credential and profile contract

Set `RSA_BROKER_CREDENTIALS_FILE` to an absolute path containing exactly this
UTF-8 JSON shape (values below are placeholders):

```json
{
  "version": 1,
  "broker": "chase",
  "accounts": [
    {
      "username": "operator-supplied username",
      "password": "operator-supplied password",
      "phone_last_four": "1234",
      "debug": false
    }
  ]
}
```

The input must be either a FIFO or a regular file on a Linux `tmpfs`, with no
group or other permission bits. Symlinks and relative paths are rejected. The
reader accepts at most 64 KiB, rejects duplicate/unknown/missing fields, requires
schema version `1`, broker `chase`, a non-empty account list, a four-digit
`phone_last_four`, and a JSON boolean for `debug`. It opens without following a
symlink, verifies the opened object, unlinks an accepted path when possible,
reads it once, and retains only typed in-process values. Error messages and
credential object representations do not contain submitted values.

`CHASE` is legacy-only. A non-empty `CHASE` value fails closed unless
`RSA_ALLOW_LEGACY_ENV_CREDENTIALS=true`; the legacy form remains
`username:password:phone-last-four[:true|false]`. Do not use that exception in
staging or production. If both a structured input and a non-empty `CHASE` are
configured, Chase rejects the ambiguous configuration.

Chase second-factor entry is local-only. When `login()` indicates that a second
factor is required, a command/CLI run reads the expected 8-digit numeric code
from `/dev/tty` with terminal echo disabled and displays only masking
characters. The prompt has a five-minute overall timeout and accepts `cancel`;
invalid input, cancellation, timeout, or terminal failure stops authentication
before account enumeration. The value is passed directly to `login_two()` and
is never sent through Discord, written to a file, or included in an error or
log. A Chase run initiated through Discord fails closed if second factor is
required.

By default each Chase run uses a mode-0700 temporary browser profile and removes
it when the run ends. The browser is also closed and the temporary profile is
removed after MFA cancellation, timeout, or error. Durable state requires both
`RSA_CHASE_ALLOW_DURABLE_PROFILE=true` and `RSA_CHASE_PROFILE_DIR` naming an
existing absolute, symlink-free directory owned by the process user with no
group or other permission bits. Setting the directory without the opt-in, or
the opt-in without the directory, fails closed. Durable state is sensitive
session material and requires a separately reviewed expiry and revocation
procedure. These credential and profile changes do not alter
`TRADING_DISABLED`; it continues to reject explicit live orders before broker
initialization.

## Required gates before broker connectivity

1. Add an explicit Discord allowlist and bind every remaining non-Chase prompt
   to the initiating user and request; reject concurrent or unmatched input.
2. Remove live trading from the always-on Discord process. It may propose plans,
   but only the one-shot worker may execute an approved plan.
3. Replace raw exception/response forwarding with redacted structured errors;
   remove CAPTCHA files immediately after use.
4. Add a typed credential-provider interface and prohibit `.env` broker secrets
   in staging and production.
5. Make persistent session state opt-in per broker, stored outside the image with
   mode `0600`, an expiry, identity binding, and a tested revoke/delete path.
6. Keep `TRADING_DISABLED=true` until the approval grant, replay protection,
   account expansion, dry-run verification, and audit record are tested.
7. Validate one selected brokerage at a time in non-live staging. Production
   still requires separate human authorization.

## Decisions still required

Before implementation, identify the brokerages and account count that must work
first. That determines whether the first execution path is stateless token auth,
interactive OTP, or browser/session-state auth, and whether any session cache is
worth preserving.
