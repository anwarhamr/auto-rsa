## How to set up Robinhood MFA

The bot never accepts or stores a Robinhood TOTP seed. Keep the seed only in an
operator-controlled authenticator and enter the current one-time code through
the worker's local terminal when prompted.

1. In the Robinhood app, open **Security and privacy**, then
   **Two-factor authentication**.
2. Choose either Robinhood app approval or an authenticator app.
3. If using an authenticator, enroll it directly in an operator-controlled app
   and keep its setup key out of `.env`, account JSON, password input, images,
   logs, and tickets.
4. Set the account's `mfa` field to `workflow` for Robinhood app/email/SMS, or
   `totp` for operator-entered authenticator codes.
5. Start the one-shot worker from a local interactive terminal. TOTP, email, and
   SMS codes are masked and bounded by the authentication deadline. Robinhood
   MFA is unavailable through Discord.

See [Credential and session security](CREDENTIAL-SECURITY.md) for the protected
account/password JSON formats and tmpfs session requirements.
