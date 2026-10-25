# Robinhood appliance egress policy

This stack is a dedicated, one-shot Robinhood execution boundary. It is not the
normal Discord/Watchtower deployment and must not be combined with
`docker-compose.yml`. Discord remains outside this stack, no service publishes
an inbound port, and neither service receives the Docker socket.

## Security boundary

`trader` shares the `robinhood-egress` network namespace. The gateway receives
only the temporary NET_ADMIN/SETUID/SETGID/SETPCAP capabilities, installs an
nftables `INPUT`/`OUTPUT` default-deny policy before it reports healthy, then
drops to UID 10002 with its capability bounding set emptied and runs a
loopback-only Squid CONNECT proxy. The trader runs as fixed UID 10001 with no capabilities, a
read-only root filesystem, and `no-new-privileges`.

The trader UID may connect only to `127.0.0.1:3128`. It cannot open a direct
internet, host, LAN, metadata, Ollama, DNS, DNS-over-TLS, or QUIC socket. The
proxy UID may issue DNS and public TCP/443 connections, but Squid accepts only
`CONNECT api.robinhood.com:443`. Numeric CONNECT targets, all other names,
plain HTTP, and every other destination port are denied. Standard private,
loopback, link-local, carrier-grade NAT, benchmark, documentation, multicast,
and reserved IPv4 ranges are denied before the proxy's TCP/443 rule. IPv6 has
no accepting rule and is disabled on the Compose network.

TLS remains end to end between the application and Robinhood; the proxy does
not decrypt it. Consequently the policy constrains hostname and port, not URL
path. `deploy/egress/robinhood-endpoints.json` classifies every Robinhood host
literal in the pinned `robin-stocks` dependency. A test fails closed when that
dependency introduces an unreviewed host.

## Required host state

Use a native Linux appliance with Docker Compose and nftables support. Reserve
UID/GID 10001 for the trader. Install the durable account document described in
[Credential and session security](CREDENTIAL-SECURITY.md) as a mode-0600 regular
file owned by 10001. Prepare the runtime directory on host `tmpfs`, also owned
by 10001:

```bash
install -d -o 10001 -g 10001 -m 0700 /run/rsa-auto-trader/robinhood
install -d -o 10001 -g 10001 -m 0700 /run/rsa-auto-trader/robinhood/sessions
```

When a cache miss requires passwords, install the version-1 password document
as `/run/rsa-auto-trader/robinhood/passwords.json`, mode 0600 and owner 10001,
immediately before the one-shot command. The credential loader consumes and
unlinks it. The runtime bind mount preserves the tmpfs session cache across
one-shot containers without writing bearer state into an image or Docker
volume.

## Build and configure

Build both images through the reviewed release process. The gateway base image
is pinned by digest; deployed application and gateway references must also be
immutable registry digests. For an entirely local qualification, Docker image
IDs (`sha256:...`) are acceptable immutable references.

```bash
release_commit="$(git rev-parse HEAD)"
docker build --tag "auto-rsa:robinhood-$release_commit" .
docker build --tag "rsa-robinhood-egress:$release_commit" deploy/egress

app_image="$(docker image inspect --format '{{.Id}}' "auto-rsa:robinhood-$release_commit")"
egress_image="$(docker image inspect --format '{{.Id}}' "rsa-robinhood-egress:$release_commit")"
```

Copy `deploy/systemd/robinhood-deploy.env.example` to
`/etc/rsa-auto-trader/robinhood-deploy.env`, mode 0600, and replace every
placeholder. Keep `TRADING_DISABLED=true` through qualification. Render the
stack before starting it:

```bash
docker compose \
  --env-file /etc/rsa-auto-trader/robinhood-deploy.env \
  --profile run \
  -f docker-compose.robinhood.yml config --quiet

docker compose \
  --env-file /etc/rsa-auto-trader/robinhood-deploy.env \
  -f docker-compose.robinhood.yml \
  up -d --no-build robinhood-egress
```

The systemd unit starts only the gateway. Install
`deploy/bin/rsa-robinhood-run` with the release and invoke bounded one-shot
commands through it, for example:

```bash
RSA_ROBINHOOD_DEPLOY_ENV=/etc/rsa-auto-trader/robinhood-deploy.env \
  deploy/bin/rsa-robinhood-run holdings robinhood
```

The wrapper accepts only `healthcheck`, `holdings robinhood`, or one explicit
Robinhood buy/sell command. It does not accept `all`, another brokerage,
Discord mode, Docker mode, or arbitrary application arguments. The appliance
sets `RSA_DISABLE_UPDATE_CHECK=true`; PyPI is neither required nor allowed.

## Offline validation

Static and unit checks make no network requests:

```bash
python -m unittest discover -s tests -p 'test_*.py'
docker compose --profile run -f docker-compose.robinhood.yml config --quiet
```

After both images have been built or loaded locally, the integration probe uses
only a synthetic TLS fixture on an isolated Docker test network:

```bash
export RSA_TEST_APP_IMAGE="sha256:<local-application-image-id>"
export RSA_TEST_EGRESS_IMAGE="sha256:<local-gateway-image-id>"
tests/egress/run.sh
```

The probe proves that the fixture works through the exact hostname allowlist
and that direct raw-IP, host-gateway, metadata, Ollama, DNS, DoH, DoT, QUIC,
numeric proxy target, Discord, and other-host attempts fail. The test-only nft
policy contains one clearly marked exception for the synthetic fixture's
benchmark-range address; production has no such exception.

## Deployment limitations

- Security qualification must run on the target native Linux kernel. Docker
  Desktop on macOS runs inside a Linux VM and is useful only as a functional
  precheck, not appliance proof.
- Rootless Docker, Docker user-namespace remapping, alternate container
  runtimes, and IPv6-enabled daemon customizations are unsupported until
  separately qualified. The UID-owner rules depend on the documented fixed
  UIDs.
- Host root or Docker-daemon access can replace the containers or firewall and
  is outside this boundary. Never expose the Docker socket to a controller.
- The deny set covers normal private-addressed host/LAN layouts. An appliance
  attached to a LAN that uses globally routable address space must add that
  site prefix to `blocked_ipv4` and extend the offline probe before deployment.
- Docker's embedded DNS can be destination-NATed before the output filter, so
  DNS is restricted by trusted proxy UID and port. The untrusted trader UID has
  no DNS rule.
- Robinhood can add or redirect to a new service hostname. Such traffic fails
  closed until the inventory, exact Squid allowlist, tests, and deployment are
  reviewed together.
- The egress proxy permits all HTTPS paths at `api.robinhood.com`; path-level
  policy would require application-layer enforcement or TLS interception.
