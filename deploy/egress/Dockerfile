FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nftables \
        squid \
        util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10002 egressproxy \
    && useradd --uid 10002 --gid 10002 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin egressproxy \
    && install -d -o 10002 -g 10002 -m 0750 /var/spool/squid \
    && install -d -o root -g root -m 0755 /etc/rsa-egress \
    && find / -xdev -type f -perm /6000 -exec chmod a-s {} +

COPY --chmod=0444 squid.conf /etc/squid/squid.conf
COPY --chmod=0444 robinhood-endpoints.allow /etc/squid/robinhood-endpoints.allow
COPY --chmod=0444 nftables.conf /etc/rsa-egress/nftables.conf
COPY --chmod=0555 entrypoint.sh /usr/local/bin/rsa-egress-entrypoint

ENTRYPOINT ["/usr/local/bin/rsa-egress-entrypoint"]
