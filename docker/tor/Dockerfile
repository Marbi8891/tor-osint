# Servicio Tor mínimo para tor-osint: solo SOCKS, sin relay ni servicios onion.
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends tor ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY torrc /etc/tor/torrc
USER debian-tor
EXPOSE 9050

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=5 \
    CMD grep -q "Bootstrapped 100%" /var/lib/tor/notices.log || exit 1

ENTRYPOINT ["tor", "-f", "/etc/tor/torrc"]
