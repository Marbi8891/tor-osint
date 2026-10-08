# Servicio Tor mínimo para tor-osint: solo SOCKS, sin relay ni servicios onion.
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends tor ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY torrc /etc/tor/torrc
USER debian-tor
EXPOSE 9050

# El primer arranque descarga el consenso y miles de descriptores: puede tardar varios
# minutos. Durante el start-period los fallos no cuentan.
HEALTHCHECK --interval=15s --timeout=5s --start-period=300s --retries=8 \
    CMD grep -q "Bootstrapped 100%" /var/lib/tor/notices.log || exit 1

ENTRYPOINT ["tor", "-f", "/etc/tor/torrc"]
