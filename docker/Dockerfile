# Imagen de tor-osint (CLI + interfaz web). Se ejecuta sin privilegios.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    TOR_OSINT_CONTAINER=1 \
    TOR_SOCKS=tor:9050

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-compile . \
    && useradd --create-home --uid 10001 osint \
    && mkdir -p /work/data /work/results \
    && chown -R osint:osint /work

USER osint
WORKDIR /work
EXPOSE 8765

ENTRYPOINT ["tor-osint"]
CMD ["--help"]
