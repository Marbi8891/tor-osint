# Crawl programado

El crawl programado consulta **las mismas fuentes explícitas** de `data/sources.txt`,
una vez cada una y sin recursión. Tras cada ejecución, `tor-osint changes` muestra qué
cambió y `tor-osint alerts` las coincidencias nuevas de la watchlist.

## systemd (recomendado, como usuario, sin root)

```bash
mkdir -p ~/.config/systemd/user
cp contrib/systemd/tor-osint-crawl.{service,timer} ~/.config/systemd/user/
# Edita WorkingDirectory/ExecStart si el proyecto no está en ~/tor-osint
systemctl --user daemon-reload
systemctl --user enable --now tor-osint-crawl.timer
systemctl --user list-timers tor-osint-crawl.timer
journalctl --user -u tor-osint-crawl.service    # salida de cada crawl
```

Para que el timer funcione sin sesión abierta: `sudo loginctl enable-linger $USER`.

## cron

Ver `cron.example`. El `%` está escapado como exige crontab.

## Docker

```bash
docker compose run --rm cli crawl
```

o, desde el anfitrión, un timer/cron que ejecute ese comando en el directorio del proyecto.

## Recomendaciones

- No bajes de varias horas entre crawls: el objetivo es vigilar cambios, no generar tráfico.
- Mantén `TOR_DELAY` ≥ 2 s y un `TOR_MAX_URLS` acorde a tus fuentes.
- Revisa periódicamente `tor-osint audit` y `tor-osint verify`.
