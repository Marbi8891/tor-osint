# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/); versionado
[SemVer](https://semver.org/lang/es/).

## [0.5.0] - 2026-10-08

### Añadido
- Historial: cada crawl guarda una versión (`snapshots` + `contents` deduplicados); comandos
  `history`, `diff` y `changes`; la salida de `crawl` marca páginas nuevas y con cambios.
- Búsqueda de texto completo con SQLite FTS5 (BM25, prefijos, sin tildes, resaltado);
  `search --substring` mantiene la búsqueda literal.
- Casi duplicados con SimHash (`duplicates --near`), umbral calibrado.
- Watchlist de términos e IOCs con alertas por versión de contenido (`watch`, `alerts`).
- Notas y etiquetas sobre páginas e IOCs (`note`, `tag`).
- IOCs nuevos con validación de checksum: Bitcoin (Base58Check, Bech32/Bech32m), Ethereum
  (EIP-55 con Keccak-256), MITRE ATT&CK y huellas PGP.
- Enriquecimiento CVSS offline desde un JSON de NVD (`nvd-import`).
- Exportación STIX 2.1 y MISP.
- Cadena de custodia: manifiesto SHA-256 de exportaciones e informes, `verify` y `audit`.
- HTML original opcional como evidencia (`crawl --save-raw`, gzip, permisos 0600).
- Interfaz web: cambios y diff, watchlist y alertas, notas y etiquetas, grafo de correlación,
  CVSS, casi duplicados, STIX/MISP, verificación y auditoría.
- Docker Compose con servicio Tor; unidades systemd y ejemplo de cron para crawls programados.
- CI con tests en Python 3.10–3.14 y prueba de extremo a extremo contra la red Tor real
  (Docker + Tor, `tor-check`, crawl de la onion oficial de The Tor Project, informe, STIX y `verify`).
- Análisis de seguridad con CodeQL (Python y JavaScript), workflow de release que publica la
  GitHub Release y las imágenes en GitHub Container Registry, `pre-commit`, `Makefile`,
  código de conducta y `CITATION.cff`.
- Manual: notas de Kali Linux (entorno virtual obligatorio, `web` en otra terminal, `!` en zsh),
  tras probar el flujo completo a mano en Kali rolling con Python 3.14.

### Cambiado
- Esquema de base de datos v3 con migración automática desde v1/v2.
- Frontend dividido en módulos ES.
- `TOR_TIMEOUT` por defecto pasa de 30 a 60 s: en la primera prueba contra la red Tor real, la
  primera conexión a una onion superó los 30 s (descriptor + circuito de rendezvous).

### Corregido
- Indicadores de cabecera ocultos que se mostraban vacíos (`[hidden]` frente a `.pill`).
- Hashes largos que desbordaban la pantalla en móvil.
- Healthcheck del contenedor de Tor: margen de arranque de 5 minutos para el primer bootstrap.

## [0.4.0] - 2026-10-08

### Añadido
- Interfaz web local (`tor-osint web`): panel, fuentes y crawl en segundo plano, páginas,
  búsqueda, IOCs, correlación, duplicados, exportación e informe. Solo loopback, CSRF,
  validación de `Host` y CSP estricta.
- `sources --add`.

## [0.3.0] - 2026-10-08

### Añadido
- Reestructuración del script original en un paquete: configuración, cliente Tor, validación
  de fuentes (checksum onion v3), parser, redacción de secretos, IOCs, SQLite, búsqueda,
  deduplicación, exportación e informe. Tests con pytest y lint con ruff.

### Corregido (respecto al script original)
- XSS en el informe HTML, inyección de fórmulas en CSV, redirecciones fuera de `.onion`,
  respuestas sin cerrar, rate limiting omitido tras errores, comodines `LIKE` sin escapar,
  falsos positivos de IOCs y credenciales guardadas en claro.

[0.5.0]: https://github.com/Marbi8891/tor-osint/releases/tag/v0.5.0
[0.4.0]: https://github.com/Marbi8891/tor-osint/commits/v0.5.0
[0.3.0]: https://github.com/Marbi8891/tor-osint/commits/v0.5.0
