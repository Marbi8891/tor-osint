# tor-osint

Plataforma **local** de investigación OSINT sobre fuentes `.onion` que el investigador define
explícitamente. Consulta cada fuente a través de Tor, guarda el contenido en SQLite, extrae
indicadores (IOCs), y permite buscar, correlacionar, deduplicar, exportar y generar informes HTML.

> Proyecto de laboratorio para aprendizaje de ciberseguridad. No es un crawler de la red Tor:
> **no descubre servicios, no sigue enlaces y no interactúa** con los sitios (sin formularios,
> sin login, sin compras).

## 1. Objetivo

- Recopilar de forma controlada el contenido de una lista cerrada de fuentes `.onion`.
- Normalizar y almacenar el contenido como evidencia (fecha, código HTTP, SHA-256).
- Extraer IOCs (emails, dominios, URLs, IPv4, MD5/SHA-1/SHA-256, CVE, URLs onion).
- Buscar (texto y regex), correlacionar IOCs entre páginas y detectar contenido duplicado.
- Exportar (JSON/CSV) y documentar los hallazgos en un informe HTML autocontenido.

## 2. Arquitectura

```
sources.txt / --url ──► sources (validación onion v3 + checksum)
                              │
                              ▼
      tor (TorClient: SOCKS5h, timeout, límite de bytes, rate limit, redirecciones solo .onion)
                              │ bytes no confiables
                              ▼
      parser (título, texto, enlaces; sin JS) ──► redact (elimina credenciales/secretos)
                              │
                 ┌────────────┼──────────────┐
                 ▼            ▼              ▼
              ioc.py      dedup.py       database.py (SQLite: pages + iocs)
                                             │
              ┌──────────────┬───────────────┼──────────────┐
              ▼              ▼               ▼              ▼
          search.py      related/iocs    export.py      report.py
```

| Módulo | Responsabilidad |
|---|---|
| `cli.py` | `argparse`, subcomandos, códigos de salida y mensajes |
| `config.py` | Valores por defecto, variables `TOR_*`, overrides de CLI, límites duros |
| `sources.py` | Validación de URLs `.onion` (v2 sintaxis, v3 con checksum) y carga de fuentes |
| `tor.py` | Cliente HTTP por Tor y `tor-check` |
| `crawler.py` | Orquesta fetch → parse → redact → IOCs → hash → SQLite (sin recursión) |
| `parser.py` | Extracción de título, texto y enlaces del HTML no confiable |
| `redact.py` | Redacción de credenciales y secretos antes de almacenar |
| `ioc.py` | Extractores y normalizadores de IOCs |
| `dedup.py` | Normalización de texto, SHA-256 y grupos de duplicados |
| `database.py` | Esquema SQLite, inserción/actualización y consultas de agregación |
| `search.py` | Búsqueda literal y por regex sobre datos locales |
| `export.py` | Exportación JSON y CSV (con protección frente a CSV injection) |
| `report.py` | Informe HTML escapado y con CSP |

Respecto a la estructura propuesta se añadieron tres módulos: `sources.py` (validación
compartida por CLI y crawler), `redact.py` (política de no almacenar secretos, aislada y
testeable) y `export.py` (separado del informe).

## 3. Instalación en Kali Linux

```bash
sudo apt update
sudo apt install -y tor python3-venv

git clone https://github.com/Marbi8891/portfolio-mrabeh.git
cd portfolio-mrabeh/tor-osint

python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"      # instala el comando `tor-osint` + pytest y ruff

tor-osint --help
```

Dependencias de ejecución: `requests[socks]` (incluye PySocks) y `beautifulsoup4`.
Todo lo demás es biblioteca estándar (`sqlite3`, `argparse`, `logging`, `csv`, `html`...).

## 4. Configuración de Tor

```bash
sudo systemctl enable --now tor
sudo systemctl status tor       # debe estar "active"
tor-osint tor-check             # IsTor: True
tor-osint tor-check --show-ip   # además muestra la IP de salida (oculta por defecto)
```

`tor-check` consulta el endpoint oficial `https://check.torproject.org/api/ip`.

El proxy se usa siempre como `socks5h://`: la resolución DNS se hace dentro de Tor (imprescindible
para `.onion` y para no filtrar consultas DNS). La sesión ignora `HTTP(S)_PROXY` del entorno.

| Variable | Por defecto | Opción CLI | Descripción |
|---|---|---|---|
| `TOR_SOCKS` | `127.0.0.1:9050` | `--socks` | Proxy SOCKS de Tor (Tor Browser usa `9150`) |
| `TOR_TIMEOUT` | `30` | `--timeout` | Segundos por petición (máx. 300) |
| `TOR_DELAY` | `2` | `--delay` | Segundos mínimos entre peticiones (mín. 0.5) |
| `TOR_MAX_BYTES` | `2097152` | `--max-bytes` | Bytes máximos por respuesta (máx. 20 MiB) |
| `TOR_MAX_URLS` | `100` | `crawl --max-urls` | URLs máximas por ejecución |

Las opciones de red van después del subcomando: `tor-osint crawl --delay 5 --timeout 60`.
Opciones globales (antes del subcomando): `--data-dir`, `--db`, `--sources`, `--results-dir`, `-v`.

## 5. Configuración de fuentes

`data/sources.txt`: una URL `.onion` por línea, `#` para comentarios.

```text
# Servicio onion oficial de The Tor Project
http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/
```

Validación aplicada a cada línea:

- esquema `http` o `https`;
- host terminado en `.onion` (se admiten subdominios);
- 56 caracteres base32 (`a-z2-7`) para v3, **con verificación del checksum y la versión** de la
  especificación rend-spec-v3; 16 caracteres para v2 (solo sintaxis; v2 está retirado desde 2021
  y se avisa);
- sin credenciales embebidas (`user:pass@`) y con puerto válido.

`tor-osint sources` muestra las fuentes válidas y las rechazadas.

Los enlaces `.onion` encontrados en las páginas **se registran pero nunca se visitan**.
`tor-osint sources --discovered` los lista para que decidas manualmente si añadirlos.

## 6. Comandos

```bash
tor-osint tor-check                      # verifica que el tráfico sale por Tor
tor-osint sources [--discovered]         # valida fuentes / onion descubiertas no incluidas
tor-osint crawl                          # consulta data/sources.txt (1 petición por fuente)
tor-osint crawl --url http://<id>.onion/ # consulta solo URLs indicadas explícitamente
tor-osint search "empresa"               # búsqueda literal en título y texto
tor-osint regex "CVE-202[0-9]-[0-9]+"    # regex sobre la BD local
tor-osint iocs                           # estadísticas por tipo
tor-osint iocs --type domain             # email | domain | url | ipv4 | hash | md5 | sha1 | sha256 | cve | onion
tor-osint related example.com            # páginas donde aparece un IOC
tor-osint related CVE-2024-1234
tor-osint related 8.8.8.8
tor-osint duplicates                     # URLs con contenido idéntico (SHA-256)
tor-osint export --format json           # results/results.json
tor-osint export --format csv            # results/results.csv + results/results_iocs.csv
tor-osint report                         # results/report.html
tor-osint report --output results/caso-01.html
```

Cada subcomando tiene ayuda propia: `tor-osint crawl --help`. Con `python -m tor_osint` funciona
igual sin instalar el comando.

Códigos de salida: `0` OK, `1` error de ejecución (Tor no disponible, todas las fuentes fallaron,
BD), `2` entrada o configuración inválida.

## 7. Estructura del proyecto

```
tor-osint/
├── src/tor_osint/
│   ├── __init__.py  __main__.py  cli.py  config.py  sources.py  tor.py
│   ├── crawler.py  parser.py  redact.py  ioc.py  dedup.py
│   ├── database.py  search.py  export.py  report.py
├── tests/            # pytest, sin red (HTTP mockeado)
├── data/sources.txt  # fuentes (la BD data/results.db se ignora en git)
├── results/          # exportaciones e informes (ignorado en git)
├── pyproject.toml    # dependencias, entry point, pytest y ruff
├── README.md  LICENSE  .gitignore
```

## 8. Base de datos

SQLite en `data/results.db` (configurable con `--db`). Es compatible con la BD de la versión
anterior del script: la tabla `pages` mantiene las mismas columnas.

**`pages`**: una fila por URL final (deduplicación por URL; un nuevo `crawl` la actualiza).

| Columna | Contenido |
|---|---|
| `url` (UNIQUE) | URL final tras redirecciones `.onion` |
| `source` | Fuente de `sources.txt` que la originó |
| `fetched_at` | ISO-8601 UTC |
| `status` | Código HTTP |
| `title`, `text` | Título y texto visible, **ya redactados** |
| `content_hash` | SHA-256 del texto normalizado (espacios colapsados) |
| `links_json` | Enlaces http(s) absolutos de la página |
| `iocs_json` | IOCs normalizados agrupados por tipo |

**`iocs`**: relación IOC ↔ página (`UNIQUE(type, normalized_value, page_id)`), con `value`
(tal como apareció), `normalized_value`, `first_seen`, `last_seen` y `page_id` (FK con
`ON DELETE CASCADE`). Si un IOC desaparece de una página en un nuevo crawl, deja de
correlacionarse con ella.

Índices: `pages(content_hash)`, `pages(fetched_at)`, `pages(source)`, `iocs(normalized_value)`,
`iocs(type)`, `iocs(page_id)`.

Normalización: emails y dominios en minúsculas, CVE en mayúsculas, hashes en minúsculas, IPv4
canónica, URLs con esquema y host en minúsculas y sin credenciales ni fragmento.

## 9. Seguridad

Segura por defecto:

- **Alcance cerrado**: solo `sources.txt` o `--url`. Sin recursión ni descubrimiento; los enlaces
  descubiertos solo se registran.
- **Límites**: timeout por petición, tamaño máximo de respuesta (lectura en streaming y corte),
  máximo de URLs por ejecución, máximo 5 redirecciones con detección de bucles.
- **Rate limiting**: intervalo mínimo entre peticiones (incluidas las fallidas y las redirecciones),
  que no se puede bajar de 0.5 s.
- **Redirecciones**: se siguen manualmente y solo hacia URLs `.onion` válidas (nunca a clearnet).
- **Contenido no confiable**: solo se aceptan `text/html`, `application/xhtml+xml` y `text/plain`;
  el HTML se parsea con `html.parser` sin ejecutar JavaScript ni cargar recursos; se eliminan
  `script/style/iframe/object/embed...`. No se guardan ficheros descargados ni se usa `subprocess`.
- **No se almacenan secretos**: antes de guardar nada se redactan combos `email:password`,
  pares `password=`/`token=`/`api_key=`, `Bearer`, credenciales en URLs, claves privadas PEM,
  claves AWS, tokens de GitHub, Slack, Google y Stripe, y JWT (`redact.py`).
- **Informe HTML**: todo escapado con `html.escape`, CSP `default-src 'none'`, sin enlaces
  clicables ni recursos externos.
- **CSV**: celdas que empiezan por `= + - @` se prefijan con `'` (anti CSV injection).
- **SQL**: solo consultas parametrizadas; `LIKE` con comodines escapados.
- **Regex del usuario**: solo se ejecuta sobre la BD local, nunca durante el crawling.
- `tor-check` no muestra la IP de salida salvo con `--show-ip`. Los errores de conexión se
  registran por tipo (el detalle completo solo con `-vv`).

Uso responsable: emplea la herramienta solo sobre fuentes que tengas legitimidad para consultar
y respeta la legislación aplicable. No incluye ni incluirá autenticación, explotación ni
interacción con mercados.

## 10. Tests

```bash
pytest           # todos los tests (sin Tor ni red: HTTP mockeado con FakeSession)
ruff check .     # lint
ruff format --check .
```

Cobertura por fichero:

| Test | Qué cubre |
|---|---|
| `test_config.py` | Entorno, overrides de CLI, límites |
| `test_sources.py` | Validación onion v2/v3 (checksum), normalización, carga de fuentes |
| `test_tor.py` | Proxy socks5h, timeout, truncado, Content-Type, redirecciones, bucles, rate limit, `tor-check` |
| `test_parser.py` | Título, texto, enlaces, charset, HTML roto, límites |
| `test_ioc.py` | Cada extractor + falsos positivos + normalización |
| `test_redact.py` | Secretos redactados y texto benigno intacto |
| `test_crawler.py` | Pipeline completo, no recursión, `max_urls`, fallos, HTTP 404 |
| `test_database.py` | Esquema, índices, upsert, first/last_seen, IOCs obsoletos |
| `test_search_dedup.py` | Búsqueda, comodines `LIKE`, regex, deduplicación |
| `test_export_report.py` | JSON, CSV injection, escape XSS del informe, secciones |
| `test_cli.py` | Flujo de extremo a extremo de todos los comandos |

## 11. Limitaciones

- La extracción de IOCs es heurística: puede haber falsos positivos (versiones tipo `1.2.3.4`
  como IPv4) y falsos negativos (dominios en TLDs que coinciden con extensiones de fichero, como
  `.zip` o `.md`, que se descartan a propósito). Solo IPv4, no IPv6.
- La redacción de secretos se basa en patrones; no garantiza detectar todos los formatos.
- El hash se calcula sobre el texto **visible y redactado**, no sobre el HTML original (que no se
  guarda). Sirve para deduplicar y como huella de la evidencia almacenada, no del fichero remoto.
- Sin JavaScript: las páginas que generan el contenido en el cliente aparecerán vacías.
- No se respeta `robots.txt` automáticamente; el control está en la lista cerrada de fuentes y el
  rate limiting.
- La regex de usuario usa el módulo `re` (sin timeout): una regex patológica puede tardar sobre
  una BD grande. Solo afecta a datos locales.
- Sin exportación STIX: requeriría la dependencia `stix2` y un modelado cuidadoso de objetos;
  se dejó fuera para no añadir dependencias sin poder validarlo bien.
- Las onion v2 se validan solo por sintaxis y en la práctica son inaccesibles.
