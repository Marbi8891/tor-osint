# Manual de tor-osint

> Referencia completa. Para una visión general, ver el [README](../README.md).

Plataforma **local** de investigación OSINT sobre fuentes `.onion` que el investigador define
explícitamente. Consulta cada fuente a través de Tor, guarda cada versión en SQLite, extrae
indicadores (IOCs) y permite buscar, correlacionar, detectar cambios, vigilar términos, anotar,
exportar (JSON, CSV, STIX 2.1, MISP) y generar informes con cadena de custodia.

Se usa desde la **línea de comandos** o desde una **interfaz web local** (`tor-osint web`), y se
puede levantar como laboratorio con **Docker Compose** (Tor incluido).

> Proyecto de laboratorio para aprendizaje de ciberseguridad. No es un crawler de la red Tor:
> **no descubre servicios, no sigue enlaces y no interactúa** con los sitios (sin formularios,
> sin login, sin compras).

## 1. Objetivo

- Recopilar de forma controlada el contenido de una lista cerrada de fuentes `.onion`.
- Guardar cada crawl como una **versión** (fecha, código HTTP, SHA-256) y detectar **cambios**.
- Extraer 13 tipos de IOCs: emails, dominios, URLs, IPv4, MD5/SHA-1/SHA-256, CVE, URLs onion,
  direcciones Bitcoin y Ethereum (con checksum), técnicas MITRE ATT&CK y huellas PGP.
- Buscar (texto completo, literal y regex), correlacionar IOCs entre páginas, detectar contenido
  duplicado y casi duplicado.
- Vigilar términos e IOCs (watchlist con alertas) y anotar páginas e IOCs (notas y etiquetas).
- Exportar (JSON, CSV, STIX 2.1, MISP) y documentar en un informe HTML, con manifiesto de hashes
  y registro de auditoría.

## 2. Arquitectura

```
sources.txt / --url ──► sources (validación onion v3 + checksum)
                              │
                              ▼
      tor (TorClient: SOCKS5h, timeout, límite de bytes, rate limit, redirecciones solo .onion)
                              │ bytes no confiables            ┌─► crawl --save-raw: HTML gzip 0600
                              ▼                                │
      parser (título, texto, enlaces; sin JS) ──► redact (elimina credenciales/secretos)
                              │
             ┌────────────────┼──────────────────┐
             ▼                ▼                  ▼
          ioc.py (+crypto)  dedup.py (SHA-256,   database.py (SQLite v3: pages, snapshots,
                            SimHash)              contents, iocs, FTS5, watchlist, notas, audit)
                                                   │
      ┌──────────┬──────────┬──────────┬──────────┼──────────┬──────────┬──────────┐
      ▼          ▼          ▼          ▼          ▼          ▼          ▼          ▼
   search     changes     watch      notes     enrich     export    interop    report
   (FTS5)     (diff)     (alertas)  (tags)     (NVD)     (JSON/CSV) (STIX/MISP) (HTML)
      └──────────┴──────────┴──────────┴────┬─────┴──────────┴──────────┴──────────┘
                                   custody (manifiesto SHA-256 + verify)
                          cli.py + cli_case.py ◄──┴──► web.py + web_research.py + static/
```

| Módulo | Responsabilidad |
|---|---|
| `cli.py`, `cli_case.py` | `argparse`: comandos principales y de gestión de la investigación |
| `config.py` | Valores por defecto, variables `TOR_*`, overrides de CLI, límites duros |
| `sources.py` | Validación de URLs `.onion` (v2 sintaxis, v3 con checksum) y carga/alta de fuentes |
| `tor.py` | Cliente HTTP por Tor y `tor-check` |
| `crawler.py` | fetch → parse → redact → IOCs → hash → SQLite; cambios, alertas, HTML crudo opcional |
| `parser.py` | Título, texto y enlaces del HTML no confiable |
| `redact.py` | Redacción de credenciales y secretos antes de almacenar |
| `ioc.py`, `crypto.py` | Extractores y normalizadores; Base58Check, Bech32/Bech32m, EIP-55 (Keccak-256) |
| `dedup.py` | SHA-256 del texto normalizado, duplicados exactos y casi duplicados (SimHash) |
| `database.py` | Esquema v3 con migración automática, historial, auditoría y consultas |
| `changes.py` | Historial de versiones, diff por palabras, cambios recientes |
| `search.py` | FTS5 (BM25, prefijos, sin tildes, snippets), búsqueda literal y regex locales |
| `watch.py`, `notes.py` | Watchlist y alertas; notas y etiquetas |
| `enrich.py` | Importación offline de CVSS desde un JSON de NVD (API 2.0) |
| `export.py`, `interop.py` | JSON/CSV; STIX 2.1 y MISP |
| `custody.py` | Manifiesto SHA-256 de exportaciones/informes y verificación |
| `report.py` | Informe HTML escapado y con CSP |
| `web.py`, `web_research.py` | Servidor local (stdlib `http.server`), API JSON y controles de seguridad |
| `static/` | Frontend en módulos ES sin frameworks: `core`, `status`, `views`, `research`, `app` |

## 3. Instalación en Kali Linux

```bash
sudo apt update
sudo apt install -y tor python3-venv

git clone https://github.com/Marbi8891/tor-osint.git
cd tor-osint

python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"      # comando `tor-osint` + pytest, ruff y stix2 (solo para tests)

tor-osint --help
```

Dependencias de ejecución: `requests[socks]` (incluye PySocks) y `beautifulsoup4`. Todo lo
demás es biblioteca estándar (`sqlite3`, `argparse`, `http.server`, `hashlib`, `difflib`...).

### Con Docker Compose (Tor incluido)

```bash
docker compose up -d --build                 # Tor + interfaz web en http://127.0.0.1:8765/
docker compose run --rm cli tor-check
docker compose run --rm cli crawl
docker compose run --rm cli report
TOR_OSINT_PORT=9000 docker compose up -d     # otro puerto en el anfitrión
```

- El servicio `tor` solo hace de cliente (sin relay); su puerto SOCKS **no se publica** en el
  anfitrión y su `SocksPolicy` solo acepta redes privadas (la red de Compose).
- La web se publica **solo en `127.0.0.1`**; los contenedores de la app corren sin root, con el
  sistema de ficheros de solo lectura, `cap_drop: ALL` y `no-new-privileges`.
- `data/` y `results/` se montan desde el proyecto. Si tu usuario no es el 1000:
  `TOR_OSINT_UID=$(id -u) TOR_OSINT_GID=$(id -g) docker compose up -d`.

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
| `TOR_TIMEOUT` | `60` | `--timeout` | Segundos por petición (máx. 300). La primera conexión a una onion puede tardar más de 30 s |
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

Validación de cada línea: esquema `http`/`https`; host `.onion` (se admiten subdominios); 56
caracteres base32 para v3 **con verificación del checksum y la versión** (rend-spec-v3) o 16
para v2 (solo sintaxis; v2 está retirado desde 2021 y se avisa); sin credenciales embebidas.

```bash
tor-osint sources                          # válidas y rechazadas
tor-osint sources --add http://<id>.onion/ # añade una fuente validada
tor-osint sources --discovered             # .onion vistas en páginas que NO están en las fuentes
```

Los enlaces `.onion` encontrados **se registran pero nunca se visitan**: decides tú si añadirlos.

## 6. Comandos

### Recopilación

```bash
tor-osint tor-check                      # verifica que el tráfico sale por Tor
tor-osint crawl                          # consulta data/sources.txt (1 petición por fuente)
tor-osint crawl --url http://<id>.onion/ # solo las URLs indicadas
tor-osint crawl --save-raw               # además guarda el HTML original (ver Seguridad)
```

La salida de `crawl` marca cada página como nueva, con cambios o sin cambios, e indica las
alertas nuevas de la watchlist.

### Búsqueda y correlación

```bash
tor-osint search "empresa acme"          # texto completo (FTS5): relevancia, prefijos, sin tildes
tor-osint search --substring "100%"      # búsqueda literal
tor-osint regex "CVE-202[0-9]-[0-9]+"    # regex sobre la BD local
tor-osint iocs                           # estadísticas por tipo
tor-osint iocs --type cve                # tipos: email domain url ipv4 md5 sha1 sha256 cve onion
                                         #        btc eth attack pgp · alias: hash, crypto
tor-osint related example.com            # páginas donde aparece un IOC
tor-osint duplicates                     # contenido idéntico (SHA-256)
tor-osint duplicates --near              # casi duplicados (SimHash, --distance N)
```

### Cambios entre crawls

```bash
tor-osint changes                        # páginas que cambiaron en su último crawl
tor-osint history 3                      # versiones de la página 3
tor-osint diff 3                         # diff entre las dos últimas versiones
tor-osint diff 3 --from 4 --to 9         # entre dos versiones concretas
```

### Watchlist, notas y etiquetas

```bash
tor-osint watch add term "acme" --label "cliente"
tor-osint watch add ioc CVE-2024-3400
tor-osint watch list | rm ID | scan
tor-osint alerts                         # alertas pendientes (--all para todas)
tor-osint alerts --ack                   # marcar todas como revisadas (o --ack 3 5)
tor-osint note add page 3 "Mismo kit que el caso anterior"
tor-osint note add ioc example.com "Dominio de phishing confirmado"
tor-osint note list [page 3]
tor-osint tag add ioc CVE-2024-3400 prioridad
tor-osint tag list [prioridad]
```

Una alerta se genera por (vigilancia, página, versión del contenido): si la página no cambia no
se repite; si cambia y sigue coincidiendo, se crea otra. Los términos ignoran mayúsculas y tildes.

### Enriquecimiento, exportación y evidencias

```bash
curl -o nvd.json "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228"
tor-osint nvd-import nvd.json            # CVSS de los CVE presentes en la BD (--all: todos)
tor-osint export --format json|csv|stix|misp
tor-osint report [--output results/caso-01.html]
tor-osint verify                         # comprueba los hashes del manifiesto
tor-osint audit                          # registro de acciones (cadena de custodia)
```

`nvd-import` no consulta NVD: tú descargas el fichero (por clearnet, fuera de Tor) y la
herramienta solo lo lee. Admite `.json` y `.json.gz` del formato de la API 2.0.

Cada subcomando tiene ayuda propia (`tor-osint diff --help`). `python -m tor_osint` funciona igual.
Códigos de salida: `0` OK, `1` error de ejecución o verificación fallida, `2` entrada inválida.

## 6.1 Interfaz web

```bash
tor-osint web            # http://127.0.0.1:8765/
tor-osint web --open     # y abre el navegador
```

| Sección | Qué permite |
|---|---|
| Panel | Fuentes, páginas, IOCs, alertas pendientes, cambios recientes, duplicados, códigos HTTP |
| Fuentes y crawl | Añadir fuentes, crawl de todas o de las seleccionadas con progreso, `.onion` descubiertas |
| Cambios | Páginas que cambiaron; diff por palabras con selector de versiones y delta de IOCs |
| Páginas | Detalle con IOCs, enlaces (texto), historial de versiones, notas y etiquetas |
| Buscar | Texto completo con resaltado, literal y regex |
| IOCs | Estadísticas, filtro por tipo, CVSS, correlación con notas y etiquetas por IOC |
| Grafo | Grafo página ↔ IOC con leyenda, resaltado de vecinos (ratón o teclado) y vista en tabla |
| Watchlist | Vigilancias y alertas (revisar una o todas); indicador de alertas en la cabecera |
| Duplicados | Idénticos (SHA-256) y casi duplicados (SimHash) |
| Exportar e informe | JSON, CSV, STIX 2.1, MISP, informe HTML, verificación de integridad y auditoría |

Seguridad específica de la interfaz:

- Escucha **solo en loopback**; se valida la cabecera `Host` (DNS rebinding). En Docker,
  `--container` exige además `TOR_OSINT_CONTAINER=1` (lo define la imagen) y `--public-port`
  indica el puerto publicado en el anfitrión para la validación de `Host`.
- Las peticiones POST exigen `Content-Type: application/json`, un **token CSRF** por ejecución y,
  si el navegador envía `Origin`, que sea el propio.
- CSP estricta (`default-src 'none'; script-src 'self'`…, sin `unsafe-inline`), `X-Frame-Options:
  DENY`, `nosniff`, `no-referrer` y `no-store`.
- El frontend pinta todos los datos con `textContent`; un test falla si algún módulo usa
  `innerHTML`, `insertAdjacentHTML`, `document.write` o `eval`.
- Estáticos desde lista blanca y cuerpo de petición limitado a 64 KiB.
- Los colores del grafo (3 tonos + gris) están validados para daltonismo en modo claro y oscuro;
  la forma distingue páginas (cuadrados) de IOCs (círculos).

## 6.2 Crawl programado

`contrib/` incluye un servicio + timer de systemd **de usuario** (cada 6 h con margen aleatorio,
endurecido con `ProtectSystem=strict`) y un ejemplo de cron. Instrucciones en
[`contrib/README.md`](../contrib/README.md). Consulta siempre las mismas fuentes explícitas.

## 7. Estructura del proyecto

```
tor-osint/
├── src/tor_osint/        # 25 módulos Python + static/ (frontend)
├── tests/                # pytest, sin red (HTTP mockeado)
├── docker/               # Dockerfile de la app y servicio Tor (torrc)
├── contrib/              # systemd timer y cron para crawls programados
├── data/sources.txt      # fuentes (results.db y raw/ se ignoran en git)
├── results/              # exportaciones, informes y manifest.json (ignorado en git)
├── docker-compose.yml  pyproject.toml  README.md  LICENSE
```

## 8. Base de datos

SQLite en `data/results.db` (configurable con `--db`), esquema **v3**. Al abrir una base de datos
de una versión anterior se **migra automáticamente**: se crean las tablas nuevas, un snapshot
inicial por página, el SimHash y el índice FTS5.

| Tabla | Contenido |
|---|---|
| `pages` | Estado actual por URL final: fuente, fecha, HTTP, título y texto **redactados**, SHA-256, SimHash, enlaces e IOCs (JSON) |
| `snapshots` | Una fila por página y crawl: fecha, HTTP, título, hash, IOCs y SHA-256 del HTML crudo (si se guardó) |
| `contents` | Textos deduplicados por hash (cada versión distinta se guarda una vez) |
| `pages_fts` | Índice FTS5 (`unicode61`, sin tildes) sincronizado con `pages` por triggers |
| `iocs` | Relación IOC ↔ página con `value`, `normalized_value`, `first_seen`, `last_seen` |
| `watchlist`, `alerts` | Vigilancias y alertas `UNIQUE(watch_id, page_id, content_hash)` |
| `notes`, `tags` | Anotaciones sobre páginas (`id`) o IOCs (valor normalizado) |
| `cve_info` | CVSS, severidad, versión y descripción importados de NVD |
| `audit_log` | Fecha, usuario del sistema, acción y detalles (sin secretos) |

Normalización: emails y dominios en minúsculas, CVE y ATT&CK en mayúsculas, hashes en
minúsculas, IPv4 canónica, URLs sin credenciales ni fragmento, Ethereum en minúsculas, Bitcoin
Bech32 en minúsculas (Base58 conserva mayúsculas), PGP sin espacios en mayúsculas.

## 9. Seguridad

Segura por defecto:

- **Alcance cerrado**: solo `sources.txt` o `--url`. Sin recursión ni descubrimiento.
- **Límites y rate limiting**: timeout, tamaño máximo de respuesta, máximo de URLs, máximo 5
  redirecciones (solo `.onion`, con detección de bucles) e intervalo mínimo de 0,5 s entre
  peticiones, incluidas las fallidas.
- **Contenido no confiable**: solo `text/html`, `application/xhtml+xml` y `text/plain`; HTML
  parseado sin JavaScript; nunca se ejecuta ni se renderiza nada descargado; sin `subprocess`.
- **No se almacenan secretos**: antes de guardar se redactan combos `email:password`,
  `password=`/`token=`/`api_key=`, `Bearer`, credenciales en URLs, claves PEM, claves AWS, tokens de
  GitHub, Slack, Google, Stripe y JWT. El orden parseo → redacción → IOCs/hash garantiza que no
  llegan ni a la BD, ni a los IOCs, ni a las exportaciones.
- **HTML crudo opcional** (`crawl --save-raw`): es la única excepción a la redacción y por eso
  solo se activa explícitamente. Se guarda comprimido en `data/raw/<sha256>.html.gz` con
  permisos `0600`, nunca se abre ni se sirve desde la web, y la CLI avisa al activarlo.
- **Informe**: todo escapado, CSP `default-src 'none'`, sin enlaces clicables ni recursos externos.
- **CSV**: celdas que empiezan por `= + - @` se prefijan con `'` (anti CSV injection).
- **SQL**: solo consultas parametrizadas; `LIKE` con comodines escapados; FTS5 con cada palabra
  entre comillas (sin operadores del usuario).
- **Regex del usuario**: solo sobre la BD local.
- **Cadena de custodia**: manifiesto SHA-256 de cada exportación e informe, `verify` y
  `audit_log` de acciones.
- **Sin consultas externas automáticas**: el enriquecimiento CVSS lee un fichero local.

Uso responsable: emplea la herramienta solo sobre fuentes que tengas legitimidad para consultar
y respeta la legislación aplicable. No incluye ni incluirá autenticación, explotación ni
interacción con mercados.

## 10. Tests

```bash
pytest                  # todos los tests (sin Tor ni red: HTTP mockeado)
ruff check .            # lint
ruff format --check .
```

CI: `.github/workflows/ci.yml` ejecuta lint y tests en Python 3.10–3.13 y una prueba de extremo a
extremo con Docker contra la red Tor real (la onion oficial de The Tor Project).

| Test | Qué cubre |
|---|---|
| `test_config.py` | Entorno, overrides de CLI, límites |
| `test_sources.py` | Validación onion v2/v3 (checksum), normalización, carga de fuentes |
| `test_tor.py` | Proxy socks5h, timeout, truncado, Content-Type, redirecciones, bucles, rate limit |
| `test_parser.py` | Título, texto, enlaces, charset, HTML roto, límites |
| `test_ioc.py` | Cada extractor + falsos positivos + normalización |
| `test_crypto.py` | Keccak-256 (vector conocido y contra `hashlib`), EIP-55, BIP-173, BIP-350, Base58Check |
| `test_redact.py` | Secretos redactados y texto benigno intacto |
| `test_crawler.py` | Pipeline, no recursión, `max_urls`, fallos, HTTP 404 |
| `test_database.py` | Esquema, índices, upsert, first/last_seen, IOCs obsoletos |
| `test_history.py` | Snapshots, diff, cambios, FTS5, SimHash, HTML crudo, auditoría, **migración desde v2** |
| `test_watch_notes.py` | Watchlist, alertas por versión, notas, etiquetas, normalización |
| `test_search_dedup.py` | Búsqueda literal, comodines, regex, duplicados |
| `test_enrich.py` | Importación NVD (v4.0/v3.1/v2, gzip, errores), CVSS en el informe |
| `test_interop_custody.py` | **STIX 2.1 validado con la librería oficial `stix2`**, MISP, manifiesto y `verify` |
| `test_export_report.py` | JSON, CSV injection, escape XSS del informe, secciones |
| `test_cli.py` | Flujo de extremo a extremo de los comandos |
| `test_web.py` | Servidor real: loopback, Host, CSRF, Origin, CSP, estáticos, API completa, modo contenedor, análisis estático anti-`innerHTML` |

El frontend se verificó además en Chromium (Playwright), en claro a 1280 px y oscuro a 390 px,
con un recorrido que usa todas las vistas (notas, etiquetas, watchlist, grafo, exportación,
verificación) sin errores de consola, sin desbordamiento y sin ejecutar el HTML malicioso de
prueba. Esa verificación no forma parte de `pytest` para no añadir dependencias.

## 11. Limitaciones

- Los tests unitarios usan HTTP simulado; la prueba contra la red Tor real la hace el job
  «Docker + Tor real» del CI, solo contra el servicio onion oficial de The Tor Project.
- La extracción de IOCs es heurística: falsos positivos posibles (versiones tipo `1.2.3.4`,
  códigos tipo `T1234`) y falsos negativos (TLDs que coinciden con extensiones de fichero, como
  `.zip` o `.md`). Solo IPv4, no IPv6.
- La redacción de secretos se basa en patrones; no garantiza detectar todos los formatos.
- El hash se calcula sobre el texto **visible y redactado**: huella de la evidencia almacenada, no
  del fichero remoto (para eso está `--save-raw`).
- SimHash no es fiable con páginas de menos de ~50 palabras; el umbral (14 bits) se calibró con
  texto sintético. La búsqueda de casi duplicados es O(n²).
- STIX 2.1 no tiene objetos núcleo para carteras de criptomonedas ni huellas PGP: se omiten.
- Sin JavaScript: las páginas que generan su contenido en el cliente aparecen vacías.
- No se respeta `robots.txt` automáticamente; el control está en la lista cerrada de fuentes.
- La regex de usuario usa `re` sin timeout: una regex patológica puede tardar (solo datos locales).
- La interfaz web es monousuario y local, sin autenticación (por eso solo escucha en loopback);
  el estado del crawl en curso se pierde si se detiene el servidor.
- El healthcheck del contenedor de Tor solo comprueba que el arranque llegó al 100 % alguna vez.
