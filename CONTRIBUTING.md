# Contribuir

¡Gracias por el interés! Antes de proponer cambios, ten en cuenta el alcance del proyecto.

## Alcance (no negociable)

tor-osint trabaja **solo** con fuentes `.onion` que el analista define explícitamente, una
petición por fuente y sin interactuar con ellas. No se aceptarán cambios que añadan:

- descubrimiento de servicios `.onion` o crawling recursivo;
- seguimiento automático de enlaces;
- autenticación, uso de credenciales, bypass de controles o explotación;
- interacción con servicios (formularios, compras, mensajes);
- consultas externas automáticas (el enriquecimiento debe ser a partir de ficheros locales);
- ejecución o renderizado de contenido descargado.

## Entorno de desarrollo

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check . && ruff format --check .
tor-osint web   # interfaz en http://127.0.0.1:8765/
```

Los tests **no necesitan Tor ni red**: el HTTP se simula con `tests/conftest.py`
(`FakeSession`, `make_onion()` para generar direcciones v3 válidas).

## Reglas de código

- Contenido remoto = no confiable. En el frontend, nunca `innerHTML` (hay un test que lo impide).
- SQL siempre parametrizado; nada de interpolar valores del usuario.
- Cada funcionalidad nueva con tests; cada error corregido con un test que lo reproduzca.
- Sin dependencias nuevas de ejecución salvo que sean imprescindibles y estén bien mantenidas.
- Docstrings en las funciones públicas y type hints donde aporten valor.
- Mensajes de commit al estilo [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`, `test:`…).

## Pull requests

Rellena la plantilla, mantén el PR acotado a un cambio y asegúrate de que el CI está en verde.
Si el cambio afecta a la seguridad, explica el riesgo y cómo lo has probado.
