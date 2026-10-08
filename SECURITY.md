# Seguridad

## Versiones con soporte

| Versión | Soporte |
|---|---|
| 0.5.x | ✅ |
| < 0.5 | ❌ |

## Reportar una vulnerabilidad

**No abras un issue público.** Usa el reporte privado de GitHub:
[Security → Report a vulnerability](https://github.com/Marbi8891/tor-osint/security/advisories/new).

Incluye la versión, cómo reproducirlo y el impacto que esperas. Intentaré responder en un plazo
de 7 días y publicar el arreglo junto con un aviso de seguridad cuando proceda.

Interesan especialmente:

- fugas de tráfico o DNS fuera de Tor;
- ejecución o renderizado de contenido remoto (XSS en la interfaz o en el informe);
- CSRF, DNS rebinding o exposición de la interfaz web fuera de loopback;
- credenciales o secretos que lleguen a la base de datos, exportaciones o informes;
- formas de que la herramienta consulte URLs que el analista no indicó (recursión, redirecciones).

## Modelo de amenazas (resumen)

tor-osint corre en la máquina del analista y procesa **contenido remoto no confiable**. Por eso:
todo el tráfico va por `socks5h`, las redirecciones solo pueden ir a `.onion`, el HTML se parsea
sin JavaScript, los secretos se redactan antes de guardar, el informe y la interfaz escapan todo y
aplican CSP estricta, y la interfaz web solo escucha en loopback con CSRF y validación de `Host`.
Detalle completo en la sección «Seguridad» del [manual](docs/MANUAL.md#9-seguridad).

## Uso responsable

Esta herramienta es para investigación y aprendizaje sobre fuentes que tengas legitimidad para
consultar, cumpliendo la legislación aplicable. No incluye ni incluirá funciones de
autenticación, explotación, evasión de controles ni interacción con servicios o mercados.
