## Qué cambia

<!-- Resumen breve y por qué. -->

## Cómo se ha probado

- [ ] `pytest`
- [ ] `ruff check .` y `ruff format --check .`
- [ ] Tests nuevos para el comportamiento nuevo o el error corregido

## Alcance y seguridad

- [ ] No amplía el alcance (sin descubrimiento, recursión, autenticación ni interacción con servicios)
- [ ] El contenido remoto sigue tratándose como no confiable (sin `innerHTML`, sin ejecutar nada descargado)
- [ ] No se guardan credenciales ni secretos nuevos
