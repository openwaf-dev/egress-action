# OpenWAF Egress CI

[English](README.md)

Una GitHub Action que pone el tráfico de salida de un job detrás de una lista de destinos permitidos. Cada conexión y
cada consulta DNS del job y de sus contenedores queda con nombre y registrada; lo que no está en `.github/egress.yml`
se informa (`audit`) o se rechaza (`enforce`); lo que sale se revisa en busca de secretos con los detectores de
[OpenWAF Egress](https://github.com/openwaf-dev/egress); y el resumen del job lista todos los destinos con los que
habló.

Funciona como un sidecar dentro del job, en el propio runner: sin cuenta, sin servicio y sin enviar datos a ningún
sitio salvo que actives [`send-events`](#enviar-los-eventos-a-openwaf). Beta en acceso anticipado.

Runners Linux, x64 y arm64: los de GitHub, o self-hosted donde el usuario del job llega a root con `sudo` o con el
daemon de Docker.

Documentación del producto: [developers.openwaf.dev/es/egress/ci/quickstart/](https://developers.openwaf.dev/es/egress/ci/quickstart/).

## Inicio rápido

1. Añade la acción como primer paso después del checkout (los pasos anteriores no quedan cubiertos):

   ```yaml
   steps:
     - uses: actions/checkout@v4
     - uses: openwaf-dev/egress-action@v0.3.2
     - run: make test
   ```

   En producción, fija el SHA completo del commit de la versión en vez de la etiqueta (una etiqueta se puede mover;
   un SHA, no), con la versión como comentario para que Dependabot pueda actualizarlo:
   `uses: openwaf-dev/egress-action@<SHA de 40 caracteres de v0.3.2> # v0.3.2`.

2. Sube `.github/egress.yml`:

   ```yaml
   version: 1
   mode: audit                 # audit: solo informa; enforce: rechaza el resto
   presets: [github-actions]   # la lista que GitHub publica para los runners de Actions (api.github.com/meta), nombres exactos
   allow:
     - proxy.golang.org        # puertos 80 y 443
     - "*.npmjs.org"           # cualquier nombre bajo npmjs.org (no npmjs.org en sí)
     - registry.example.com:5000
   inspect: []                 # hosts cuyo TLS se termina para revisar los cuerpos (ver abajo)
   ```

3. Ejecuta el workflow, abre el resumen del job y copia en `allow` los nombres que aparecen en «Names outside the
   policy». Cuando varias ejecuciones salgan limpias, pon `mode: enforce`.

Más workflows en [`examples/`](examples/): primera ejecución en audit, enforce, builds de Docker, un runner
self-hosted con `sudo`, un monorepo con una política por job y el envío de eventos a OpenWAF.

## Entradas

| Entrada | Por defecto | Qué hace |
|---|---|---|
| `policy` | `.github/egress.yml` | Fichero de política. |
| `mode` | vacío | `audit` o `enforce`; manda sobre el `mode` del fichero. |
| `lock` | `auto` | Bloqueo nftables limitado al usuario del job: `auto` (activo si se llega a root con `sudo` o Docker), `on` (el paso falla si no se llega a root), `off`. Sin el bloqueo solo se cubre `HTTPS_PROXY`; en enforce, un bloqueo que no se puede instalar hace fallar el paso. |
| `containers` | `track` | `track`: el Docker del job pasa por su propio socket; sus contenedores y builds se atribuyen y cumplen la política igual que el job. `lock-all`: además rechaza fuera de la política el tráfico de cualquier otro contenedor (runners que ejecutan un job cada vez). `off`: Docker sin tocar. |
| `no-proxy` | vacío | Entradas extra de `NO_PROXY`, separadas por comas. |
| `token` | `github.token` | Lee `api.github.com/meta` para el preset `github-actions`. |
| `send-events` | `off` | `on`: envía los destinos, bloqueos y detecciones del job a los eventos de OpenWAF Egress de tu organización. Necesita `permissions: id-token: write`. Un fallo nunca hace fallar el job. |
| `openwaf-api` | `https://dash.openwaf.dev` | API de OpenWAF para `send-events`. |

Salida: `proxy` (`http://127.0.0.1:PUERTO`).

La acción deja para los pasos siguientes `HTTPS_PROXY`, `HTTP_PROXY` (y sus formas en minúsculas), `NO_PROXY`
(`localhost`, `127.0.0.1`, `::1`, `172.16.0.0/12`, `.local`, `.localhost`, `.test` y tu `no-proxy`) y
`EGRESS_CI_STATE`; con el seguimiento de Docker, `DOCKER_HOST` y `BUILDX_BUILDER`; con `inspect`, las variables de
CA que se listan en [Límites](#límites).

## Política

| Clave | Significado |
|---|---|
| `version` | `1`. |
| `mode` | `audit` (por defecto) o `enforce`. |
| `presets` | `github-actions`: los nombres que GitHub publica para los runners de Actions en `api.github.com/meta` (se descargan al empezar y se guardan 6 horas; si la descarga falla, una copia incluida en el binario), con las cuentas de almacenamiento de Azure por nombre exacto, más `raw.githubusercontent.com`. |
| `allow` | `host` (puertos 80 y 443), `*.dominio` (cualquier nombre por debajo, no el dominio en sí), `host:5000`, `host:80,8080`, `host:*` (cualquier puerto). Los nombres no distinguen mayúsculas; se acepta una dirección IPv4 como host. |
| `inspect` | Hosts cuyo TLS termina el proxy para revisar los cuerpos. Misma sintaxis que `allow`. |

Una clave desconocida es un error: una errata hace fallar el paso en vez de no permitir nada sin avisar.

## Cómo funciona

| Pieza | Qué hace |
|---|---|
| Proxy | `HTTPS_PROXY`/`HTTP_PROXY` para los pasos siguientes. Los túneles `CONNECT` se comprueban por nombre y por el SNI de TLS (un SNI fuera de la política se rechaza); no se descifran salvo que el host esté en `inspect`. Se rechazan los destinos de loopback, link-local (metadatos de la nube) y multicast. |
| Bloqueo | Una tabla nftables que solo afecta a los sockets del usuario del job: su DNS va al forwarder y cualquier otra conexión TCP a un proxy transparente (el propio runner, herramientas que ignoran las variables de proxy). El resto de flujos (UDP, ICMP, IPv6) fuera de la política se rechaza en enforce. |
| Proxy transparente | Pone nombre a cada conexión con su SNI de TLS o su Host de HTTP, comprueba ese nombre contra la política y que la dirección a la que se envió es una de las que resuelve ese nombre (un SNI permitido enviado a otra dirección es domain fronting y se rechaza). Una conexión sin nombre solo pasa a una dirección que resolvió un nombre permitido. |
| DNS | Cada nombre se registra con quién lo pidió; los nombres fuera de la política reciben NXDOMAIN en enforce; las etiquetas largas de alta entropía (datos codificados en nombres) se marcan. |
| Docker | `DOCKER_HOST` apunta a un socket que sirve el sidecar. Las redes del job entran en el bloqueo por subred al crearse (un contenedor que pide el bridge por defecto recibe la red propia del job), así que un contenedor está cubierto desde su primer paquete: su DNS y su TCP pasan por el mismo forwarder y el mismo proxy transparente, atribuidos por contenedor, y el resto se rechaza en enforce. Contenedores, redes y volúmenes llevan una etiqueta. Los pulls de imágenes se comprueban por registry antes de que el daemon descargue nada. `docker build` usa un contenedor builder del job (`BUILDX_BUILDER`, carga las imágenes en el daemon), así que los pasos del build también son del job; su caché de BuildKit se conserva para el siguiente job del mismo usuario del runner, hasta 4 GB. |
| DLP | Se revisan la URL, las cabeceras y los cuerpos de texto de hasta 4 MiB de HTTP en claro y de HTTPS inspeccionado: claves privadas, claves de acceso de AWS, claves `sk-`, tokens de GitHub (salvo hacia GitHub) y tarjetas de pago (Luhn). En enforce la petición se rechaza. |
| Informe | El resumen del job: destinos con puertos, vía (proxy, direct, container, udp), bytes, contenedores, pulls de imágenes, nombres fuera de la política y detecciones. `report.json` en el log del paso posterior. |

## Enviar los eventos a OpenWAF

Con `send-events: on` y `permissions: id-token: write`, el paso posterior pide a GitHub un token OIDC (audiencia
`openwaf-egress-ci`), lo cambia en la API de OpenWAF por un token que dura 15 minutos y envía un evento por destino
(host, puerto, vía, contenedor, decisión, motivo, ids de detección, número de conexiones y bytes) con la identidad de
la ejecución (repositorio, workflow, job, id e intento de la ejecución, commit, ref, evento y nombre del runner).
Nunca cuerpos, cabeceras ni URLs. El repositorio tiene que estar registrado en una organización de OpenWAF con Egress
activado. Si algo falla (sin `id-token: write`, un repositorio sin registrar, la red), el resumen dice por qué y el
job sigue. Ver [la documentación](https://developers.openwaf.dev/es/egress/ci/send-events/).

## Límites

- Solo se cubren los pasos posteriores a la acción. Un paso con root puede quitar el bloqueo: en los runners de
  GitHub todos los jobs tienen `sudo`, y en los self-hosted el grupo docker equivale a root. La acción encarece la
  exfiltración por parte de una dependencia o una herramienta; no es una frontera frente a código que se propone
  saltársela.
- Docker usado sin `DOCKER_HOST` (una herramienta que abre `/var/run/docker.sock` por su cuenta) no se atribuye; con
  `lock-all` su tráfico fuera de la política se rechaza igualmente y, si no, aparece como ajeno al job. Los
  contenedores con `--network host` quedan fuera del bloqueo salvo que se ejecuten con el usuario del job.
- Los pulls de imágenes los hace el daemon: se comprueba el registry, las conexiones propias del daemon no pasan por
  el proxy.
- Sin `inspect`, los cuerpos de las peticiones HTTPS no se revisan: los proxies ven el destino, no el contenido.
  Inspeccionar exige que el job confíe en una CA creada para la ejecución (exportada como `NODE_EXTRA_CA_CERTS`,
  `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`); las herramientas con su propio almacén
  de confianza o con pinning fallan. La inspección se aplica a las conexiones hechas por `HTTPS_PROXY`, en HTTP/1.1.
- Los destinos en `172.16.0.0/12` (el rango de direcciones de Docker) quedan a las reglas del propio runner.
- Solo IPv4 para poner nombre al TCP; el IPv6 del job se rechaza en enforce.
- Un job por usuario del runner a la vez (el bloqueo y los puertos van por usuario).

## Build

`scripts/build-dist.sh` genera `dist/` de forma reproducible (versión de Go de `go.mod`; binarios guardados con
`gzip -n` y los digests de los binarios sin comprimir en `dist/SHA256SUMS`, que se comprueban antes de cada
ejecución); la CI comprueba que `dist/` coincide con el código y ejecuta las sondas de contención (`tests/probes.sh`)
en runners de GitHub en audit y en enforce.

## Seguridad

Las vulnerabilidades se informan en privado a **security@openwaf.dev** (ver [SECURITY.md](SECURITY.md)); nunca en
un issue público.

## Contribuir

Ver [CONTRIBUTING.md](CONTRIBUTING.md) y [CHANGELOG.md](CHANGELOG.md).

## Licencia

[Apache License 2.0](LICENSE). © OpenWAF.
