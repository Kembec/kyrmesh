# Kyrmesh

Kyrmesh es una red privada sobre WireGuard, compatible con las aplicaciones de
Tailscale, pensada para quien administra una red pequeña y necesita sumar
dispositivos de personas que no saben de redes. Su propuesta es que dar de alta
un dispositivo sea lo más sencillo posible: la persona abre un enlace de
invitación y queda conectada, sin terminal, sin claves y sin configurar nada de
red.

Kyrmesh es un fork de [Headscale](https://github.com/juanfont/headscale), el
servidor de control autoalojado para clientes de Tailscale. Conserva todo lo
de Headscale y le agrega el alta por invitación.

## Estado actual

- **Invitaciones de un solo uso.** Cada invitación es una clave de
  preautorización de un solo uso, con vencimiento, entregada como enlace. Un
  enlace usado, vencido o revocado se rechaza.
- **Piloto probado.** [`kyrmesh/pilot/`](kyrmesh/pilot/README.md) levanta en una
  sola máquina, sin root ni Docker, un servidor y varios dispositivos
  `tailscaled` reales, y comprueba acceso por política, denegación por
  defecto, revocación y el alta por invitación.

Lo que todavía no hay:

- En Windows el alta aún pide un comando: la aplicación de Tailscale no ofrece
  en pantalla la opción de servidor alternativo.
- No hay panel de administración: las invitaciones se crean desde la línea de
  comandos.
- El binario, el CLI y el módulo de Go siguen llamándose `headscale`.

## Cómo empezar

### 1. Compilar

Requiere Go 1.27 o superior.

```sh
go build -o headscale ./cmd/headscale
```

`make build` hace lo mismo, pero antes exige las herramientas de desarrollo
(`golangci-lint`, `buf`, `prettier` y otras); `nix develop` las instala.

### 2. Configurar

Parte de [`config-example.yaml`](config-example.yaml). Para las invitaciones,
lo imprescindible es `server_url`: debe ser la dirección por la que los
dispositivos llegan al servidor, porque con ella se arma el enlace. El resto de
la instalación y la configuración es la de Headscale:
[requisitos](docs/setup/requirements.md),
[instalación](docs/setup/install/source.md) y
[referencia de configuración](docs/ref/configuration.md).

### 3. Invitar un dispositivo

Con el servidor en marcha y un usuario creado
(`headscale users create <nombre>`; `headscale users list` muestra su id):

```sh
headscale invites create --user <id> --expiration 24h
```

Imprime un enlace `<server_url>/join?code=…`. `--expiration` es opcional
(24 h por defecto) y `--tags` asigna etiquetas en lugar de un usuario. Para
revocar una invitación que no se usó: `headscale preauthkeys expire --id <id>`.

### 4. Lo que hace quien la recibe

1. Abre el enlace en Safari o Chrome, en el dispositivo que quiere conectar.
2. Instala Tailscale y lo apunta al servidor: el perfil `/apple` en iPhone,
   iPad y Mac; «Use an alternate server» en Android.
3. Toca «Log in», confirma en la página que se abre y el dispositivo queda
   registrado con el usuario, las etiquetas y el vencimiento de la invitación.

## Probarlo

[`kyrmesh/pilot/README.md`](kyrmesh/pilot/README.md) explica cómo correr el
piloto (`kyrmesh/pilot/pilot.sh all`), qué escenarios cubre, cómo se aísla de
la red de la máquina y sus límites.

## Documentación heredada

Todo lo que Kyrmesh no cambia —políticas de acceso, DNS, rutas, DERP, OIDC,
API, clientes compatibles— está documentado en [`docs/`](docs/), que es la
documentación de Headscale. La versión publicada está en
[headscale.net](https://headscale.net/stable/).

## Contribuir

Ver [CONTRIBUTING.md](CONTRIBUTING.md). Las pruebas se corren con `make test`;
`make fmt` y `make lint` aplican el formato y el análisis del proyecto.

## Origen y licencia

Kyrmesh es un fork de [Headscale](https://github.com/juanfont/headscale),
creado por Juan Font y mantenido por sus colaboradores. Se distribuye bajo la
licencia BSD de 3 cláusulas, Copyright (c) 2020, Juan Font: ver
[LICENSE](LICENSE).

Este proyecto no está asociado con Tailscale Inc.
