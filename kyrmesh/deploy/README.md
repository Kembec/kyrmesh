# Instalar el servidor de Kyrmesh

Un comando deja un servidor de Kyrmesh funcionando en una VM gratuita de Google Cloud, con su
registro DNS, su certificado y un primer enlace de invitación. Quien lo instala no abre puertos de
su router, no crea registros DNS, no compila y no escribe `sudo`.

```sh
git clone https://github.com/Kembec/kyrmesh && cd kyrmesh/kyrmesh/deploy/gcp
CLOUDFLARE_API_TOKEN=<token> ./up.sh --project <proyecto-gcp> --host ctrl.red.ejemplo.com --zone ejemplo.com
```

Al terminar imprime la dirección del servidor y un enlace de un solo uso, válido una hora, que se
abre en el primer dispositivo para sumarlo a la red.

## Lo que hace falta antes

| Qué | Para qué |
|---|---|
| Un proyecto de Google Cloud con facturación activa | La VM `e2-micro` y su disco entran en el nivel gratuito de Compute Engine, pero Google lo exige |
| `gcloud` con la sesión iniciada | Terraform usa esa sesión. Cloud Shell ya la trae, junto con `gcloud` |
| Una zona en Cloudflare y un token de esa zona | Cloudflare › My Profile › API Tokens › plantilla «Edit zone DNS», limitada a la zona. El token queda en el servidor para renovar el certificado y Cloudflare no lo limita a un registro: quien tome el servidor puede editar toda la zona. Usa una zona solo para Kyrmesh (un dominio aparte o una subzona delegada) |

Terraform 1.11 o superior se usa si está instalado; si no, `up.sh` descarga la versión 1.16.4 junto
a sí mismo y comprueba su SHA-256.

`--host` es el nombre por el que los dispositivos llegan al servidor y debe estar libre: si ya
tiene un registro A que no sea de este despliegue (creado por Kyrmesh, con el comentario `kyrmesh`, y
con el estado de esta carpeta para ese `--host`), `up.sh` se detiene antes de crear nada. Opciones: `--region` y
`--compute-zone` (us-east1, us-central1 o us-west1, las del nivel gratuito), `--user` (el primer
usuario, `admin` por defecto), `--staging` (certificado de prueba de Let's Encrypt) y
`--plan-only` (muestra el plan y no crea nada).

## Qué crea

| Recurso | Detalle |
|---|---|
| Red, subred y dos reglas de firewall | Públicos solo 443/tcp (control y DERP sobre TLS) y 3478/udp (STUN); SSH solo desde IAP |
| Cuenta de servicio | Su único permiso es leer el secreto del token |
| Secreto en Secret Manager | El token de Cloudflare, escrito con un argumento de solo escritura: no queda en el estado ni en el plan de Terraform |
| VM `e2-micro`, Debian 12, 30 GB | Arranque seguro (Shielded VM); dirección efímera |

El estado de Terraform queda en `gcp/terraform.tfstate`, junto al script, y se necesita para
actualizar o retirar el servidor.

## Qué pasa al arrancar la VM

`gcp/startup.sh` corre en cada arranque. La primera vez lee de los metadatos de la instancia el
instalador y sus parámetros, pide el token a Secret Manager y ejecuta `install.sh`, que:

1. descarga el binario de la versión fijada en `RELEASE` y lo rechaza si su SHA-256 no coincide;
2. crea el usuario de sistema `kyrmesh` y guarda el token con permiso 0400 solo para él (el servicio no puede llegar al servidor de metadatos, así que tampoco al secreto por la cuenta de servicio);
3. escribe la configuración, la valida con `configtest` y deja una política que niega todo salvo
   que los dispositivos del primer usuario se vean entre sí;
4. instala dos servicios de systemd: `kyrmesh-dns-a`, que en cada arranque apunta el registro A a la
   dirección actual de la VM (solo si no existe o lo creó Kyrmesh; uno ajeno no se toca), y `kyrmesh`, aislado (sin root, sistema de solo lectura, sin acceso a
   `/home`);
5. obtiene un certificado comodín por DNS-01, así el nombre del servidor no aparece en los
   registros públicos de transparencia de certificados.

En los arranques siguientes, si los metadatos no cambiaron, solo renueva el token si se rotó.

## Otro Linux

`install.sh` funciona en cualquier Linux con systemd (Debian 12 o Ubuntu 22.04 en adelante, amd64
o arm64) desde un clon del repositorio. Sin una nube que lo aloje, el equipo necesita una
dirección pública con 443/tcp y 3478/udp abiertos:

```sh
sudo KYRMESH_HOST=ctrl.red.ejemplo.com KYRMESH_ZONE=ejemplo.com KYRMESH_TOKEN_FILE=token bash install.sh
```

El encabezado del script lista el resto de las variables.

## Administrar, actualizar y retirar

- **Otra invitación**: `gcloud compute ssh <vm> --zone=<zona> --project=<proyecto> --tunnel-through-iap --command='sudo kyrmesh-invite [usuario] [vencimiento]'`.
- **Actualizar**: con `RELEASE` en la versión nueva (`git pull`), se corre otra vez `up.sh` con
  los mismos parámetros y se reinicia la VM (`gcloud compute instances reset`).
- **Rotar el token**: `cloudflare_token_version = "2"` en `terraform.tfvars` (`up.sh` escribe
  sus parámetros en `up.auto.tfvars` y no toca ese archivo), `up.sh` con el token nuevo y un
  reinicio de la VM.
- **Retirar**: `deletion_protection = false` en `terraform.tfvars`; en `gcp/`, con
  `GOOGLE_OAUTH_ACCESS_TOKEN=$(gcloud auth print-access-token)`, `terraform apply` y
  `terraform destroy`; después se borra el registro A en Cloudflare.

## Costo

La VM `e2-micro`, el disco de 30 GB estándar, 1 GB de salida al mes y el secreto (6 versiones
activas y 10.000 accesos al mes) entran en los niveles gratuitos de Google Cloud en las tres
regiones admitidas. La dirección IPv4 externa se rige por la tarifa de red vigente de Google
Cloud.

## Publicar una versión

Una etiqueta `kyrmesh-v*` dispara `.github/workflows/kyrmesh-release.yml`, que compila los dos
binarios de forma reproducible y los publica con `SHA256SUMS`. Después se fijan la versión y las
sumas en `RELEASE`, comprobadas contra una compilación local del mismo commit:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags=-buildid= -o kyrmesh-linux-amd64 ./cmd/headscale
```

## Probar sin nube

`test/e2e-lima.sh` levanta una VM desechable de Debian 12 con Lima y reproduce un primer arranque
en GCE sin nada real detrás: Pebble hace de autoridad certificadora y `mocks.py` de servidor de
metadatos, Secret Manager, Cloudflare y la descarga de la versión. Comprueba el certificado, el
registro A, que el token no aparezca en los registros, la invitación, que un binario alterado se
rechace y que todo vuelva tras reiniciar. Al final borra la VM.

```sh
kyrmesh/deploy/test/e2e-lima.sh <binario kyrmesh-linux-arm64> <carpeta con pebble y pebble-challtestsrv>
```
