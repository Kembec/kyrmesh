# Kyrmesh Core pilot

An isolated, reproducible pilot of Kyrmesh Core on Headscale. It proves, with
real `tailscaled` devices and real WireGuard sessions, that:

- two authorized devices reach the one resource the policy grants;
- everything else is denied by default: another port on the same device, a
  registered device without a grant, and a device holding a forged, expired or
  no pre-auth key;
- revoking a device cuts its access within seconds, leaves the others alone,
  and the device cannot come back with the key it used before;
- the host's own network, including a Tailscale already running on it, is the
  same before, during and after the pilot, and `down` leaves nothing behind.

No Headscale code is changed: the pilot is configuration, a policy and the
scripts that run it. No mock stands in for a connection.

## Run it

Requirements: `bash`, `curl`, `python3`, Tailscale ≥ 1.80 (`tailscale` and
`tailscaled`), and either Go (to build Headscale from this checkout) or a
Headscale binary in `HEADSCALE_BIN`. No root, no Docker, no VM.

```sh
kyrmesh/pilot/pilot.sh all          # up + test + down; exits 1 if any scenario fails
```

Or step by step: `up`, `test`, `down`. `KYRMESH_RUN` sets the run directory
(default `$TMPDIR/kyrmesh-pilot`) and `KYRMESH_RESULTS` where the report goes
(default `<run>-results`). The report, `results.md`, has one row per scenario
with PASS or FAIL and what was observed, plus the host snapshots it compared.

## How it stays isolated

| Piece | What it is | Why it cannot touch the host |
|---|---|---|
| Control | Headscale on `127.0.0.1:18080`, SQLite and keys in the run directory | loopback only; nothing listens on another interface |
| Devices | `resource` (user `svc`), `laptop` (`alice`), `phone` (`bob`), `outsider` (`mallory`), `intruder` (none) | each is a `tailscaled --tun=userspace-networking` with its own state, socket and SOCKS5 port: no TUN, no routes, no DNS, and `--no-logs-no-support` |
| Resource | two local HTTP services on the `resource` device: `28080` (granted) and `28081` (not granted) | bound to `127.0.0.1` |
| Relay | `derp-norelay.yaml` declares one unreachable region | Headscale needs a DERP map; with no reachable relay every packet takes a direct WireGuard path |

The policy (`policy.json`) has a single grant — `alice@` and `bob@` to
`svc@` on `tcp:28080` — so anything not named there is denied. Its `tests`
block states the same intent and `headscale policy check` runs it (S0).

## Scenarios

| Id | Checks |
|---|---|
| S0 | the policy's own tests pass against the live server |
| S1 allow | `laptop` and `phone` fetch a random marker from `resource:28080` over the tailnet; the row also says how long their first WireGuard session took to open |
| S1 e2e | each client gets a TSMP pong from `resource` (only its WireGuard endpoint can answer one), has a handshake and a confirmed direct address, and sees the peer key Headscale registered for `resource` |
| S2 | `resource:28081` is refused while it answers locally; `outsider` is refused and does not even get `resource` in its netmap; a forged key (real prefix, wrong secret), an expired key and no key never bring `intruder` to `Running`, each rejected for that exact reason, on a fresh `intruder` every time |
| S3 | `headscale nodes expire` on `phone` logs it out and makes `resource` treat it as expired (time measured) so its requests fail; `laptop` keeps access; after `nodes delete`, the used single-use key cannot bring `phone` back (`already used`) |
| S4 | interfaces, default and tunnel routes, resolvers and the host Tailscale state are identical before, during and after |
| S5 | after `down`, no pilot process or port remains and the run directory, with every key, is gone |

## Rollback

`kyrmesh/pilot/pilot.sh down` stops every pilot process by its pid file,
checks that none is left, and deletes the run directory (state, database and
keys). It only deletes a directory that `up` marked as its own. Nothing outside
the run and results directories is written.

## Limits of this pilot

- All devices run on one host. It proves control-plane authorization, policy
  enforcement, WireGuard sessions and revocation; it does not prove NAT
  traversal or relaying between networks, which needs devices on separate
  networks and a DERP server.
- Encryption is shown from both ends (TSMP pong, handshake, keys, direct
  path), not with a packet capture: that needs root, which the pilot avoids.
  Devices use the host's own addresses as endpoints, so no packet leaves it.
- `up` opens each client's first WireGuard session before the scenarios run
  and records how long it took; on a heavily loaded host it can exceed the
  5 s a first request would otherwise wait.
- Invitation without a terminal is a separate deliverable.

## Origin

Kyrmesh Core is a fork of [Headscale](https://github.com/juanfont/headscale),
BSD 3-Clause License, Copyright (c) 2020, Juan Font. This pilot keeps the
upstream code, license and attributions unchanged.
