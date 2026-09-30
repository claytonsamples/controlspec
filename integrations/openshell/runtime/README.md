# Reproduce the OpenShell runtime experiment

This is a local, synthetic purchase experiment using released NVIDIA OpenShell
v0.1.2 binaries. It runs a real gateway, supervisor and Linux workload through
the ControlSpec middleware. It is not a production deployment or a certification
of either project. No model, GPU, payment account or inference service is needed.

The tested host was Windows with Docker Desktop, Docker Engine 28.5.1 and a WSL2
Linux 6.6.87 kernel. OpenShell labels Windows/WSL2 support experimental. Startup
must pass its actual Landlock, seccomp and task-memory qualification; the kernel
version alone is insufficient.

## Start a fresh experiment

Requirements: PowerShell 7, Docker Desktop running Linux containers, an amd64
host, outbound access to GitHub/GHCR and package registries, and a ControlSpec
checkout. From the checkout root:

```powershell
pwsh -File integrations/openshell/runtime/launch.ps1
```

The launcher creates a unique `csrt-YYYYMMDD-xxxx` namespace, a controller, a
private state volume, a Docker network and two local images. It prints the path
of a `launch.json` manifest in the operating system's temporary directory. Keep
that manifest to identify the resources. It does not alter existing containers
or publish any host ports. A failed launch preserves resources and logs for
inspection; running it again creates a different experiment.

The controller mounts the checkout read-only at `/repo`, its private volume at
`/state`, and the Docker socket. The socket gives this **trusted operator
controller** authority over Docker. Neither the socket, checkout nor state
volume is mounted in the agent workload. The gateway creates a workload with
`network_mode=none` and a separate supervisor with host networking. Do not run
untrusted code in the controller or treat its unauthenticated gateway API as a
multiuser deployment.

The gateway API is plaintext and unauthenticated on the controller's bridge
address. **No published host ports does not isolate it from every sibling
container or the Docker host.** This setup assumes a trusted, single-operator
Docker environment. It also explicitly uses `AppArmor=Unconfined` and disables
resource admission. Those are local experiment settings, not production
hardening. ControlSpec's middleware TLS and JWT authentication remain enabled.

The launcher installs dependencies from the committed `backend/uv.lock`, verifies
the exact SHA-256 of each released executable archive before extracting it, and
generates fresh local credentials. It retains ordinary system trust roots and
adds only the experiment's **public target CA** to a derived supervisor image.
No NVIDIA executable is patched. Private keys never leave the state volume.
The base image digests are fixed; Ubuntu's curl package installation still uses
the current distribution repository, so this recipe does not claim reproducible
image bytes. The manifest records the resulting image IDs.

## Create and exercise the controlled workload

Use the controller and run name printed by the launcher:

```powershell
$Controller = 'YOUR_RUN_NAME-controller'
$Sandbox = 'YOUR_RUN_NAME'
docker exec $Controller openshell --gateway-endpoint http://127.0.0.1:17670 sandbox create --name $Sandbox --policy /state/policies/policy-controlspec.yaml --no-tty --detach -- sleep infinity
docker exec $Controller openshell --gateway-endpoint http://127.0.0.1:17670 sandbox get $Sandbox --output json
```

Keep sandbox names at most 19 characters. Copy a strict JSON request to the
workload using the CLI's upload facility, or pass the body directly to curl:

```powershell
$Body = '{"schema_version":"1","action_id":"runtime-purchase-1","amount_minor":4200,"currency":"USD","merchant":"demo-store","recurring":false}'
docker exec $Controller openshell --gateway-endpoint http://127.0.0.1:17670 sandbox exec --name $Sandbox --no-tty --no-login-shell -- /usr/bin/curl --silent --show-error --include --max-time 20 https://host.openshell.internal:18081/purchases -H 'content-type: application/json' --data-raw $Body
```

Check the request fields against the current `PurchaseRequest` schema if adapting
the example. A successful purchase requires a middleware-issued exact-action
ticket. Inspect state from the trusted controller, using certificate verification:

```powershell
docker exec $Controller /state/venv/bin/python -c "import json,ssl,urllib.request; c=ssl.create_default_context(cafile='/state/tls/target-ca.pem'); print(urllib.request.urlopen('https://127.0.0.1:18081/state',context=c).read().decode())"
```

The middleware TLS certificate is trusted by the gateway through an explicit CA;
each extension call also requires a gateway-signed JWT with the exact audience
`urn:openshell:extension:middleware:controlspec-demo`. The target uses a separate
CA and hostname-verified HTTPS. No TLS-skip rule or `curl -k` is needed.

For a pending larger purchase, use the existing operator CLI inside the trusted
controller with an interactive terminal:

```powershell
docker exec -it $Controller /state/venv/bin/python -m assurance.controlspec.openshell_demo.cli --state-dir /state approve --gateway-id YOUR_GATEWAY_ID --sandbox-id YOUR_SANDBOX_ID --action-id YOUR_ACTION_ID
```

The gateway ID is in `/state/bootstrap.json`; the sandbox ID comes from
`sandbox get`. The command displays the exact action and requires its request
digest to approve. The agent never receives the operator credential. A receipt
must still be reconciled before claiming verified completion.

`policy-native.yaml` retains the same host/port/binary/method/path admission
rules without the middleware. The controlled target still requires a ticket,
so native traffic reaching that target does not by itself produce an unguarded
purchase. This policy is not a strongest-possible native business policy, and
does not establish superiority over native OpenShell controls.

For this REST purchase endpoint, the native comparison is specifically the
configured method, path, query and destination boundary. This trial does not
demonstrate a native numeric purchase-body amount rule.

Run the recorded adversarial suite after creating the workload (it makes
synthetic purchases and deliberately stops this experiment's middleware):

```powershell
docker exec $Controller /state/venv/bin/python /repo/integrations/openshell/runtime/probe.py --sandbox $Sandbox --sandbox-id YOUR_SANDBOX_ID
```

The probe prints its evidence path. Preserve that JSON before removing the
experiment. Scripted approval in the probe is labeled as such; use the manual
operator command above to demonstrate an actual human approval.

## Why this trial uses HTTPS

During the v0.1.2 trial, a plain HTTP request was reported to the extension with
`target.scheme = "https"`. The pinned upstream relay passes the literal
`"https"` into middleware request construction in
[`middleware.rs`, line 524](https://github.com/NVIDIA/OpenShell/blob/6648bd0c290efbc41ba131ee9831ee45cd431f94/crates/openshell-supervisor-network/src/l7/middleware.rs#L524),
called by the REST path in [`relay.rs`, line 1864](https://github.com/NVIDIA/OpenShell/blob/6648bd0c290efbc41ba131ee9831ee45cd431f94/crates/openshell-supervisor-network/src/l7/relay.rs#L1864).
The HTTP attempt was rejected by ControlSpec's exact target check. This recipe
uses actual HTTPS end to end, so the observed scheme matches the transport. It
does not weaken the check or change upstream binaries. Recheck that behavior
before supporting HTTP or upgrading OpenShell.

## Files and trust boundaries

- `/state/bootstrap.json`: public setup metadata, identity and target origin.
- `/state/gateway.toml`: local gateway and strict extension registration.
- `/state/policies/`: copies of the two public policy examples.
- `/state/jwt/`, `/state/tls/`, `ticket.secret`, `operator.secret`: private state;
  never upload this directory or mount it in a workload.
- `/state/logs/`: target, middleware and gateway logs.
- `/state/rpc-targets.jsonl`: observed request target metadata, excluding tickets.
- `/state/decisions.sqlite` and `/state/target.sqlite`: local demonstration records.

The TLS leaf certificates expire after one day. Start a fresh experiment after
expiry; do not disable verification. The bootstrap refuses to replace existing
secrets or silently change its identity/configuration. Its per-service commands
are `target` and `middleware`; `up` starts all three services. Inspect recorded
PIDs and logs before restarting anything. The controller uses Docker's `--init`
to reap exited children.

Stop the named sandbox through `openshell sandbox delete`, then stop its exact
controller when finished. Preserve evidence before manually removing resources
listed in your manifest. This directory intentionally provides no Docker prune
or global cleanup command.

Upstream executables are unmodified Apache-2.0 OpenShell release artifacts;
[provenance and license information](../UPSTREAM.md) identifies the source pin.
The controller also installs third-party packages with their own licenses.
This independent experiment is not endorsed by NVIDIA or Hugging Face.
