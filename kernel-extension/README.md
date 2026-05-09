# OxiBelt Kernel Extension

This directory contains the optional Linux host tuning package for high-traffic OxiBelt edge deployments.

It targets Linux `7.0.x` and newer. The installer refuses older kernel releases unless `--force` is provided for hosts with equivalent vendor backports.

## Install

Preview changes:

```sh
kernel-extension/install.sh --dry-run
```

Install and apply sysctl settings on the host:

```sh
sudo kernel-extension/install.sh --apply
kernel-extension/verify.sh
```

Stage into another root, useful for image builds or tests:

```sh
kernel-extension/install.sh --apply --root /tmp/oxibelt-root --kernel-release 7.0.3
kernel-extension/verify.sh --root /tmp/oxibelt-root --kernel-release 7.0.3
```

## Installed Files

- `/etc/sysctl.d/90-oxibelt-edge.conf`
- `/etc/security/limits.d/90-oxibelt-edge.conf`
- `/etc/systemd/system/oxibelt.service.d/10-limits.conf`

The sysctl template raises listen backlog, network backlog, UDP socket buffer ceilings, ephemeral port range, and system-wide file capacity. The limits template raises `nofile` only for the `oxibelt` service account, and the systemd template raises `nofile` for OxiBelt service deployments.

## Rollback

Remove the installed files, then reload the relevant host services:

```sh
sudo rm -f /etc/sysctl.d/90-oxibelt-edge.conf
sudo rm -f /etc/security/limits.d/90-oxibelt-edge.conf
sudo rm -rf /etc/systemd/system/oxibelt.service.d
sudo sysctl --system
sudo systemctl daemon-reload
```

## Container Notes

Containers usually cannot raise host sysctls or process limits after launch. This is especially true when OxiBelt is started with dropped Linux capabilities such as `--cap-drop=ALL`.

The supported model is:

- apply this package on the host before starting OxiBelt containers, or
- pass container runtime settings that are equivalent to the needed parts of this package.

A capability-dropped OxiBelt container can still benefit from tuning that was already applied by the host or by the container runtime. For example, host-level network tuning may improve container behavior, and Docker `--ulimit` values directly affect the OxiBelt process. The container should not be expected to run `kernel-extension/install.sh --apply` and change the host kernel at runtime.

For Docker, prefer setting process limits and allowed namespaced sysctls at container creation time:

```sh
docker run \
  --cap-drop=ALL \
  --ulimit nofile=1048576:1048576 \
  --sysctl net.core.somaxconn=65535 \
  oxibelt:latest
```

Docker only permits a subset of sysctls from container launch, and availability depends on the network mode, kernel, and runtime policy. With `--network host`, OxiBelt uses the host network namespace more directly, so host-applied network tuning is usually the clearest source of benefit.

Host systemd drop-ins such as `LimitNOFILE` for a native `oxibelt.service` do not automatically apply to processes started by Docker. Use Docker `--ulimit`, Compose `ulimits`, Kubernetes `securityContext` and runtime-specific settings, or an equivalent supervisor-level limit for container deployments.

If OxiBelt must bind privileged ports such as `:443`, either map host ports to unprivileged container ports or grant only the narrow capability needed for that use case, for example `CAP_NET_BIND_SERVICE`, instead of running the container privileged.
