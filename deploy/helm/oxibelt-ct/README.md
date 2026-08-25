# OxiBelt CT Helm scaffold

This experimental chart creates a role-isolated OxiBelt workload, signer sidecar, Secret mounts,
storage credential wiring, migration Job, Service, and NetworkPolicy. It does not synthesize the
OxiBelt runtime configuration.

`log.config` is the complete and sole source of truth for OxiBelt. It must contain the listeners,
TLS configuration, CT routes, log role and protocol, identity, signed-root trust, signer paths,
storage settings, shard, and limits. Chart values configure Kubernetes resources and the signer
process only; they are never merged into `log.config`.

The public Secret keys are projected at fixed paths:

- `/run/oxibelt/ct/roots/root-bundle.json`
- `/run/oxibelt/ct/identity/public-key.der`

The default configuration deliberately keeps CT disabled. Before deployment, replace `log.config`
with a complete validated configuration and ensure its signer profile, fixed Secret paths,
environment-variable names, listener port, role, and local/production profile agree with the chart
values. Production images must use immutable digests, and the example placeholder digests and
TEST-NET object-storage CIDR must be replaced.

The Service is disabled by default because this scaffold cannot derive OxiBelt's health listener
from the opaque `log.config`, and therefore cannot safely install an application readiness probe.
Enabling the Service requires `service.acknowledgeNoReadinessProbe: true`; doing so can route
traffic before CT publication is within MMD or another runtime subsystem is ready. A production
deployment should add a readiness probe aligned with its explicit OxiBelt health-listener
configuration before treating the chart as operational.
