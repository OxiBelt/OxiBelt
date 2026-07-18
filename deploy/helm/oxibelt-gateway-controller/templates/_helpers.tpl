{{- define "oxibelt-gateway-controller.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "oxibelt-gateway-controller.leaseName" -}}
{{- default (include "oxibelt-gateway-controller.name" .) .Values.leaderElection.leaseName | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "oxibelt-gateway-controller.image" -}}
{{- $repository := required "image.repository is required" .Values.image.repository -}}
{{- $digest := .Values.image.digest | default "" -}}
{{- if $digest -}}
{{- if not (regexMatch "^sha256:[0-9a-f]{64}$" $digest) -}}
{{- fail "image.digest must be an empty string or a lower-case sha256 digest" -}}
{{- end -}}
{{- printf "%s@%s" $repository $digest -}}
{{- else -}}
{{- printf "%s:%s" $repository (required "image.tag is required when image.digest is empty" .Values.image.tag) -}}
{{- end -}}
{{- end -}}

{{- define "oxibelt-gateway-controller.validateManagedConfigPath" -}}
{{- $path := .Values.managedConfigPath -}}
{{- if not (hasSuffix ".toml" $path) -}}
{{- fail "managedConfigPath must end in .toml" -}}
{{- end -}}

{{- $parts := splitList "/" $path -}}
{{- if lt (len $parts) 2 -}}
{{- fail "managedConfigPath must be a nested relative TOML path" -}}
{{- end -}}
{{- range $part := $parts -}}
{{- if not (regexMatch "^[A-Za-z0-9][A-Za-z0-9._-]*$" $part) -}}
{{- fail "managedConfigPath must contain only safe relative path segments" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "oxibelt-gateway-controller.validateSecurity" -}}
{{- if not (kindIs "bool" .Values.serviceAccount.automountServiceAccountToken) -}}
{{- fail "serviceAccount.automountServiceAccountToken must be a boolean" -}}
{{- end -}}
{{- if .Values.serviceAccount.automountServiceAccountToken -}}
{{- fail "serviceAccount.automountServiceAccountToken must remain false; the controller uses an explicit projected credential" -}}
{{- end -}}
{{- $expirationSeconds := int .Values.serviceAccount.tokenProjection.expirationSeconds -}}
{{- if or (lt $expirationSeconds 600) (gt $expirationSeconds 3600) -}}
{{- fail "serviceAccount.tokenProjection.expirationSeconds must be between 600 and 3600" -}}
{{- end -}}
{{- if not (kindIs "bool" .Values.watchAllNamespaces) -}}
{{- fail "watchAllNamespaces must be a boolean" -}}
{{- end -}}
{{- if not (kindIs "string" .Values.watchNamespace) -}}
{{- fail "watchNamespace must be a string" -}}
{{- end -}}
{{- if and .Values.watchAllNamespaces .Values.watchNamespace -}}
{{- fail "watchAllNamespaces=true cannot be combined with watchNamespace" -}}
{{- end -}}
{{- if and (not .Values.watchAllNamespaces) .Values.watchNamespace (or (gt (len .Values.watchNamespace) 63) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" .Values.watchNamespace))) -}}
{{- fail "watchNamespace must be a safe Kubernetes namespace name" -}}
{{- end -}}
{{- if lt (int .Values.replicaCount) 1 -}}
{{- fail "replicaCount must be at least 1" -}}
{{- end -}}
{{- if and .Values.leaderElection.leaseName (or (gt (len .Values.leaderElection.leaseName) 63) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" .Values.leaderElection.leaseName))) -}}
{{- fail "leaderElection.leaseName must be empty or a safe Kubernetes DNS label" -}}
{{- end -}}
{{- $leaseName := include "oxibelt-gateway-controller.leaseName" . -}}
{{- if or (gt (len $leaseName) 63) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" $leaseName)) -}}
{{- fail "leaderElection.leaseName must be empty or a safe Kubernetes DNS label" -}}
{{- end -}}
{{- $lease := int .Values.leaderElection.leaseDurationSeconds -}}
{{- $renew := int .Values.leaderElection.renewDeadlineSeconds -}}
{{- $retry := int .Values.leaderElection.retryPeriodSeconds -}}
{{- if or (lt $lease 10) (gt $lease 300) -}}
{{- fail "leaderElection.leaseDurationSeconds must be between 10 and 300" -}}
{{- end -}}
{{- if or (lt $renew 5) (gt $renew 120) -}}
{{- fail "leaderElection.renewDeadlineSeconds must be between 5 and 120" -}}
{{- end -}}
{{- if or (lt $retry 1) (gt $retry 30) -}}
{{- fail "leaderElection.retryPeriodSeconds must be between 1 and 30" -}}
{{- end -}}
{{- if or (ge $retry $renew) (ge $renew $lease) (gt (mul 2 $retry) $renew) (gt (add $renew $retry) $lease) -}}
{{- fail "leaderElection timings must satisfy 2 * retry <= renew, retry < renew < lease, and renew + retry <= lease" -}}
{{- end -}}
{{- if and .Values.podAntiAffinity.enabled (hasKey .Values.affinity "podAntiAffinity") -}}
{{- fail "podAntiAffinity.enabled=true cannot be combined with affinity.podAntiAffinity" -}}
{{- end -}}
{{- if or (lt (int .Values.podAntiAffinity.weight) 1) (gt (int .Values.podAntiAffinity.weight) 100) -}}
{{- fail "podAntiAffinity.weight must be between 1 and 100" -}}
{{- end -}}
{{- if not (regexMatch "^[A-Za-z0-9]([A-Za-z0-9._/-]*[A-Za-z0-9])?$" .Values.podAntiAffinity.topologyKey) -}}
{{- fail "podAntiAffinity.topologyKey must be a non-empty Kubernetes label key" -}}
{{- end -}}
{{- end -}}
