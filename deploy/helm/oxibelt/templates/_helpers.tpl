{{- define "oxibelt.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "oxibelt.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "oxibelt.name" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "oxibelt.selectorLabels" -}}
app.kubernetes.io/name: {{ include "oxibelt.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "oxibelt.labels" -}}
{{ include "oxibelt.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}

{{- define "oxibelt.configMapName" -}}
{{- if and (not .Values.config.create) (not .Values.config.existingConfigMap) -}}
{{- fail "config.existingConfigMap is required when config.create=false" -}}
{{- end -}}
{{- if .Values.config.existingConfigMap -}}
{{- .Values.config.existingConfigMap -}}
{{- else -}}
{{- printf "%s-config-%s" (include "oxibelt.name" . | trunc 42 | trimSuffix "-") (include "oxibelt.generatedConfigDigest" . | trunc 12) -}}
{{- end -}}
{{- end -}}

{{- define "oxibelt.operationalProfileConfig" -}}
{{- if .Values.operationalProfile.name -}}
profile = {{ .Values.operationalProfile.name | quote }}
profile_version = {{ .Values.operationalProfile.version }}
{{ end -}}
{{- end -}}

{{- define "oxibelt.operationalProfileWafConfig" -}}
{{- if .Values.operationalProfile.name }}
[waf]
enabled = true
mode = {{ .Values.operationalProfile.wafMode | quote }}
{{ end -}}
{{- end -}}

{{- define "oxibelt.publicTlsConfig" -}}
{{- if .Values.tls.serverNames -}}
server_names = {{ .Values.tls.serverNames | toJson }}
require_sni = true
reject_unknown_sni = true
{{ end -}}
{{- end -}}

{{- define "oxibelt.generatedConfigContent" -}}
{{- include "oxibelt.operationalProfileConfig" . -}}
{{- tpl .Values.config.inline . -}}
{{- include "oxibelt.operationalProfileWafConfig" . -}}
{{- end -}}

{{- define "oxibelt.certMountPath" -}}
{{- $configMountPath := trimSuffix "/" .Values.config.mountPath -}}
{{- printf "%s/cert" (dir $configMountPath) -}}
{{- end -}}

{{- define "oxibelt.adminBind" -}}
{{- $address := .Values.admin.bindAddress -}}
{{- $port := int .Values.admin.service.port -}}
{{- if or (eq $address "::") (eq $address "::1") -}}
{{- printf "[%s]:%d" $address $port -}}
{{- else -}}
{{- printf "%s:%d" $address $port -}}
{{- end -}}
{{- end -}}

{{- define "oxibelt.adminConfig" -}}
[admin]
enabled = {{ .Values.admin.enabled }}
bind = {{ include "oxibelt.adminBind" . | quote }}
bearer_token_env = "OXIBELT_ADMIN_TOKEN"
{{- if .Values.admin.insecureDevelopmentMode.enabled }}
transport = "plaintext"
allow_insecure_plaintext = true
{{- else if .Values.admin.tls.enabled }}
transport = "tls"
allow_insecure_plaintext = false
{{- else }}
transport = "plaintext_allowlist"
allow_insecure_plaintext = false
{{- end }}
plaintext_allowed_source_cidrs = ["127.0.0.0/8", "::1/128"]
{{- if and .Values.admin.enabled .Values.admin.tls.enabled }}

[admin.tls]
enabled = true
min_version = "tls1.3"
max_version = "tls1.3"
session_tickets = false
require_sni = true
reject_unknown_sni = true

[[admin.tls.certificates]]
server_names = {{ .Values.admin.tls.serverNames | toJson }}
cert_chain = "admin-server/tls.crt"
private_key = "admin-server/tls.key"
default = true

[admin.tls.client_auth]
{{- if .Values.admin.mtls.enabled }}
mode = "require"
ca_certs = ["admin-client-ca/ca.crt"]
{{- else }}
mode = "off"
ca_certs = []
{{- end }}
verify_depth = {{ .Values.admin.mtls.verifyDepth }}
{{- end }}
{{- end -}}

{{- define "oxibelt.generatedConfigDigest" -}}
{{- printf "oxibelt-helm-config-v1\n%s\n%s" .Values.config.key (include "oxibelt.generatedConfigContent" .) | sha256sum -}}
{{- end -}}

{{- define "oxibelt.configDigest" -}}
{{- if .Values.config.existingConfigMap -}}
{{- $digest := required "config.existingConfigMapDigest is required when config.existingConfigMap is set" .Values.config.existingConfigMapDigest -}}
{{- if not (regexMatch "^[a-f0-9]{64}$" $digest) -}}
{{- fail "config.existingConfigMapDigest must be a lower-case 64-character SHA-256 digest" -}}
{{- end -}}
{{- $digest -}}
{{- else -}}
{{- include "oxibelt.generatedConfigDigest" . -}}
{{- end -}}
{{- end -}}

{{- define "oxibelt.oxiruleConfigMapDigest" -}}
{{- if .Values.oxirule.enabled -}}
{{- $digest := required "oxirule.existingConfigMapDigest is required when oxirule.enabled=true" .Values.oxirule.existingConfigMapDigest -}}
{{- if not (regexMatch "^[a-f0-9]{64}$" $digest) -}}
{{- fail "oxirule.existingConfigMapDigest must be a lower-case 64-character SHA-256 digest" -}}
{{- end -}}
{{- $digest -}}
{{- end -}}
{{- end -}}

{{- define "oxibelt.validatePublicTls" -}}
{{- if and .Values.tls.serverNames (not .Values.tls.enabled) -}}
{{- fail "tls.serverNames requires tls.enabled=true" -}}
{{- end -}}
{{- $seenServerNames := dict -}}
{{- range $serverName := .Values.tls.serverNames -}}
{{- if not (regexMatch "^([*][.])?[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?([.][A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$" $serverName) -}}
{{- fail "tls.serverNames must contain valid DNS names or leftmost wildcards" -}}
{{- end -}}
{{- $normalizedServerName := lower $serverName -}}
{{- if hasKey $seenServerNames $normalizedServerName -}}
{{- fail "tls.serverNames must not contain duplicate names" -}}
{{- end -}}
{{- $_ := set $seenServerNames $normalizedServerName true -}}
{{- end -}}
{{- end -}}

{{- define "oxibelt.validateQuicHostKey" -}}
{{- $secretName := .Values.quic.hostKeySecretName -}}
{{- if $secretName -}}
{{- if or (gt (len $secretName) 253) (not (regexMatch "^[a-z0-9]([a-z0-9-]*[a-z0-9])?$" $secretName)) -}}
{{- fail "quic.hostKeySecretName must be a safe Kubernetes Secret name" -}}
{{- end -}}
{{- if not (regexMatch "^[A-Za-z0-9._-]+$" .Values.quic.hostKeySecretKey) -}}
{{- fail "quic.hostKeySecretKey must be a safe Kubernetes Secret key" -}}
{{- end -}}
{{- if and .Values.tls.enabled (eq $secretName .Values.tls.secretName) -}}
{{- fail "quic.hostKeySecretName must differ from tls.secretName so the host key remains narrowly projected" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "oxibelt.validateOperationalProfile" -}}
{{- include "oxibelt.validatePublicTls" . -}}
{{- include "oxibelt.validateQuicHostKey" . -}}
{{- $profile := .Values.operationalProfile -}}
{{- $name := $profile.name -}}
{{- $version := int $profile.version -}}
{{- if lt $version 1 -}}
{{- fail "operationalProfile.version must be at least 1" -}}
{{- end -}}
{{- if and (not $name) (ne $version 1) -}}
{{- fail "operationalProfile.version requires a nonempty operationalProfile.name" -}}
{{- end -}}
{{- if $name -}}
{{- if ne $name "edge-secure-medium" -}}
{{- fail "operationalProfile.name must be edge-secure-medium" -}}
{{- end -}}
{{- if not (has $profile.wafMode (list "enforcing" "monitor")) -}}
{{- fail "operationalProfile.wafMode must be enforcing or monitor" -}}
{{- end -}}
{{- if or (not .Values.config.create) .Values.config.existingConfigMap -}}
{{- fail "operationalProfile.name requires chart-owned config.create=true with no config.existingConfigMap" -}}
{{- end -}}
{{- if eq $name "edge-secure-medium" -}}
{{- if ne $version 1 -}}
{{- fail "operationalProfile edge-secure-medium supports only version 1" -}}
{{- end -}}
{{- if not .Values.tls.enabled -}}
{{- fail "operationalProfile edge-secure-medium requires tls.enabled=true" -}}
{{- end -}}
{{- if not .Values.tls.secretName -}}
{{- fail "operationalProfile edge-secure-medium requires tls.secretName" -}}
{{- end -}}
{{- if eq (len .Values.tls.serverNames) 0 -}}
{{- fail "operationalProfile edge-secure-medium requires tls.serverNames" -}}
{{- end -}}
{{- if not .Values.quic.hostKeySecretName -}}
{{- fail "operationalProfile edge-secure-medium requires quic.hostKeySecretName" -}}
{{- end -}}
{{- if not .Values.metrics.enabled -}}
{{- fail "operationalProfile edge-secure-medium requires metrics.enabled=true" -}}
{{- end -}}
{{- if .Values.admin.enabled -}}
{{- fail "operationalProfile edge-secure-medium keeps admin.enabled=false because the chart does not render the required IPM and durable audit configuration" -}}
{{- end -}}
{{- if .Values.admin.service.enabled -}}
{{- fail "operationalProfile edge-secure-medium keeps admin.service.enabled=false" -}}
{{- end -}}
{{- if lt (int .Values.lifecycle.terminationGracePeriodSeconds) 340 -}}
{{- fail "operationalProfile edge-secure-medium requires lifecycle.terminationGracePeriodSeconds of at least 340" -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "oxibelt.validateConfigRollout" -}}
{{- $mode := .Values.configRollout.mode -}}
{{- if not (has $mode (list "helm_immutable" "kubernetes_immutable")) -}}
{{- fail "configRollout.mode must be helm_immutable or kubernetes_immutable" -}}
{{- end -}}
{{- $path := .Values.configRollout.managedConfigPath -}}
{{- if hasPrefix "/" $path -}}
{{- fail "configRollout.managedConfigPath must be relative to the config root" -}}
{{- end -}}
{{- if not (hasSuffix ".toml" $path) -}}
{{- fail "configRollout.managedConfigPath must end in .toml" -}}
{{- end -}}
{{- $parts := splitList "/" $path -}}
{{- if lt (len $parts) 2 -}}
{{- fail "configRollout.managedConfigPath must be a nested relative TOML path" -}}
{{- end -}}
{{- range $part := $parts -}}
{{- if not (regexMatch "^[A-Za-z0-9][A-Za-z0-9._-]*$" $part) -}}
{{- fail "configRollout.managedConfigPath must contain only safe relative path segments" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "oxibelt.validateBaseConfigKey" -}}
{{- $key := .Values.config.key -}}
{{- if eq $key "gateway-config-directory" -}}
{{- fail "config.key must not use the reserved gateway-config-directory sentinel key" -}}
{{- end -}}
{{- if not (regexMatch "^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$" $key) -}}
{{- fail "config.key must be a safe ConfigMap key and base filename" -}}
{{- end -}}
{{- end -}}

{{- define "oxibelt.validateRedisSecretProjections" -}}
{{- $projections := .Values.sharedState.redisSecretProjections | default (list) -}}
{{- $projectionNames := dict -}}
{{- range $projection := $projections -}}
{{- if not $projection.name -}}
{{- fail "sharedState.redisSecretProjections[].name is required" -}}
{{- else if or (gt (len $projection.name) 63) (not (regexMatch "^[a-z0-9]([a-z0-9-]*[a-z0-9])?$" $projection.name)) -}}
{{- fail "sharedState.redisSecretProjections[].name must be a safe lower-case DNS label up to 63 characters" -}}
{{- end -}}
{{- if hasKey $projectionNames $projection.name -}}
{{- fail "sharedState.redisSecretProjections must not reuse a projection name" -}}
{{- end -}}
{{- $_ := set $projectionNames $projection.name true -}}
{{- if not $projection.secretName -}}
{{- fail "sharedState.redisSecretProjections[].secretName is required" -}}
{{- else if or (gt (len $projection.secretName) 253) (not (regexMatch "^[a-z0-9]([a-z0-9-]*[a-z0-9])?$" $projection.secretName)) -}}
{{- fail "sharedState.redisSecretProjections[].secretName must be a safe Kubernetes Secret name" -}}
{{- end -}}
{{- if not $projection.items -}}
{{- fail "sharedState.redisSecretProjections[].items must contain at least one Secret key" -}}
{{- else -}}
{{- $paths := dict -}}
{{- range $item := $projection.items -}}
{{- if not $item.key -}}
{{- fail "sharedState.redisSecretProjections[].items[].key is required" -}}
{{- else if not (regexMatch "^[A-Za-z0-9._-]+$" $item.key) -}}
{{- fail "sharedState.redisSecretProjections[].items[].key must be a safe Kubernetes Secret key" -}}
{{- end -}}
{{- if not $item.path -}}
{{- fail "sharedState.redisSecretProjections[].items[].path is required" -}}
{{- else if not (regexMatch "^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*$" $item.path) -}}
{{- fail "sharedState.redisSecretProjections[].items[].path must be a safe relative path" -}}
{{- end -}}
{{- if hasKey $paths $item.path -}}
{{- fail "sharedState.redisSecretProjections[].items must not reuse a projected path" -}}
{{- end -}}
{{- $_ := set $paths $item.path true -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "oxibelt.validateAdmin" -}}
{{- $admin := .Values.admin -}}
{{- $address := $admin.bindAddress -}}
{{- $isLoopback := or (eq $address "127.0.0.1") (eq $address "::1") -}}
{{- $externalService := and $admin.service.enabled (has $admin.service.type (list "LoadBalancer" "NodePort")) -}}
{{- $configMountPath := trimSuffix "/" .Values.config.mountPath -}}
{{- $expectedCertMountPath := include "oxibelt.certMountPath" . -}}
{{- $hasRedisSecretProjections := gt (len .Values.sharedState.redisSecretProjections) 0 -}}
{{- $hasQuicHostKey := ne .Values.quic.hostKeySecretName "" -}}
{{- if or (not (hasPrefix "/" $configMountPath)) (eq $configMountPath "/") -}}
{{- fail "config.mountPath must be an absolute non-root directory" -}}
{{- end -}}
{{- if and (or .Values.tls.enabled (and $admin.enabled $admin.tls.enabled) $hasRedisSecretProjections $hasQuicHostKey) (ne (trimSuffix "/" .Values.tls.mountPath) $expectedCertMountPath) -}}
{{- fail "tls.mountPath must be the cert sibling of config.mountPath" -}}
{{- end -}}
{{- if and $admin.service.enabled (not $admin.enabled) -}}
{{- fail "admin.service.enabled requires admin.enabled=true" -}}
{{- end -}}
{{- if $admin.enabled -}}
{{- if not (has $address (list "127.0.0.1" "0.0.0.0" "::1" "::")) -}}
{{- fail "admin.bindAddress must be 127.0.0.1, 0.0.0.0, ::1, or ::" -}}
{{- end -}}
{{- if or (lt (int $admin.service.port) 1) (gt (int $admin.service.port) 65535) -}}
{{- fail "admin.service.port must be between 1 and 65535" -}}
{{- end -}}
{{- if not $admin.tokenSecretName -}}
{{- fail "admin.tokenSecretName is required when admin.enabled=true" -}}
{{- end -}}
{{- if not (regexMatch "^[A-Za-z0-9._-]+$" $admin.tokenSecretKey) -}}
{{- fail "admin.tokenSecretKey must be a safe Kubernetes Secret key" -}}
{{- end -}}
{{- if not (has $admin.mtls.enforcement (list "required_non_loopback" "required_external" "optional")) -}}
{{- fail "admin.mtls.enforcement must be required_non_loopback, required_external, or optional" -}}
{{- end -}}
{{- if and $admin.service.enabled $isLoopback -}}
{{- fail "admin.service.enabled requires a non-loopback admin.bindAddress" -}}
{{- end -}}
{{- if $admin.insecureDevelopmentMode.enabled -}}
{{- if or $admin.tls.enabled $admin.mtls.enabled -}}
{{- fail "admin.insecureDevelopmentMode.enabled cannot be combined with admin TLS or mTLS" -}}
{{- end -}}
{{- if $externalService -}}
{{- fail "admin.insecureDevelopmentMode.enabled only permits a disabled or ClusterIP Admin Service" -}}
{{- end -}}
{{- else -}}
{{- if and (not $isLoopback) (not $admin.tls.enabled) -}}
{{- fail "admin.tls.enabled is required for a non-loopback admin.bindAddress unless admin.insecureDevelopmentMode.enabled=true" -}}
{{- end -}}
{{- end -}}
{{- if $admin.tls.enabled -}}
{{- if not $admin.tls.secretName -}}
{{- fail "admin.tls.secretName is required when admin TLS is enabled" -}}
{{- end -}}
{{- if or (not (regexMatch "^[A-Za-z0-9._-]+$" $admin.tls.certKey)) (not (regexMatch "^[A-Za-z0-9._-]+$" $admin.tls.privateKeyKey)) -}}
{{- fail "admin TLS certificate keys must be safe Kubernetes Secret keys" -}}
{{- end -}}
{{- if eq (len $admin.tls.serverNames) 0 -}}
{{- fail "admin.tls.serverNames must include at least one DNS name when admin TLS is enabled" -}}
{{- end -}}
{{- $seenServerNames := dict -}}
{{- range $serverName := $admin.tls.serverNames -}}
{{- if not (regexMatch "^([*][.])?[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?([.][A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$" $serverName) -}}
{{- fail "admin.tls.serverNames must contain valid DNS names or leftmost wildcards" -}}
{{- end -}}
{{- $normalizedServerName := lower $serverName -}}
{{- if hasKey $seenServerNames $normalizedServerName -}}
{{- fail "admin.tls.serverNames must not contain duplicate names" -}}
{{- end -}}
{{- $_ := set $seenServerNames $normalizedServerName true -}}
{{- end -}}
{{- end -}}
{{- if $admin.mtls.enabled -}}
{{- if not $admin.tls.enabled -}}
{{- fail "admin.mtls.enabled requires admin.tls.enabled=true" -}}
{{- end -}}
{{- if not $admin.mtls.clientCaSecretName -}}
{{- fail "admin.mtls.clientCaSecretName is required when admin mTLS is enabled" -}}
{{- end -}}
{{- if not (regexMatch "^[A-Za-z0-9._-]+$" $admin.mtls.clientCaSecretKey) -}}
{{- fail "admin.mtls.clientCaSecretKey must be a safe Kubernetes Secret key" -}}
{{- end -}}
{{- if or (lt (int $admin.mtls.verifyDepth) 1) (gt (int $admin.mtls.verifyDepth) 255) -}}
{{- fail "admin.mtls.verifyDepth must be between 1 and 255" -}}
{{- end -}}
{{- end -}}
{{- if and (not $admin.insecureDevelopmentMode.enabled) (eq $admin.mtls.enforcement "required_non_loopback") (not $isLoopback) (not $admin.mtls.enabled) -}}
{{- fail "admin.mtls.enabled is required for a non-loopback admin.bindAddress by the required_non_loopback policy" -}}
{{- end -}}
{{- if and (not $admin.insecureDevelopmentMode.enabled) (eq $admin.mtls.enforcement "required_external") $externalService (not $admin.mtls.enabled) -}}
{{- fail "admin.mtls.enabled is required for NodePort or LoadBalancer Admin Services by the required_external policy" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "oxibelt.validateWorkloadRollout" -}}
{{- if eq .Values.workload.kind "Deployment" -}}
{{- if le (int .Values.workload.deployment.progressDeadlineSeconds) (int .Values.workload.deployment.minReadySeconds) -}}
{{- fail "workload.deployment.progressDeadlineSeconds must be greater than workload.deployment.minReadySeconds" -}}
{{- end -}}
{{- end -}}
{{- end -}}
