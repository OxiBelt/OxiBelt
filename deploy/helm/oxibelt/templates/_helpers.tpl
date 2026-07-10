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
{{- if .Values.config.existingConfigMap -}}
{{- .Values.config.existingConfigMap -}}
{{- else -}}
{{- printf "%s-config-%s" (include "oxibelt.name" . | trunc 42 | trimSuffix "-") (include "oxibelt.generatedConfigDigest" . | trunc 12) -}}
{{- end -}}
{{- end -}}

{{- define "oxibelt.generatedConfigContent" -}}
{{- tpl .Values.config.inline . -}}
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

{{- define "oxibelt.validateAdmin" -}}
{{- $admin := .Values.admin -}}
{{- $address := $admin.bindAddress -}}
{{- $isLoopback := or (eq $address "127.0.0.1") (eq $address "::1") -}}
{{- $externalService := and $admin.service.enabled (has $admin.service.type (list "LoadBalancer" "NodePort")) -}}
{{- $configMountPath := trimSuffix "/" .Values.config.mountPath -}}
{{- $expectedCertMountPath := include "oxibelt.certMountPath" . -}}
{{- if or (not (hasPrefix "/" $configMountPath)) (eq $configMountPath "/") -}}
{{- fail "config.mountPath must be an absolute non-root directory" -}}
{{- end -}}
{{- if and (or .Values.tls.enabled (and $admin.enabled $admin.tls.enabled)) (ne (trimSuffix "/" .Values.tls.mountPath) $expectedCertMountPath) -}}
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
