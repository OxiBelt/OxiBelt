{{- define "oxibelt.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "oxibelt.validateImageRole" -}}
{{- $role := .Values.image.role -}}
{{- if not (has $role (list "dataplane" "dataplane-strict" "standalone")) -}}
{{- fail "image.role must be dataplane, dataplane-strict, or standalone" -}}
{{- end -}}
{{- $repository := .Values.image.repository | default "" -}}
{{- $expectedRepository := include "oxibelt.imageRepositoryForRole" . -}}
{{- $officialRepositories := list "ghcr.io/oxibelt/oxibelt" "ghcr.io/oxibelt/oxibelt-dataplane" "ghcr.io/oxibelt/oxibelt-dataplane-strict" -}}
{{- if and $repository (has $repository $officialRepositories) (ne $repository $expectedRepository) -}}
{{- fail (printf "image.repository %s does not match image.role %s; expected %s" $repository $role $expectedRepository) -}}
{{- end -}}
{{- end -}}

{{- define "oxibelt.imageRepositoryForRole" -}}
{{- if eq .Values.image.role "standalone" -}}
ghcr.io/oxibelt/oxibelt
{{- else if eq .Values.image.role "dataplane-strict" -}}
ghcr.io/oxibelt/oxibelt-dataplane-strict
{{- else -}}
ghcr.io/oxibelt/oxibelt-dataplane
{{- end -}}
{{- end -}}

{{- define "oxibelt.imageExecutable" -}}
{{- if eq .Values.image.role "dataplane-strict" -}}
/usr/local/bin/oxibelt-dataplane-strict
{{- else -}}
/usr/local/bin/oxibelt
{{- end -}}
{{- end -}}

{{- define "oxibelt.image" -}}
{{- include "oxibelt.validateImageRole" . -}}
{{- $repository := .Values.image.repository | default (include "oxibelt.imageRepositoryForRole" .) -}}
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

{{- define "oxibelt.cacheVolumeEnabled" -}}
{{- if eq .Values.cacheVolume.mode "enabled" -}}true
{{- else if eq .Values.cacheVolume.mode "disabled" -}}false
{{- else if eq .Values.image.role "dataplane-strict" -}}false
{{- else -}}true
{{- end -}}
{{- end -}}

{{- define "oxibelt.validateCacheVolume" -}}
{{- if not (has .Values.cacheVolume.mode (list "auto" "enabled" "disabled")) -}}
{{- fail "cacheVolume.mode must be auto, enabled, or disabled" -}}
{{- end -}}
{{- $sizeLimit := .Values.cacheVolume.sizeLimit | default "" -}}
{{- if and (eq .Values.cacheVolume.mode "disabled") $sizeLimit -}}
{{- fail "cacheVolume.sizeLimit requires cacheVolume.mode=auto or enabled" -}}
{{- end -}}
{{- if and (eq .Values.image.role "dataplane-strict") (eq .Values.cacheVolume.mode "enabled") (not $sizeLimit) -}}
{{- fail "cacheVolume.sizeLimit is required when cacheVolume.mode=enabled for image.role=dataplane-strict" -}}
{{- end -}}
{{- end -}}

{{- define "oxibelt.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "oxibelt.name" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "oxibelt.kubernetesApiAccessEnabled" -}}
{{- if or .Values.kubernetesDiscovery.rbac.create .Values.kubernetesDiscovery.serviceAccountToken.enabled -}}true{{- else -}}false{{- end -}}
{{- end -}}

{{- define "oxibelt.validateKubernetesServiceAccount" -}}
{{- if not (kindIs "bool" .Values.serviceAccount.automountServiceAccountToken) -}}
{{- fail "serviceAccount.automountServiceAccountToken must be a boolean" -}}
{{- end -}}
{{- if .Values.serviceAccount.automountServiceAccountToken -}}
{{- fail "serviceAccount.automountServiceAccountToken must remain false; use kubernetesDiscovery.serviceAccountToken.enabled for an explicit projected credential" -}}
{{- end -}}
{{- if not (kindIs "bool" .Values.kubernetesDiscovery.serviceAccountToken.enabled) -}}
{{- fail "kubernetesDiscovery.serviceAccountToken.enabled must be a boolean" -}}
{{- end -}}
{{- if not (kindIs "bool" .Values.kubernetesDiscovery.rbac.create) -}}
{{- fail "kubernetesDiscovery.rbac.create must be a boolean" -}}
{{- end -}}
{{- $expirationSeconds := int .Values.kubernetesDiscovery.serviceAccountToken.expirationSeconds -}}
{{- if or (lt $expirationSeconds 600) (gt $expirationSeconds 3600) -}}
{{- fail "kubernetesDiscovery.serviceAccountToken.expirationSeconds must be between 600 and 3600" -}}
{{- end -}}
{{- $namespaces := .Values.kubernetesDiscovery.rbac.namespaces | default (list) -}}
{{- if not (kindIs "slice" $namespaces) -}}
{{- fail "kubernetesDiscovery.rbac.namespaces must be an array" -}}
{{- end -}}
{{- $seenNamespaces := dict -}}
{{- range $namespace := $namespaces -}}
{{- if not (kindIs "string" $namespace) -}}
{{- fail "kubernetesDiscovery.rbac.namespaces must contain namespace strings" -}}
{{- end -}}
{{- if or (gt (len $namespace) 63) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" $namespace)) -}}
{{- fail "kubernetesDiscovery.rbac.namespaces must contain safe Kubernetes namespace names" -}}
{{- end -}}
{{- if hasKey $seenNamespaces $namespace -}}
{{- fail "kubernetesDiscovery.rbac.namespaces must not contain duplicates" -}}
{{- end -}}
{{- $_ := set $seenNamespaces $namespace true -}}
{{- end -}}
{{- end -}}

{{- define "oxibelt.selectorLabels" -}}
app.kubernetes.io/name: {{ include "oxibelt.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "oxibelt.ciliumSelectorLabels" -}}
k8s:app.kubernetes.io/name: {{ include "oxibelt.name" . }}
k8s:app.kubernetes.io/instance: {{ .Release.Name }}
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
{{- if ne .Values.image.role "dataplane-strict" -}}
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

{{- define "oxibelt.validateLifecycle" -}}
{{- $lifecycle := .Values.lifecycle -}}
{{- if not (kindIs "map" $lifecycle) -}}
{{- fail "lifecycle must be an object" -}}
{{- end -}}
{{- if not (hasKey $lifecycle "terminationGracePeriodSeconds") -}}
{{- fail "lifecycle.terminationGracePeriodSeconds is required" -}}
{{- end -}}
{{- $terminationGracePeriodSeconds := toString $lifecycle.terminationGracePeriodSeconds -}}
{{- if not (regexMatch "^[0-9]{1,9}$" $terminationGracePeriodSeconds) -}}
{{- fail "lifecycle.terminationGracePeriodSeconds must be a non-negative integer no greater than 999999999" -}}
{{- end -}}
{{- $preStop := $lifecycle.preStop -}}
{{- if not (kindIs "map" $preStop) -}}
{{- fail "lifecycle.preStop must be an object" -}}
{{- end -}}
{{- if or (not (hasKey $preStop "enabled")) (not (kindIs "bool" $preStop.enabled)) -}}
{{- fail "lifecycle.preStop.enabled must be a boolean" -}}
{{- end -}}
{{- if not (hasKey $preStop "drainSeconds") -}}
{{- fail "lifecycle.preStop.drainSeconds is required" -}}
{{- end -}}
{{- $drainSeconds := toString $preStop.drainSeconds -}}
{{- if not (regexMatch "^[1-9][0-9]{0,4}$" $drainSeconds) -}}
{{- fail "lifecycle.preStop.drainSeconds must be an integer between 1 and 86400" -}}
{{- end -}}
{{- if gt (int $drainSeconds) 86400 -}}
{{- fail "lifecycle.preStop.drainSeconds must be an integer between 1 and 86400" -}}
{{- end -}}
{{- end -}}

{{- define "oxibelt.validateAutoscaling" -}}
{{- $autoscaling := .Values.autoscaling -}}
{{- if not (kindIs "map" $autoscaling) -}}
{{- fail "autoscaling must be an object" -}}
{{- end -}}
{{- if or (not (hasKey $autoscaling "enabled")) (not (kindIs "bool" $autoscaling.enabled)) -}}
{{- fail "autoscaling.enabled must be a boolean" -}}
{{- end -}}
{{- if not (hasKey $autoscaling "minReplicas") -}}
{{- fail "autoscaling.minReplicas is required" -}}
{{- end -}}
{{- include "oxibelt.validatePositiveInteger" (dict "value" $autoscaling.minReplicas "field" "autoscaling.minReplicas") -}}
{{- if not (hasKey $autoscaling "maxReplicas") -}}
{{- fail "autoscaling.maxReplicas is required" -}}
{{- end -}}
{{- include "oxibelt.validatePositiveInteger" (dict "value" $autoscaling.maxReplicas "field" "autoscaling.maxReplicas") -}}
{{- if lt (int $autoscaling.maxReplicas) (int $autoscaling.minReplicas) -}}
{{- if and (kindIs "map" .Values.operationalProfile) (eq .Values.operationalProfile.name "edge-secure-medium") -}}
{{- fail "operationalProfile edge-secure-medium requires autoscaling.maxReplicas to be at least autoscaling.minReplicas" -}}
{{- else -}}
{{- fail "autoscaling.maxReplicas must be at least autoscaling.minReplicas" -}}
{{- end -}}
{{- end -}}
{{- if not (hasKey $autoscaling "targetCPUUtilizationPercentage") -}}
{{- fail "autoscaling.targetCPUUtilizationPercentage is required" -}}
{{- end -}}
{{- include "oxibelt.validatePositiveInteger" (dict "value" $autoscaling.targetCPUUtilizationPercentage "field" "autoscaling.targetCPUUtilizationPercentage") -}}
{{- if gt (int $autoscaling.targetCPUUtilizationPercentage) 100 -}}
{{- fail "autoscaling.targetCPUUtilizationPercentage must be between 1 and 100" -}}
{{- end -}}
{{- $activeRequests := $autoscaling.activeRequests -}}
{{- if not (kindIs "map" $activeRequests) -}}
{{- fail "autoscaling.activeRequests must be an object" -}}
{{- end -}}
{{- if or (not (hasKey $activeRequests "enabled")) (not (kindIs "bool" $activeRequests.enabled)) -}}
{{- fail "autoscaling.activeRequests.enabled must be a boolean" -}}
{{- end -}}
{{- if not (hasKey $activeRequests "targetAverageValue") -}}
{{- fail "autoscaling.activeRequests.targetAverageValue is required" -}}
{{- end -}}
{{- include "oxibelt.validatePositiveInteger" (dict "value" $activeRequests.targetAverageValue "field" "autoscaling.activeRequests.targetAverageValue") -}}
{{- $scaleDown := $autoscaling.scaleDown -}}
{{- if not (kindIs "map" $scaleDown) -}}
{{- fail "autoscaling.scaleDown must be an object" -}}
{{- end -}}
{{- if not (hasKey $scaleDown "stabilizationWindowSeconds") -}}
{{- fail "autoscaling.scaleDown.stabilizationWindowSeconds is required" -}}
{{- end -}}
{{- $stabilizationWindowSeconds := toString $scaleDown.stabilizationWindowSeconds -}}
{{- if or (not (regexMatch "^[0-9]{1,4}$" $stabilizationWindowSeconds)) (gt (int $stabilizationWindowSeconds) 3600) -}}
{{- fail "autoscaling.scaleDown.stabilizationWindowSeconds must be an integer between 0 and 3600" -}}
{{- end -}}
{{- if not (hasKey $scaleDown "periodSeconds") -}}
{{- fail "autoscaling.scaleDown.periodSeconds is required" -}}
{{- end -}}
{{- $periodSeconds := toString $scaleDown.periodSeconds -}}
{{- if or (not (regexMatch "^[1-9][0-9]{0,3}$" $periodSeconds)) (gt (int $periodSeconds) 1800) -}}
{{- fail "autoscaling.scaleDown.periodSeconds must be an integer between 1 and 1800" -}}
{{- end -}}
{{- if and $autoscaling.enabled (ne .Values.workload.kind "Deployment") -}}
{{- fail "autoscaling.enabled=true requires workload.kind=Deployment" -}}
{{- end -}}
{{- if $activeRequests.enabled -}}
{{- if not $autoscaling.enabled -}}
{{- fail "autoscaling.activeRequests.enabled=true requires autoscaling.enabled=true" -}}
{{- end -}}
{{- include "oxibelt.validateLifecycle" . -}}
{{- $metrics := .Values.metrics -}}
{{- if not (kindIs "map" $metrics) -}}
{{- fail "metrics must be an object when autoscaling.activeRequests.enabled=true" -}}
{{- end -}}
{{- if or (not (hasKey $metrics "enabled")) (not (kindIs "bool" $metrics.enabled)) -}}
{{- fail "metrics.enabled must be a boolean when autoscaling.activeRequests.enabled=true" -}}
{{- end -}}
{{- if not $metrics.enabled -}}
{{- fail "autoscaling.activeRequests.enabled=true requires metrics.enabled=true" -}}
{{- end -}}
{{- $operationalProfile := .Values.operationalProfile -}}
{{- if not (kindIs "map" $operationalProfile) -}}
{{- fail "operationalProfile must be an object when autoscaling.activeRequests.enabled=true" -}}
{{- end -}}
{{- if ne $operationalProfile.name "edge-secure-medium" -}}
{{- fail "autoscaling.activeRequests.enabled=true requires operationalProfile.name=edge-secure-medium so the active-work gauge is sampled" -}}
{{- end -}}
{{- if not .Values.lifecycle.preStop.enabled -}}
{{- fail "autoscaling.activeRequests.enabled=true requires lifecycle.preStop.enabled=true" -}}
{{- end -}}
{{- if le (int .Values.lifecycle.terminationGracePeriodSeconds) 0 -}}
{{- fail "autoscaling.activeRequests.enabled=true requires lifecycle.terminationGracePeriodSeconds greater than zero" -}}
{{- end -}}
{{- if lt (int $stabilizationWindowSeconds) (int .Values.lifecycle.preStop.drainSeconds) -}}
{{- fail "autoscaling.scaleDown.stabilizationWindowSeconds must be at least lifecycle.preStop.drainSeconds when autoscaling.activeRequests.enabled=true" -}}
{{- end -}}
{{- if lt (int $periodSeconds) (int .Values.lifecycle.terminationGracePeriodSeconds) -}}
{{- fail "autoscaling.scaleDown.periodSeconds must be at least lifecycle.terminationGracePeriodSeconds when autoscaling.activeRequests.enabled=true" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "oxibelt.validatePositiveInteger" -}}
{{- $value := toString .value -}}
{{- $field := .field -}}
{{- if not (regexMatch "^[1-9][0-9]{0,8}$" $value) -}}
{{- fail (printf "%s must be a positive integer no greater than 999999999" $field) -}}
{{- end -}}
{{- end -}}

{{- define "oxibelt.validatePodDistribution" -}}
{{- $distribution := .Values.podDistribution -}}
{{- if not (kindIs "map" $distribution) -}}
{{- fail "podDistribution must be an object" -}}
{{- end -}}
{{- if or (not (hasKey $distribution "enabled")) (not (kindIs "bool" $distribution.enabled)) -}}
{{- fail "podDistribution.enabled must be a boolean" -}}
{{- end -}}
{{- $nodeSpread := $distribution.nodeSpread -}}
{{- if not (kindIs "map" $nodeSpread) -}}
{{- fail "podDistribution.nodeSpread must be an object" -}}
{{- end -}}
{{- if or (not (hasKey $nodeSpread "enabled")) (not (kindIs "bool" $nodeSpread.enabled)) -}}
{{- fail "podDistribution.nodeSpread.enabled must be a boolean" -}}
{{- end -}}
{{- include "oxibelt.validatePositiveInteger" (dict "value" $nodeSpread.maxSkew "field" "podDistribution.nodeSpread.maxSkew") -}}
{{- include "oxibelt.validatePositiveInteger" (dict "value" $nodeSpread.minDomains "field" "podDistribution.nodeSpread.minDomains") -}}
{{- if not (has $nodeSpread.whenUnsatisfiable (list "DoNotSchedule" "ScheduleAnyway")) -}}
{{- fail "podDistribution.nodeSpread.whenUnsatisfiable must be DoNotSchedule or ScheduleAnyway" -}}
{{- end -}}
{{- if and $distribution.enabled $nodeSpread.enabled (ne $nodeSpread.whenUnsatisfiable "DoNotSchedule") -}}
{{- fail "podDistribution.nodeSpread.minDomains requires podDistribution.nodeSpread.whenUnsatisfiable=DoNotSchedule" -}}
{{- end -}}
{{- if and $distribution.enabled $nodeSpread.enabled (not (semverCompare ">=1.30.0-0" (trimPrefix "v" .Capabilities.KubeVersion.Version))) -}}
{{- fail "podDistribution.nodeSpread.minDomains requires Kubernetes 1.30 or later" -}}
{{- end -}}
{{- $zoneSpread := $distribution.zoneSpread -}}
{{- if not (kindIs "map" $zoneSpread) -}}
{{- fail "podDistribution.zoneSpread must be an object" -}}
{{- end -}}
{{- if or (not (hasKey $zoneSpread "enabled")) (not (kindIs "bool" $zoneSpread.enabled)) -}}
{{- fail "podDistribution.zoneSpread.enabled must be a boolean" -}}
{{- end -}}
{{- include "oxibelt.validatePositiveInteger" (dict "value" $zoneSpread.maxSkew "field" "podDistribution.zoneSpread.maxSkew") -}}
{{- if not (has $zoneSpread.whenUnsatisfiable (list "DoNotSchedule" "ScheduleAnyway")) -}}
{{- fail "podDistribution.zoneSpread.whenUnsatisfiable must be DoNotSchedule or ScheduleAnyway" -}}
{{- end -}}
{{- $podAntiAffinity := $distribution.podAntiAffinity -}}
{{- if not (kindIs "map" $podAntiAffinity) -}}
{{- fail "podDistribution.podAntiAffinity must be an object" -}}
{{- end -}}
{{- if or (not (hasKey $podAntiAffinity "enabled")) (not (kindIs "bool" $podAntiAffinity.enabled)) -}}
{{- fail "podDistribution.podAntiAffinity.enabled must be a boolean" -}}
{{- end -}}
{{- $weight := toString $podAntiAffinity.weight -}}
{{- if or (not (regexMatch "^[1-9][0-9]{0,2}$" $weight)) (gt (int $weight) 100) -}}
{{- fail "podDistribution.podAntiAffinity.weight must be an integer between 1 and 100" -}}
{{- end -}}
{{- $affinity := .Values.affinity -}}
{{- if not (kindIs "map" $affinity) -}}
{{- fail "affinity must be an object" -}}
{{- end -}}
{{- if and $distribution.enabled $podAntiAffinity.enabled (hasKey $affinity "podAntiAffinity") -}}
{{- fail "podDistribution.podAntiAffinity.enabled cannot be combined with affinity.podAntiAffinity" -}}
{{- end -}}
{{- end -}}

{{- define "oxibelt.validatePodDisruptionBudgetValue" -}}
{{- $value := toString .value -}}
{{- $field := .field -}}
{{- if not (or (regexMatch "^[0-9]{1,9}$" $value) (regexMatch "^(0|[1-9][0-9]?|100)%$" $value)) -}}
{{- fail (printf "%s must be a non-negative integer no greater than 999999999 or percentage" $field) -}}
{{- end -}}
{{- end -}}

{{- define "oxibelt.podDisruptionBudgetValue" -}}
{{- $value := toString . -}}
{{- if hasSuffix "%" $value -}}
{{- $value | quote -}}
{{- else -}}
{{- int $value -}}
{{- end -}}
{{- end -}}

{{- define "oxibelt.validatePodDisruptionBudget" -}}
{{- $pdb := .Values.podDisruptionBudget -}}
{{- if not (kindIs "map" $pdb) -}}
{{- fail "podDisruptionBudget must be an object" -}}
{{- end -}}
{{- if or (not (hasKey $pdb "enabled")) (not (kindIs "bool" $pdb.enabled)) -}}
{{- fail "podDisruptionBudget.enabled must be a boolean" -}}
{{- end -}}
{{- $minAvailable := $pdb.minAvailable -}}
{{- $maxUnavailable := $pdb.maxUnavailable -}}
{{- $hasMinAvailable := and (hasKey $pdb "minAvailable") (not (kindIs "invalid" $minAvailable)) -}}
{{- $hasMaxUnavailable := and (hasKey $pdb "maxUnavailable") (not (kindIs "invalid" $maxUnavailable)) -}}
{{- if $hasMinAvailable -}}
{{- include "oxibelt.validatePodDisruptionBudgetValue" (dict "value" $minAvailable "field" "podDisruptionBudget.minAvailable") -}}
{{- end -}}
{{- if $hasMaxUnavailable -}}
{{- include "oxibelt.validatePodDisruptionBudgetValue" (dict "value" $maxUnavailable "field" "podDisruptionBudget.maxUnavailable") -}}
{{- end -}}
{{- if and $pdb.enabled (eq $hasMinAvailable $hasMaxUnavailable) -}}
{{- fail "podDisruptionBudget requires exactly one of minAvailable or maxUnavailable when enabled" -}}
{{- end -}}
{{- $unhealthyPodEvictionPolicy := $pdb.unhealthyPodEvictionPolicy -}}
{{- if or (not (kindIs "string" $unhealthyPodEvictionPolicy)) (not (has $unhealthyPodEvictionPolicy (list "" "IfHealthyBudget" "AlwaysAllow"))) -}}
{{- fail "podDisruptionBudget.unhealthyPodEvictionPolicy must be empty, IfHealthyBudget, or AlwaysAllow" -}}
{{- end -}}
{{- if and $unhealthyPodEvictionPolicy (not (semverCompare ">=1.31.0-0" (trimPrefix "v" .Capabilities.KubeVersion.Version))) -}}
{{- fail "podDisruptionBudget.unhealthyPodEvictionPolicy requires Kubernetes 1.31 or later" -}}
{{- end -}}
{{- end -}}

{{- define "oxibelt.deploymentAffinity" -}}
{{- $affinity := deepCopy .Values.affinity -}}
{{- if and .Values.podDistribution.enabled .Values.podDistribution.podAntiAffinity.enabled -}}
{{- $selectorLabels := include "oxibelt.selectorLabels" . | fromYaml -}}
{{- $term := dict "labelSelector" (dict "matchLabels" $selectorLabels) "topologyKey" "kubernetes.io/hostname" -}}
{{- $preference := dict "weight" (int .Values.podDistribution.podAntiAffinity.weight) "podAffinityTerm" $term -}}
{{- $_ := set $affinity "podAntiAffinity" (dict "preferredDuringSchedulingIgnoredDuringExecution" (list $preference)) -}}
{{- end -}}
{{- toYaml $affinity -}}
{{- end -}}

{{- define "oxibelt.validateOperationalProfile" -}}
{{- include "oxibelt.validateAutoscaling" . -}}
{{- include "oxibelt.validatePublicTls" . -}}
{{- include "oxibelt.validateQuicHostKey" . -}}
{{- include "oxibelt.validateLifecycle" . -}}
{{- include "oxibelt.validatePodDistribution" . -}}
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
{{- if not (semverCompare ">=1.31.0-0" (trimPrefix "v" .Capabilities.KubeVersion.Version)) -}}
{{- fail "operationalProfile edge-secure-medium requires Kubernetes 1.31 or later" -}}
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
{{- if not .Values.lifecycle.preStop.enabled -}}
{{- fail "operationalProfile edge-secure-medium requires lifecycle.preStop.enabled=true" -}}
{{- end -}}
{{- if lt (int .Values.lifecycle.preStop.drainSeconds) 300 -}}
{{- fail "operationalProfile edge-secure-medium requires lifecycle.preStop.drainSeconds of at least 300" -}}
{{- end -}}
{{- $minimumTerminationGracePeriodSeconds := add (int .Values.lifecycle.preStop.drainSeconds) 60 -}}
{{- if lt (int .Values.lifecycle.terminationGracePeriodSeconds) $minimumTerminationGracePeriodSeconds -}}
{{- fail (printf "operationalProfile edge-secure-medium requires lifecycle.terminationGracePeriodSeconds of at least %d" $minimumTerminationGracePeriodSeconds) -}}
{{- end -}}
{{- if eq .Values.workload.kind "Deployment" -}}
{{- if lt (int .Values.replicaCount) 3 -}}
{{- fail "operationalProfile edge-secure-medium requires replicaCount of at least 3 for a Deployment" -}}
{{- end -}}
{{- if or (ne (toString .Values.workload.deployment.maxUnavailable) "0") (ne (toString .Values.workload.deployment.maxSurge) "1") -}}
{{- fail "operationalProfile edge-secure-medium requires Deployment maxUnavailable=0 and maxSurge=1" -}}
{{- end -}}
{{- if lt (int .Values.autoscaling.minReplicas) 3 -}}
{{- fail "operationalProfile edge-secure-medium requires autoscaling.minReplicas of at least 3" -}}
{{- end -}}
{{- if lt (int .Values.autoscaling.maxReplicas) (int .Values.autoscaling.minReplicas) -}}
{{- fail "operationalProfile edge-secure-medium requires autoscaling.maxReplicas to be at least autoscaling.minReplicas" -}}
{{- end -}}
{{- if not .Values.podDistribution.enabled -}}
{{- fail "operationalProfile edge-secure-medium requires podDistribution.enabled=true for a Deployment" -}}
{{- end -}}
{{- if or (not .Values.podDistribution.nodeSpread.enabled) (ne (int .Values.podDistribution.nodeSpread.maxSkew) 1) (lt (int .Values.podDistribution.nodeSpread.minDomains) 2) (ne .Values.podDistribution.nodeSpread.whenUnsatisfiable "DoNotSchedule") -}}
{{- fail "operationalProfile edge-secure-medium requires strict hostname podDistribution.nodeSpread" -}}
{{- end -}}
{{- if or (not .Values.podDistribution.zoneSpread.enabled) (ne (int .Values.podDistribution.zoneSpread.maxSkew) 1) (ne .Values.podDistribution.zoneSpread.whenUnsatisfiable "ScheduleAnyway") -}}
{{- fail "operationalProfile edge-secure-medium requires soft zone podDistribution.zoneSpread" -}}
{{- end -}}
{{- if or (not .Values.podDistribution.podAntiAffinity.enabled) (ne (int .Values.podDistribution.podAntiAffinity.weight) 100) -}}
{{- fail "operationalProfile edge-secure-medium requires preferred hostname podDistribution.podAntiAffinity" -}}
{{- end -}}
{{- if not .Values.podDisruptionBudget.enabled -}}
{{- fail "operationalProfile edge-secure-medium requires podDisruptionBudget.enabled=true for a Deployment" -}}
{{- end -}}
{{- if or (not (kindIs "invalid" .Values.podDisruptionBudget.minAvailable)) (ne (toString .Values.podDisruptionBudget.maxUnavailable) "1") -}}
{{- fail "operationalProfile edge-secure-medium requires podDisruptionBudget.maxUnavailable=1 with minAvailable unset" -}}
{{- end -}}
{{- if ne .Values.podDisruptionBudget.unhealthyPodEvictionPolicy "AlwaysAllow" -}}
{{- fail "operationalProfile edge-secure-medium requires podDisruptionBudget.unhealthyPodEvictionPolicy=AlwaysAllow" -}}
{{- end -}}
{{- else if eq .Values.workload.kind "DaemonSet" -}}
{{- if or (ne (int .Values.workload.daemonSet.maxUnavailable) 0) (lt (int .Values.workload.daemonSet.maxSurge) 1) -}}
{{- fail "operationalProfile edge-secure-medium requires DaemonSet maxUnavailable=0 with maxSurge of at least 1" -}}
{{- end -}}
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
{{- include "oxibelt.validateImageRole" . -}}
{{- include "oxibelt.validateCacheVolume" . -}}
{{- $admin := .Values.admin -}}
{{- $address := $admin.bindAddress -}}
{{- $isLoopback := or (eq $address "127.0.0.1") (eq $address "::1") -}}
{{- $externalService := and $admin.service.enabled (has $admin.service.type (list "LoadBalancer" "NodePort")) -}}
{{- $configMountPath := trimSuffix "/" .Values.config.mountPath -}}
{{- $expectedCertMountPath := include "oxibelt.certMountPath" . -}}
{{- $hasRedisSecretProjections := gt (len .Values.sharedState.redisSecretProjections) 0 -}}
{{- $hasQuicHostKey := ne .Values.quic.hostKeySecretName "" -}}
{{- if eq .Values.image.role "dataplane-strict" -}}
{{- if or $admin.enabled $admin.service.enabled $admin.insecureDevelopmentMode.enabled $admin.tls.enabled $admin.mtls.enabled -}}
{{- fail "image.role=dataplane-strict does not support Admin enablement, service exposure, TLS, mTLS, or insecure development mode" -}}
{{- end -}}
{{- if or (ne $admin.bindAddress "127.0.0.1") (ne (int $admin.service.port) 9092) (ne $admin.service.type "ClusterIP") $admin.service.annotations $admin.tokenSecretName (ne $admin.tokenSecretKey "token") $admin.tls.secretName (ne $admin.tls.certKey "tls.crt") (ne $admin.tls.privateKeyKey "tls.key") $admin.tls.serverNames (ne $admin.mtls.enforcement "required_non_loopback") $admin.mtls.clientCaSecretName (ne $admin.mtls.clientCaSecretKey "ca.crt") (ne (int $admin.mtls.verifyDepth) 4) -}}
{{- fail "image.role=dataplane-strict rejects Admin listener settings and Admin secret or certificate projections" -}}
{{- end -}}
{{- if .Values.networkPolicy.ingress.admin.from -}}
{{- fail "image.role=dataplane-strict rejects networkPolicy.ingress.admin.from" -}}
{{- end -}}
{{- $inlineConfig := tpl .Values.config.inline . -}}
{{- if regexMatch "(?m)^[[:space:]]*\\[{1,2}admin([.]|\\])" $inlineConfig -}}
{{- fail "image.role=dataplane-strict rejects Admin sections in config.inline; externally managed ConfigMaps are validated by the strict executable" -}}
{{- end -}}
{{- include "oxibelt.validateStrictPodSecurity" . -}}
{{- end -}}
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

{{- define "oxibelt.validateStrictPodSecurity" -}}
{{- $pod := .Values.podSecurityContext -}}
{{- $container := .Values.securityContext -}}
{{- if or (not $pod.runAsNonRoot) (ne (int $pod.runAsUser) 10001) (ne (int $pod.runAsGroup) 10001) -}}
{{- fail "image.role=dataplane-strict requires podSecurityContext.runAsNonRoot=true and runAsUser/runAsGroup=10001" -}}
{{- end -}}
{{- if or $container.allowPrivilegeEscalation (not $container.readOnlyRootFilesystem) -}}
{{- fail "image.role=dataplane-strict requires securityContext.allowPrivilegeEscalation=false and readOnlyRootFilesystem=true" -}}
{{- end -}}
{{- if not (has "ALL" $container.capabilities.drop) -}}
{{- fail "image.role=dataplane-strict requires securityContext.capabilities.drop to contain ALL" -}}
{{- end -}}
{{- if $container.capabilities.add -}}
{{- fail "image.role=dataplane-strict rejects securityContext.capabilities.add" -}}
{{- end -}}
{{- $seccomp := $pod.seccompProfile -}}
{{- if not (has $seccomp.type (list "RuntimeDefault" "Localhost")) -}}
{{- fail "image.role=dataplane-strict requires a RuntimeDefault or Localhost seccomp profile" -}}
{{- end -}}
{{- if and (eq $seccomp.type "Localhost") (not $seccomp.localhostProfile) -}}
{{- fail "podSecurityContext.seccompProfile.localhostProfile is required when type=Localhost" -}}
{{- end -}}
{{- end -}}

{{- define "oxibelt.validateWorkloadRollout" -}}
{{- if not (has .Values.workload.kind (list "Deployment" "DaemonSet")) -}}
{{- fail "workload.kind must be Deployment or DaemonSet" -}}
{{- end -}}
{{- if eq .Values.workload.kind "Deployment" -}}
{{- if le (int .Values.workload.deployment.progressDeadlineSeconds) (int .Values.workload.deployment.minReadySeconds) -}}
{{- fail "workload.deployment.progressDeadlineSeconds must be greater than workload.deployment.minReadySeconds" -}}
{{- end -}}
{{- else -}}
{{- $maxUnavailable := toString .Values.workload.daemonSet.maxUnavailable -}}
{{- $maxSurge := toString .Values.workload.daemonSet.maxSurge -}}
{{- if not (regexMatch "^[0-9]{1,9}$" $maxUnavailable) -}}
{{- fail "workload.daemonSet.maxUnavailable must be a non-negative integer no greater than 999999999" -}}
{{- end -}}
{{- if not (regexMatch "^[0-9]{1,9}$" $maxSurge) -}}
{{- fail "workload.daemonSet.maxSurge must be a non-negative integer no greater than 999999999" -}}
{{- end -}}
{{- if and (eq (int $maxUnavailable) 0) (eq (int $maxSurge) 0) -}}
{{- fail "workload.daemonSet.maxUnavailable and workload.daemonSet.maxSurge cannot both be zero" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "oxibelt.validateNetworkPolicyLabelSelector" -}}
{{- $selector := .selector -}}
{{- $field := .field -}}
{{- if not (kindIs "map" $selector) -}}
{{- fail (printf "%s must be an object" $field) -}}
{{- end -}}
{{- if not (hasKey $selector "matchLabels") -}}
{{- fail (printf "%s.matchLabels is required" $field) -}}
{{- end -}}
{{- $labels := $selector.matchLabels -}}
{{- if or (not (kindIs "map" $labels)) (eq (len $labels) 0) -}}
{{- fail (printf "%s.matchLabels must contain at least one label" $field) -}}
{{- end -}}
{{- range $key, $value := $labels -}}
{{- if or (not (kindIs "string" $key)) (not $key) (not (kindIs "string" $value)) (not $value) -}}
{{- fail (printf "%s.matchLabels must contain nonempty string keys and values" $field) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "oxibelt.validateNetworkPolicyPeer" -}}
{{- $peer := .peer -}}
{{- $field := .field -}}
{{- if not (kindIs "map" $peer) -}}
{{- fail (printf "%s must be an object" $field) -}}
{{- end -}}
{{- $hasIpBlock := hasKey $peer "ipBlock" -}}
{{- $hasNamespaceSelector := hasKey $peer "namespaceSelector" -}}
{{- $hasPodSelector := hasKey $peer "podSelector" -}}
{{- if and $hasIpBlock (or $hasNamespaceSelector $hasPodSelector) -}}
{{- fail (printf "%s must use either ipBlock or namespaceSelector/podSelector" $field) -}}
{{- end -}}
{{- if and (not $hasIpBlock) (not $hasNamespaceSelector) (not $hasPodSelector) -}}
{{- fail (printf "%s must declare an ipBlock, namespaceSelector, or podSelector" $field) -}}
{{- end -}}
{{- if $hasIpBlock -}}
{{- $ipBlock := $peer.ipBlock -}}
{{- if not (kindIs "map" $ipBlock) -}}
{{- fail (printf "%s.ipBlock must be an object" $field) -}}
{{- end -}}
{{- if or (not (hasKey $ipBlock "cidr")) (not (kindIs "string" $ipBlock.cidr)) (not $ipBlock.cidr) -}}
{{- fail (printf "%s.ipBlock.cidr is required" $field) -}}
{{- end -}}
{{- if hasKey $ipBlock "except" -}}
{{- if not (kindIs "slice" $ipBlock.except) -}}
{{- fail (printf "%s.ipBlock.except must be an array" $field) -}}
{{- end -}}
{{- range $exceptIndex, $except := $ipBlock.except -}}
{{- if or (not (kindIs "string" $except)) (not $except) -}}
{{- fail (printf "%s.ipBlock.except[%d] must be a nonempty CIDR" $field $exceptIndex) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- else -}}
{{- if $hasNamespaceSelector -}}
{{- include "oxibelt.validateNetworkPolicyLabelSelector" (dict "selector" $peer.namespaceSelector "field" (printf "%s.namespaceSelector" $field)) -}}
{{- end -}}
{{- if $hasPodSelector -}}
{{- include "oxibelt.validateNetworkPolicyLabelSelector" (dict "selector" $peer.podSelector "field" (printf "%s.podSelector" $field)) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "oxibelt.validateNetworkPolicyPeers" -}}
{{- $peers := .peers -}}
{{- $field := .field -}}
{{- $required := .required -}}
{{- if not (kindIs "slice" $peers) -}}
{{- fail (printf "%s must be an array" $field) -}}
{{- end -}}
{{- if and $required (eq (len $peers) 0) -}}
{{- fail (printf "%s must contain at least one peer" $field) -}}
{{- end -}}
{{- range $peerIndex, $peer := $peers -}}
{{- include "oxibelt.validateNetworkPolicyPeer" (dict "peer" $peer "field" (printf "%s[%d]" $field $peerIndex)) -}}
{{- end -}}
{{- end -}}

{{- define "oxibelt.validateNetworkPolicyPorts" -}}
{{- $ports := .ports -}}
{{- $field := .field -}}
{{- $allowEndPort := .allowEndPort -}}
{{- if not (kindIs "slice" $ports) -}}
{{- fail (printf "%s must be an array" $field) -}}
{{- end -}}
{{- if eq (len $ports) 0 -}}
{{- fail (printf "%s must contain at least one port" $field) -}}
{{- end -}}
{{- range $portIndex, $port := $ports -}}
{{- $portField := printf "%s[%d]" $field $portIndex -}}
{{- if not (kindIs "map" $port) -}}
{{- fail (printf "%s must be an object" $portField) -}}
{{- end -}}
{{- if not (hasKey $port "port") -}}
{{- fail (printf "%s.port is required" $portField) -}}
{{- end -}}
{{- $portText := toString $port.port -}}
{{- if not (regexMatch "^[0-9]+$" $portText) -}}
{{- fail (printf "%s.port must be a numeric port" $portField) -}}
{{- end -}}
{{- $portNumber := int $port.port -}}
{{- if or (lt $portNumber 1) (gt $portNumber 65535) -}}
{{- fail (printf "%s.port must be between 1 and 65535" $portField) -}}
{{- end -}}
{{- if or (not (hasKey $port "protocol")) (not (kindIs "string" $port.protocol)) (not (has $port.protocol (list "TCP" "UDP"))) -}}
{{- fail (printf "%s.protocol must be TCP or UDP" $portField) -}}
{{- end -}}
{{- if hasKey $port "endPort" -}}
{{- if not $allowEndPort -}}
{{- fail (printf "%s.endPort is not supported for Cilium FQDN destinations" $portField) -}}
{{- end -}}
{{- $endPortText := toString $port.endPort -}}
{{- if not (regexMatch "^[0-9]+$" $endPortText) -}}
{{- fail (printf "%s.endPort must be a numeric port" $portField) -}}
{{- end -}}
{{- $endPortNumber := int $port.endPort -}}
{{- if or (lt $endPortNumber 1) (gt $endPortNumber 65535) (lt $endPortNumber $portNumber) -}}
{{- fail (printf "%s.endPort must be between port and 65535" $portField) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "oxibelt.validateNetworkPolicyDestination" -}}
{{- $destination := .destination -}}
{{- $field := .field -}}
{{- if not (kindIs "map" $destination) -}}
{{- fail (printf "%s must be an object" $field) -}}
{{- end -}}
{{- if or (not (hasKey $destination "name")) (not (kindIs "string" $destination.name)) (not (regexMatch "^[a-z0-9]([a-z0-9-]*[a-z0-9])?$" $destination.name)) (gt (len $destination.name) 63) -}}
{{- fail (printf "%s.name must be a safe lower-case DNS label up to 63 characters" $field) -}}
{{- end -}}
{{- if or (not (hasKey $destination "category")) (not (kindIs "string" $destination.category)) (not (has $destination.category (list "upstream" "shared-state" "revocation" "kubernetes-api" "external-dependency"))) -}}
{{- fail (printf "%s.category must be upstream, shared-state, revocation, kubernetes-api, or external-dependency" $field) -}}
{{- end -}}
{{- if not (hasKey $destination "to") -}}
{{- fail (printf "%s.to is required" $field) -}}
{{- end -}}
{{- include "oxibelt.validateNetworkPolicyPeers" (dict "peers" $destination.to "field" (printf "%s.to" $field) "required" true) -}}
{{- if not (hasKey $destination "ports") -}}
{{- fail (printf "%s.ports is required" $field) -}}
{{- end -}}
{{- include "oxibelt.validateNetworkPolicyPorts" (dict "ports" $destination.ports "field" (printf "%s.ports" $field) "allowEndPort" true) -}}
{{- end -}}

{{- define "oxibelt.validateCiliumFqdnDestination" -}}
{{- $destination := .destination -}}
{{- $field := .field -}}
{{- if not (kindIs "map" $destination) -}}
{{- fail (printf "%s must be an object" $field) -}}
{{- end -}}
{{- if or (not (hasKey $destination "name")) (not (kindIs "string" $destination.name)) (not (regexMatch "^[a-z0-9]([a-z0-9-]*[a-z0-9])?$" $destination.name)) (gt (len $destination.name) 63) -}}
{{- fail (printf "%s.name must be a safe lower-case DNS label up to 63 characters" $field) -}}
{{- end -}}
{{- if or (not (hasKey $destination "category")) (not (kindIs "string" $destination.category)) (not (has $destination.category (list "upstream" "shared-state" "revocation" "kubernetes-api" "external-dependency"))) -}}
{{- fail (printf "%s.category must be upstream, shared-state, revocation, kubernetes-api, or external-dependency" $field) -}}
{{- end -}}
{{- if or (not (hasKey $destination "matchNames")) (not (kindIs "slice" $destination.matchNames)) (eq (len $destination.matchNames) 0) -}}
{{- fail (printf "%s.matchNames must contain at least one exact DNS name" $field) -}}
{{- end -}}
{{- $seenNames := dict -}}
{{- range $nameIndex, $matchName := $destination.matchNames -}}
{{- if or (not (kindIs "string" $matchName)) (gt (len $matchName) 253) (not (regexMatch "^[a-z0-9]([a-z0-9-]*[a-z0-9])?([.][a-z0-9]([a-z0-9-]*[a-z0-9])?)+$" $matchName)) (ne $matchName (lower $matchName)) -}}
{{- fail (printf "%s.matchNames[%d] must be a lower-case exact DNS name without wildcards" $field $nameIndex) -}}
{{- end -}}
{{- if hasKey $seenNames $matchName -}}
{{- fail (printf "%s.matchNames must not contain duplicate DNS names" $field) -}}
{{- end -}}
{{- $_ := set $seenNames $matchName true -}}
{{- end -}}
{{- if not (hasKey $destination "ports") -}}
{{- fail (printf "%s.ports is required" $field) -}}
{{- end -}}
{{- include "oxibelt.validateNetworkPolicyPorts" (dict "ports" $destination.ports "field" (printf "%s.ports" $field) "allowEndPort" false) -}}
{{- end -}}

{{- define "oxibelt.networkPolicyName" -}}
{{- $suffix := .suffix -}}
{{- $baseLength := int (sub 63 (add (len $suffix) 1)) -}}
{{- $base := include "oxibelt.name" .root | trunc $baseLength | trimSuffix "-" -}}
{{- printf "%s-%s" $base $suffix -}}
{{- end -}}

{{- define "oxibelt.validateAdditionalServicePorts" -}}
{{- $ports := .Values.service.additionalPorts | default (list) -}}
{{- if not (kindIs "slice" $ports) -}}
{{- fail "service.additionalPorts must be an array" -}}
{{- end -}}
{{- if gt (len $ports) 32 -}}
{{- fail "service.additionalPorts must contain at most 32 entries" -}}
{{- end -}}
{{- $names := dict -}}
{{- $serviceSockets := dict -}}
{{- $containerSockets := dict -}}
{{- range $name := list "metrics" "health" -}}
{{- $_ := set $names $name true -}}
{{- end -}}
{{- if .Values.service.ports.http.enabled -}}
{{- $_ := set $names "http" true -}}
{{- $_ := set $serviceSockets (printf "TCP/%d" (int .Values.service.ports.http.port)) true -}}
{{- $_ := set $containerSockets (printf "TCP/%d" (int .Values.service.ports.http.targetPort)) true -}}
{{- end -}}
{{- if .Values.service.ports.https.enabled -}}
{{- $_ := set $names "https" true -}}
{{- $_ := set $serviceSockets (printf "TCP/%d" (int .Values.service.ports.https.port)) true -}}
{{- $_ := set $containerSockets (printf "TCP/%d" (int .Values.service.ports.https.targetPort)) true -}}
{{- end -}}
{{- if .Values.service.ports.http3.enabled -}}
{{- $_ := set $names "http3" true -}}
{{- $_ := set $serviceSockets (printf "UDP/%d" (int .Values.service.ports.http3.port)) true -}}
{{- $_ := set $containerSockets (printf "UDP/%d" (int .Values.service.ports.http3.targetPort)) true -}}
{{- end -}}
{{- $_ := set $containerSockets (printf "TCP/%d" (int .Values.health.port)) true -}}
{{- if .Values.metrics.enabled -}}
{{- $_ := set $containerSockets (printf "TCP/%d" (int .Values.metrics.service.port)) true -}}
{{- end -}}
{{- if .Values.admin.enabled -}}
{{- $_ := set $names "admin" true -}}
{{- $_ := set $containerSockets (printf "TCP/%d" (int .Values.admin.service.port)) true -}}
{{- end -}}
{{- range $port := $ports -}}
{{- if or (not $port.name) (gt (len $port.name) 15) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" $port.name)) -}}
{{- fail "service.additionalPorts[].name must be a unique lower-case Service port name of at most 15 characters" -}}
{{- end -}}
{{- if hasKey $names $port.name -}}
{{- fail (printf "service.additionalPorts must not reuse port name %q" $port.name) -}}
{{- end -}}
{{- $_ := set $names $port.name true -}}
{{- if not (has $port.protocol (list "TCP" "UDP")) -}}
{{- fail "service.additionalPorts[].protocol must be TCP or UDP" -}}
{{- end -}}
{{- if or (lt (int $port.port) 1) (gt (int $port.port) 65535) -}}
{{- fail "service.additionalPorts[].port must be from 1 through 65535" -}}
{{- end -}}
{{- if or (lt (int $port.targetPort) 1024) (gt (int $port.targetPort) 65535) -}}
{{- fail "service.additionalPorts[].targetPort must be an unprivileged numeric port from 1024 through 65535" -}}
{{- end -}}
{{- $serviceSocket := printf "%s/%d" $port.protocol (int $port.port) -}}
{{- if hasKey $serviceSockets $serviceSocket -}}
{{- fail (printf "service.additionalPorts must not reuse Service socket %s" $serviceSocket) -}}
{{- end -}}
{{- $_ := set $serviceSockets $serviceSocket true -}}
{{- $containerSocket := printf "%s/%d" $port.protocol (int $port.targetPort) -}}
{{- if hasKey $containerSockets $containerSocket -}}
{{- fail (printf "service.additionalPorts must not reuse container socket %s" $containerSocket) -}}
{{- end -}}
{{- $_ := set $containerSockets $containerSocket true -}}
{{- end -}}
{{- end -}}

{{- define "oxibelt.validateNetworkPolicy" -}}
{{- include "oxibelt.validateAdditionalServicePorts" . -}}
{{- $networkPolicy := .Values.networkPolicy -}}
{{- if not (kindIs "map" $networkPolicy) -}}
{{- fail "networkPolicy must be an object" -}}
{{- end -}}
{{- if or (not (hasKey $networkPolicy "enabled")) (not (kindIs "bool" $networkPolicy.enabled)) -}}
{{- fail "networkPolicy.enabled must be a boolean" -}}
{{- end -}}
{{- $cilium := $networkPolicy.cilium -}}
{{- if not (kindIs "map" $cilium) -}}
{{- fail "networkPolicy.cilium must be an object" -}}
{{- end -}}
{{- if or (not (hasKey $cilium "enabled")) (not (kindIs "bool" $cilium.enabled)) -}}
{{- fail "networkPolicy.cilium.enabled must be a boolean" -}}
{{- end -}}
{{- if and $cilium.enabled (not $networkPolicy.enabled) -}}
{{- fail "networkPolicy.cilium.enabled requires networkPolicy.enabled=true" -}}
{{- end -}}
{{- if $networkPolicy.enabled -}}
{{- $ingress := $networkPolicy.ingress -}}
{{- $egress := $networkPolicy.egress -}}
{{- if not (kindIs "map" $ingress) -}}
{{- fail "networkPolicy.ingress must be an object" -}}
{{- end -}}
{{- if not (kindIs "map" $egress) -}}
{{- fail "networkPolicy.egress must be an object" -}}
{{- end -}}
{{- $public := $ingress.public -}}
{{- $metrics := $ingress.metrics -}}
{{- $admin := $ingress.admin -}}
{{- if not (kindIs "map" $public) -}}
{{- fail "networkPolicy.ingress.public must be an object" -}}
{{- end -}}
{{- if or (not (hasKey $public "allowAll")) (not (kindIs "bool" $public.allowAll)) -}}
{{- fail "networkPolicy.ingress.public.allowAll must be a boolean" -}}
{{- end -}}
{{- if not (hasKey $public "from") -}}
{{- fail "networkPolicy.ingress.public.from is required" -}}
{{- end -}}
{{- include "oxibelt.validateNetworkPolicyPeers" (dict "peers" $public.from "field" "networkPolicy.ingress.public.from" "required" false) -}}
{{- if and $public.allowAll (gt (len $public.from) 0) -}}
{{- fail "networkPolicy.ingress.public.allowAll cannot be combined with networkPolicy.ingress.public.from" -}}
{{- end -}}
{{- $hasPublicListener := or .Values.service.ports.http.enabled .Values.service.ports.https.enabled .Values.service.ports.http3.enabled (gt (len (.Values.service.additionalPorts | default (list))) 0) -}}
{{- if and (or $public.allowAll (gt (len $public.from) 0)) (not $hasPublicListener) -}}
{{- fail "networkPolicy.ingress.public requires an enabled public listener" -}}
{{- end -}}
{{- if or (not (kindIs "map" $metrics)) (not (hasKey $metrics "from")) -}}
{{- fail "networkPolicy.ingress.metrics.from is required" -}}
{{- end -}}
{{- include "oxibelt.validateNetworkPolicyPeers" (dict "peers" $metrics.from "field" "networkPolicy.ingress.metrics.from" "required" false) -}}
{{- if or (not (kindIs "map" $admin)) (not (hasKey $admin "from")) -}}
{{- fail "networkPolicy.ingress.admin.from is required" -}}
{{- end -}}
{{- include "oxibelt.validateNetworkPolicyPeers" (dict "peers" $admin.from "field" "networkPolicy.ingress.admin.from" "required" false) -}}
{{- $dns := $egress.dns -}}
{{- if not (kindIs "map" $dns) -}}
{{- fail "networkPolicy.egress.dns must be an object" -}}
{{- end -}}
{{- if or (not (hasKey $dns "enabled")) (not (kindIs "bool" $dns.enabled)) -}}
{{- fail "networkPolicy.egress.dns.enabled must be a boolean" -}}
{{- end -}}
{{- if not (hasKey $dns "to") -}}
{{- fail "networkPolicy.egress.dns.to is required" -}}
{{- end -}}
{{- include "oxibelt.validateNetworkPolicyPeers" (dict "peers" $dns.to "field" "networkPolicy.egress.dns.to" "required" $dns.enabled) -}}
{{- if not (hasKey $egress "destinations") -}}
{{- fail "networkPolicy.egress.destinations is required" -}}
{{- end -}}
{{- $destinations := $egress.destinations -}}
{{- if not (kindIs "slice" $destinations) -}}
{{- fail "networkPolicy.egress.destinations must be an array" -}}
{{- end -}}
{{- $destinationNames := dict -}}
{{- $hasKubernetesApiDestination := false -}}
{{- range $destinationIndex, $destination := $destinations -}}
{{- $destinationField := printf "networkPolicy.egress.destinations[%d]" $destinationIndex -}}
{{- include "oxibelt.validateNetworkPolicyDestination" (dict "destination" $destination "field" $destinationField) -}}
{{- if hasKey $destinationNames $destination.name -}}
{{- fail "networkPolicy.egress.destinations must not reuse a destination name" -}}
{{- end -}}
{{- $_ := set $destinationNames $destination.name true -}}
{{- if eq $destination.category "kubernetes-api" -}}
{{- $hasKubernetesApiDestination = true -}}
{{- end -}}
{{- end -}}
{{- $hasKubernetesApiAccess := eq (include "oxibelt.kubernetesApiAccessEnabled" .) "true" -}}
{{- if and $hasKubernetesApiAccess (not $hasKubernetesApiDestination) -}}
{{- fail "networkPolicy requires a kubernetes-api egress destination when Kubernetes API token projection is enabled" -}}
{{- end -}}
{{- if $cilium.enabled -}}
{{- if not $dns.enabled -}}
{{- fail "networkPolicy.cilium.enabled requires networkPolicy.egress.dns.enabled=true" -}}
{{- end -}}
{{- $ciliumDns := $cilium.dns -}}
{{- if or (not (kindIs "map" $ciliumDns)) (not (hasKey $ciliumDns "toEndpoints")) (not (kindIs "slice" $ciliumDns.toEndpoints)) (eq (len $ciliumDns.toEndpoints) 0) -}}
{{- fail "networkPolicy.cilium.dns.toEndpoints must contain at least one trusted DNS endpoint selector" -}}
{{- end -}}
{{- range $endpointIndex, $endpoint := $ciliumDns.toEndpoints -}}
{{- include "oxibelt.validateNetworkPolicyLabelSelector" (dict "selector" $endpoint "field" (printf "networkPolicy.cilium.dns.toEndpoints[%d]" $endpointIndex)) -}}
{{- end -}}
{{- if or (not (hasKey $cilium "fqdnDestinations")) (not (kindIs "slice" $cilium.fqdnDestinations)) (eq (len $cilium.fqdnDestinations) 0) -}}
{{- fail "networkPolicy.cilium.fqdnDestinations must contain at least one destination when Cilium is enabled" -}}
{{- end -}}
{{- $ciliumDestinationNames := dict -}}
{{- range $destinationIndex, $destination := $cilium.fqdnDestinations -}}
{{- $destinationField := printf "networkPolicy.cilium.fqdnDestinations[%d]" $destinationIndex -}}
{{- include "oxibelt.validateCiliumFqdnDestination" (dict "destination" $destination "field" $destinationField) -}}
{{- if hasKey $ciliumDestinationNames $destination.name -}}
{{- fail "networkPolicy.cilium.fqdnDestinations must not reuse a destination name" -}}
{{- end -}}
{{- $_ := set $ciliumDestinationNames $destination.name true -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
