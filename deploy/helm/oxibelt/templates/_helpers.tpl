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

{{- define "oxibelt.validateWorkloadRollout" -}}
{{- if eq .Values.workload.kind "Deployment" -}}
{{- if le (int .Values.workload.deployment.progressDeadlineSeconds) (int .Values.workload.deployment.minReadySeconds) -}}
{{- fail "workload.deployment.progressDeadlineSeconds must be greater than workload.deployment.minReadySeconds" -}}
{{- end -}}
{{- end -}}
{{- end -}}
