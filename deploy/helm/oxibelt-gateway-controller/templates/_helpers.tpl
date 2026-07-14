{{- define "oxibelt-gateway-controller.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
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
{{- end -}}
