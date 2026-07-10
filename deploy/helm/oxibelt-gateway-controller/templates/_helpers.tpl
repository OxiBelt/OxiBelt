{{- define "oxibelt-gateway-controller.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
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
