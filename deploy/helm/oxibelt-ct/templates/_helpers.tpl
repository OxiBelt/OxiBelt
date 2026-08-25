{{- define "oxibelt-ct.name" -}}
{{- printf "%s-%s" .Release.Name .Values.role | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- define "oxibelt-ct.image" -}}
{{- if .Values.image.digest -}}{{ printf "%s@%s" .Values.image.repository .Values.image.digest }}{{- else -}}{{ printf "%s:%s" .Values.image.repository .Values.image.tag }}{{- end -}}
{{- end -}}
{{- define "oxibelt-ct.signerImage" -}}
{{- if .Values.signer.image.digest -}}{{ printf "%s@%s" .Values.signer.image.repository .Values.signer.image.digest }}{{- else -}}{{ printf "%s:%s" .Values.signer.image.repository .Values.signer.image.tag }}{{- end -}}
{{- end -}}
