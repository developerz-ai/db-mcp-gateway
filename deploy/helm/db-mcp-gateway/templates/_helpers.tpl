{{- define "gateway.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "gateway.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else if contains (include "gateway.name" .) .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "gateway.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "gateway.selectorLabels" -}}
app.kubernetes.io/name: {{ include "gateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "gateway.labels" -}}
{{ include "gateway.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "gateway.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ default .Chart.AppVersion .Values.image.tag }}
{{- end -}}
{{- end -}}

{{- define "gateway.tlsSecretName" -}}
{{- if .Values.tls.secretName -}}
{{ .Values.tls.secretName }}
{{- else if .Values.tls.certManager.enabled -}}
{{ include "gateway.fullname" . }}-tls
{{- else -}}
{{ fail "tls.secretName is required when tls.enabled (or set tls.certManager.enabled)" }}
{{- end -}}
{{- end -}}

{{- define "gateway.probeScheme" -}}
{{ ternary "HTTPS" "HTTP" .Values.tls.enabled }}
{{- end -}}

{{/* One NetworkPolicy egress rule; an empty `to` means any destination. */}}
{{- define "gateway.egressRule" -}}
- ports:
    {{- toYaml .ports | nindent 4 }}
  {{- with .to }}
  to:
    {{- toYaml . | nindent 4 }}
  {{- end }}
{{- end -}}
