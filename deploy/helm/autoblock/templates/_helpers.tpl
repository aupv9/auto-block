{{/*
Expand the name of the chart.
*/}}
{{- define "autoblock.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "autoblock.fullname" -}}
{{- printf "%s" (include "autoblock.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "autoblock.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "autoblock.labels" -}}
helm.sh/chart: {{ include "autoblock.chart" . }}
{{ include "autoblock.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "autoblock.selectorLabels" -}}
app.kubernetes.io/name: {{ include "autoblock.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "autoblock.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "autoblock.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "autoblock.image" -}}
{{- $tag := .tag | default $.Chart.AppVersion }}
{{- printf "%s:%s" .repository $tag }}
{{- end }}
