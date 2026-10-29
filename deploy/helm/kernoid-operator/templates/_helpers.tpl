{{/*
SPDX-License-Identifier: AGPL-3.0-or-later
*/}}
{{- define "kernoid-operator.labels" -}}
app.kubernetes.io/name: kernoid-operator
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end }}

{{- define "kernoid-operator.selector" -}}
app.kubernetes.io/name: kernoid-operator
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "kernoid-operator.fullname" -}}
{{- if eq .Release.Name "kernoid-operator" -}}kernoid-operator{{- else -}}{{ printf "%s-kernoid-operator" .Release.Name | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- end }}
