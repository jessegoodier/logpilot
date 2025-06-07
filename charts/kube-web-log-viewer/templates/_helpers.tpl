{{/*
Expand the name of the chart.
*/}}
{{- define "kube-web-log-viewer.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "kube-web-log-viewer.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "kube-web-log-viewer.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "kube-web-log-viewer.labels" -}}
helm.sh/chart: {{ include "kube-web-log-viewer.chart" . }}
{{ include "kube-web-log-viewer.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "kube-web-log-viewer.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kube-web-log-viewer.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "kube-web-log-viewer.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "kube-web-log-viewer.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "src-app-path" -}}
{{- . | replace "../../src/" "" | replace "/" "-" -}}
{{- end -}}

{{- define "kube-web-log-viewer.configMapChecksum" -}}
{{- .Files.Get "src/main.py" | sha256sum }}
{{- .Files.Get "src/log_archiver.py" | sha256sum }}
{{- .Files.Get "src/index.html" | sha256sum }}
{{- end }}