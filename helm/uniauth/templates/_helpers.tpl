{{/*
Expand the name of the chart.
*/}}
{{- define "uniauth.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
Truncated at 63 chars because some Kubernetes name fields are limited to this.
*/}}
{{- define "uniauth.fullname" -}}
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
Create chart label value (chart name + version).
*/}}
{{- define "uniauth.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels applied to all resources.
*/}}
{{- define "uniauth.labels" -}}
helm.sh/chart: {{ include "uniauth.chart" . }}
{{ include "uniauth.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels used by Deployments, Services, and HPAs.
*/}}
{{- define "uniauth.selectorLabels" -}}
app.kubernetes.io/name: {{ include "uniauth.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Name of the ServiceAccount to use.
*/}}
{{- define "uniauth.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "uniauth.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Name of the Secret that holds sensitive credentials.
Returns existingSecret if set, otherwise the chart-managed secret name.
*/}}
{{- define "uniauth.secretName" -}}
{{- if .Values.secrets.existingSecret }}
{{- .Values.secrets.existingSecret }}
{{- else }}
{{- printf "%s-credentials" (include "uniauth.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Name of the ConfigMap that holds non-sensitive configuration.
*/}}
{{- define "uniauth.configMapName" -}}
{{- printf "%s-config" (include "uniauth.fullname" .) }}
{{- end }}
