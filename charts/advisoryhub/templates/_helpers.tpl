{{/*
Expand the name of the chart.
*/}}
{{- define "advisoryhub.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Fully qualified app name (release-aware, 63-char capped).
*/}}
{{- define "advisoryhub.fullname" -}}
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

{{- define "advisoryhub.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels. Pass the root context.
*/}}
{{- define "advisoryhub.labels" -}}
helm.sh/chart: {{ include "advisoryhub.chart" . }}
app.kubernetes.io/name: {{ include "advisoryhub.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels. Pass (dict "ctx" $ "component" "web"). Selectors are
immutable — keep this list minimal and stable.
*/}}
{{- define "advisoryhub.selectorLabels" -}}
app.kubernetes.io/name: {{ include "advisoryhub.name" .ctx }}
app.kubernetes.io/instance: {{ .ctx.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{- define "advisoryhub.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}

{{- define "advisoryhub.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "advisoryhub.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Hostnames the app serves, newline-joined (empty string when none are known).
django.allowedHosts wins; otherwise derived from route.host + ingress hosts.
*/}}
{{- define "advisoryhub.hosts" -}}
{{- $hosts := list -}}
{{- if .Values.django.allowedHosts -}}
{{- $hosts = .Values.django.allowedHosts -}}
{{- else -}}
{{- if and .Values.route.enabled .Values.route.host -}}
{{- $hosts = append $hosts .Values.route.host -}}
{{- end -}}
{{- range .Values.ingress.hosts -}}
{{- if .host -}}
{{- $hosts = append $hosts .host -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- $hosts | uniq | join "\n" -}}
{{- end }}

{{/*
First known hostname ("" when none) — used for the probe Host header and the
default ADVISORYHUB_BASE_URL.
*/}}
{{- define "advisoryhub.primaryHost" -}}
{{- include "advisoryhub.hosts" . | splitList "\n" | first -}}
{{- end }}

{{/*
Name of the Secret applied via envFrom ("" when none is configured).
*/}}
{{- define "advisoryhub.envSecretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else if .Values.secrets.create -}}
{{- printf "%s-env" (include "advisoryhub.fullname" .) -}}
{{- end -}}
{{- end }}

{{/*
Name of the key-files Secret ("" when none is configured).
*/}}
{{- define "advisoryhub.filesSecretName" -}}
{{- if .Values.secrets.files.existingSecret -}}
{{- .Values.secrets.files.existingSecret -}}
{{- else if .Values.secrets.files.create -}}
{{- printf "%s-keys" (include "advisoryhub.fullname" .) -}}
{{- end -}}
{{- end }}

{{/*
Every non-secret environment variable, as a YAML map of string values.
Single source of truth: configmap.yaml renders it into data; job-migrate.yaml
inlines it (pre-install hooks run before the release ConfigMap exists).
Keys whose value would be empty are omitted so config/settings/base.py
defaults apply.
*/}}
{{- define "advisoryhub.envMap" -}}
{{- $hosts := include "advisoryhub.hosts" . | splitList "\n" | compact -}}
{{- $primary := include "advisoryhub.primaryHost" . -}}
{{- $filesSecret := include "advisoryhub.filesSecretName" . -}}
DJANGO_SETTINGS_MODULE: "config.settings.prod"
DJANGO_TIME_ZONE: {{ .Values.django.timeZone | quote }}
{{- if $hosts }}
DJANGO_ALLOWED_HOSTS: {{ join "," $hosts | quote }}
{{- end }}
USE_X_FORWARDED_PROTO: {{ ternary "True" "False" .Values.django.useXForwardedProto | quote }}
TRUSTED_PROXY_COUNT: {{ .Values.django.trustedProxyCount | quote }}
{{- $origins := .Values.django.csrfTrustedOrigins -}}
{{- if not $origins }}
{{- $origins = list }}
{{- range $hosts }}
{{- $origins = append $origins (printf "https://%s" .) }}
{{- end }}
{{- end }}
{{- if $origins }}
CSRF_TRUSTED_ORIGINS: {{ join "," $origins | quote }}
{{- end }}
{{- $baseUrl := .Values.django.baseUrl }}
{{- if and (not $baseUrl) $primary }}
{{- $baseUrl = printf "https://%s" $primary }}
{{- end }}
{{- if $baseUrl }}
ADVISORYHUB_BASE_URL: {{ $baseUrl | quote }}
{{- end }}
LOG_FORMAT: "json"
LOG_LEVEL: {{ .Values.django.logLevel | quote }}
EMAIL_BACKEND: {{ .Values.email.backend | quote }}
DEFAULT_FROM_EMAIL: {{ .Values.email.defaultFrom | quote }}
{{- if .Values.email.host }}
EMAIL_HOST: {{ .Values.email.host | quote }}
EMAIL_PORT: {{ .Values.email.port | quote }}
EMAIL_USE_TLS: {{ ternary "True" "False" .Values.email.useTls | quote }}
EMAIL_USE_SSL: {{ ternary "True" "False" .Values.email.useSsl | quote }}
{{- end }}
{{- with .Values.oidc }}
{{- if .clientId }}
OIDC_RP_CLIENT_ID: {{ .clientId | quote }}
{{- end }}
{{- if .authorizationEndpoint }}
OIDC_OP_AUTHORIZATION_ENDPOINT: {{ .authorizationEndpoint | quote }}
{{- end }}
{{- if .tokenEndpoint }}
OIDC_OP_TOKEN_ENDPOINT: {{ .tokenEndpoint | quote }}
{{- end }}
{{- if .userEndpoint }}
OIDC_OP_USER_ENDPOINT: {{ .userEndpoint | quote }}
{{- end }}
{{- if .jwksEndpoint }}
OIDC_OP_JWKS_ENDPOINT: {{ .jwksEndpoint | quote }}
{{- end }}
{{- if .logoutEndpoint }}
OIDC_OP_LOGOUT_ENDPOINT: {{ .logoutEndpoint | quote }}
{{- end }}
OIDC_RP_SIGN_ALGO: {{ .signAlgo | quote }}
OIDC_GROUP_CLAIM: {{ .groupClaim | quote }}
OIDC_ADMIN_GROUP: {{ .adminGroup | quote }}
{{- end }}
READYZ_INCLUDE_BROKER: {{ ternary "True" "False" .Values.readyz.includeBroker | quote }}
READYZ_INCLUDE_PUB_REPO: {{ ternary "True" "False" .Values.readyz.includePubRepo | quote }}
{{- with .Values.pubRepo }}
{{- if .url }}
PUB_REPO_URL: {{ .url | quote }}
{{- end }}
PUB_REPO_BRANCH: {{ .branch | quote }}
PUB_REPO_AUTH: {{ .auth | quote }}
PUB_COMMIT_AUTHOR_NAME: {{ .commitAuthorName | quote }}
PUB_COMMIT_AUTHOR_EMAIL: {{ .commitAuthorEmail | quote }}
PUB_OSV_PATH_TEMPLATE: {{ .osvPathTemplate | quote }}
PUB_CSAF_PATH_TEMPLATE: {{ .csafPathTemplate | quote }}
PUB_CVE_PATH_TEMPLATE: {{ .cvePathTemplate | quote }}
{{- if .cveAssignerOrgId }}
PUB_CVE_ASSIGNER_ORG_ID: {{ .cveAssignerOrgId | quote }}
{{- end }}
PUB_CVE_ASSIGNER_SHORT_NAME: {{ .cveAssignerShortName | quote }}
{{- end }}
{{- if and (eq .Values.pubRepo.auth "ssh") $filesSecret }}
PUB_REPO_SSH_KEY_PATH: {{ printf "%s/pub-repo-ssh-key" .Values.secrets.files.mountPath | quote }}
{{- end }}
GHSA_FEATURE_ENABLED: {{ ternary "True" "False" .Values.ghsa.enabled | quote }}
{{- if .Values.ghsa.enabled }}
GITHUB_APP_ID: {{ .Values.ghsa.appId | quote }}
GITHUB_APP_API_BASE_URL: {{ .Values.ghsa.apiBaseUrl | quote }}
{{- if $filesSecret }}
GITHUB_APP_PRIVATE_KEY_PATH: {{ printf "%s/github-app-private-key" .Values.secrets.files.mountPath | quote }}
{{- end }}
{{- end }}
PMI_API_BASE_URL: {{ .Values.pmi.apiBaseUrl | quote }}
PMI_SYNC_INTERVAL_HOURS: {{ .Values.pmi.syncIntervalHours | quote }}
PMI_ROSTER_SYNC_ENABLED: {{ ternary "True" "False" .Values.rosterSync.enabled | quote }}
{{- if .Values.rosterSync.enabled }}
PMI_ROSTER_SYNC_INTERVAL_HOURS: {{ .Values.rosterSync.intervalHours | quote }}
ECLIPSE_API_BASE_URL: {{ .Values.rosterSync.eclipseApiBaseUrl | quote }}
ECLIPSE_API_TOKEN_URL: {{ .Values.rosterSync.tokenUrl | quote }}
{{- if .Values.rosterSync.scope }}
ECLIPSE_API_SCOPE: {{ .Values.rosterSync.scope | quote }}
{{- end }}
{{- end }}
INTAKE_DISABLED: {{ ternary "True" "False" .Values.intake.disabled | quote }}
INTAKE_REPORT_RETENTION_DAYS: {{ .Values.intake.retentionDays | quote }}
RATELIMIT_INTAKE_ANON: {{ .Values.intake.ratelimitAnon | quote }}
RATELIMIT_INTAKE_USER: {{ .Values.intake.ratelimitUser | quote }}
AUDIT_ACCESS_LOG_RETENTION_DAYS: {{ .Values.audit.accessLogRetentionDays | quote }}
AUDIT_ACCESS_LOG_RETENTION_ENABLED: {{ ternary "True" "False" .Values.audit.accessLogRetentionEnabled | quote }}
{{- if .Values.sentry.environment }}
SENTRY_ENVIRONMENT: {{ .Values.sentry.environment | quote }}
SENTRY_TRACES_SAMPLE_RATE: {{ .Values.sentry.tracesSampleRate | quote }}
{{- end }}
{{- end }}

{{/*
envFrom sources shared by every container: the release ConfigMap, the env
Secret (when configured) and any extraEnvFrom.
*/}}
{{- define "advisoryhub.envFrom" -}}
- configMapRef:
    name: {{ include "advisoryhub.fullname" . }}
{{- with include "advisoryhub.envSecretName" . }}
- secretRef:
    name: {{ . }}
{{- end }}
{{- with .Values.extraEnvFrom }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Pod-level security context. null uid/gid/fsGroup are omitted so OpenShift's
restricted-v2 SCC can assign them; set them in values on vanilla Kubernetes.
*/}}
{{- define "advisoryhub.podSecurityContext" -}}
{{- $ctx := dict }}
{{- range $k, $v := .Values.podSecurityContext }}
{{- if ne $v nil }}
{{- $_ := set $ctx $k $v }}
{{- end }}
{{- end }}
{{- toYaml $ctx }}
{{- end }}

{{- define "advisoryhub.containerSecurityContext" -}}
{{- toYaml .Values.containerSecurityContext }}
{{- end }}

{{/*
Pod-template annotations that force a rollout when configuration changes.
The contents of an existingSecret are invisible at template time — operators
rotate those with `kubectl rollout restart` (or a reloader controller).
*/}}
{{- define "advisoryhub.checksumAnnotations" -}}
checksum/config: {{ include (print $.Template.BasePath "/configmap.yaml") . | sha256sum }}
{{- if .Values.secrets.create }}
checksum/secret-env: {{ include (print $.Template.BasePath "/secret-env.yaml") . | sha256sum }}
{{- end }}
{{- if .Values.secrets.files.create }}
checksum/secret-keys: {{ include (print $.Template.BasePath "/secret-keys.yaml") . | sha256sum }}
{{- end }}
{{- end }}

{{/*
Volumes/mounts for the key-files Secret and the optional pinned known_hosts.
Used by web (readyz pub-repo probe) and worker (publication pushes).
*/}}
{{- define "advisoryhub.keyVolumes" -}}
{{- with include "advisoryhub.filesSecretName" . }}
- name: advisory-keys
  secret:
    secretName: {{ . }}
    defaultMode: {{ $.Values.secrets.files.defaultMode | int }}
{{- end }}
{{- if .Values.pubRepo.knownHosts }}
- name: ssh-known-hosts
  configMap:
    name: {{ include "advisoryhub.fullname" . }}-known-hosts
{{- end }}
{{- end }}

{{- define "advisoryhub.keyVolumeMounts" -}}
{{- if include "advisoryhub.filesSecretName" . }}
- name: advisory-keys
  mountPath: {{ .Values.secrets.files.mountPath }}
  readOnly: true
{{- end }}
{{- if .Values.pubRepo.knownHosts }}
{{/* The system-wide path OpenSSH consults — no $HOME coupling, works with a
read-only root fs. */}}
- name: ssh-known-hosts
  mountPath: /etc/ssh/ssh_known_hosts
  subPath: ssh_known_hosts
  readOnly: true
{{- end }}
{{- end }}
