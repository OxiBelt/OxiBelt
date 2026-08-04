{{/* edge-secure-medium v2 deployment contract. V1 deliberately does not call these helpers. */}}
{{- define "oxibelt.isOperationalProfileV2" -}}
{{- if and (eq .Values.operationalProfile.name "edge-secure-medium") (eq (int .Values.operationalProfile.version) 2) -}}true{{- else -}}false{{- end -}}
{{- end -}}

{{- define "oxibelt.validateSupplyChainAdmission" -}}
{{- if .Values.supplyChainAdmission.enabled -}}
{{- if eq (include "oxibelt.isOperationalProfileV2" .) "true" -}}
{{- if ne .Values.image.role "dataplane-strict" -}}
{{- fail "OBP106-IMAGE-ROLE: operationalProfile edge-secure-medium v2 requires image.role=dataplane-strict" -}}
{{- end -}}
{{- if and .Values.image.repository (ne .Values.image.repository "ghcr.io/oxibelt/oxibelt-dataplane-strict") -}}
{{- fail "OBP106-IMAGE-REPOSITORY: operationalProfile edge-secure-medium v2 requires the official strict data-plane repository" -}}
{{- end -}}
{{- if not (regexMatch "^sha256:[0-9a-f]{64}$" .Values.image.digest) -}}
{{- fail "OBP106-IMAGE-DIGEST: operationalProfile edge-secure-medium v2 requires image.digest to be a lower-case sha256 digest" -}}
{{- end -}}
{{- end -}}
{{- $admission := .Values.supplyChainAdmission -}}
{{- $bundle := $admission.bundle -}}
{{- $webhook := $admission.webhook -}}
{{- if not (regexMatch "^sha256:[0-9a-f]{64}$" $bundle.payloadDigest) -}}
{{- fail "OBP204-BUNDLE-DIGEST: supplyChainAdmission.bundle.payloadDigest must be a lower-case sha256 digest" -}}
{{- end -}}
{{- if or (not $bundle.inline) (gt (len $bundle.inline) 262144) -}}
{{- fail "OBP204-BUNDLE-SIZE: supplyChainAdmission.bundle.inline must contain at most 262144 bytes" -}}
{{- end -}}
{{- if or (not $bundle.keyId) (gt (len $bundle.keyId) 128) (not (regexMatch "^[A-Za-z0-9._-]+$" $bundle.keyId)) -}}
{{- fail "OBP204-BUNDLE-KEY: supplyChainAdmission.bundle.keyId is invalid" -}}
{{- end -}}
{{- if not (regexMatch "^[A-Za-z0-9+/]{43}=$" $bundle.publicKeyBase64) -}}
{{- fail "OBP204-PUBLIC-KEY: supplyChainAdmission.bundle.publicKeyBase64 must encode one raw 32-byte Ed25519 key" -}}
{{- end -}}
{{- if or (not $bundle.revocations) (gt (len $bundle.revocations) 1048576) -}}
{{- fail "OBP204-REVOCATIONS-SIZE: supplyChainAdmission.bundle.revocations must contain at most 1048576 bytes" -}}
{{- end -}}
{{- if not (regexMatch "^sha256:[0-9a-f]{64}$" $webhook.image.digest) -}}
{{- fail "OBP204-WEBHOOK-DIGEST: supplyChainAdmission webhook image requires a lower-case sha256 digest" -}}
{{- end -}}
{{- if ne $webhook.image.repository "ghcr.io/oxibelt/oxibelt-tools" -}}
{{- fail "OBP204-WEBHOOK-IMAGE: supplyChainAdmission webhook requires the official tools repository" -}}
{{- end -}}
{{- if or (lt (int $webhook.replicas) 2) (gt (int $webhook.replicas) 9) -}}
{{- fail "OBP204-WEBHOOK-REPLICAS: supplyChainAdmission webhook replicas must be between 2 and 9" -}}
{{- end -}}
{{- if or (not $webhook.tlsSecretName) (gt (len $webhook.tlsSecretName) 253) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$" $webhook.tlsSecretName)) -}}
{{- fail "OBP204-WEBHOOK-TLS: supplyChainAdmission webhook requires a DNS-subdomain tlsSecretName" -}}
{{- end -}}
{{- if or (lt (len $webhook.apiServerSourceCidrs) 1) (gt (len $webhook.apiServerSourceCidrs) 16) -}}
{{- fail "OBP204-WEBHOOK-SOURCES: supplyChainAdmission webhook requires 1 to 16 exact API-server source CIDRs" -}}
{{- end -}}
{{- range $cidr := $webhook.apiServerSourceCidrs -}}
{{- if not (or (regexMatch "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/([0-9]|[12][0-9]|3[0-2])$" $cidr) (regexMatch "^[0-9A-Fa-f:]+/([0-9]|[1-9][0-9]|1[01][0-9]|12[0-8])$" $cidr)) -}}
{{- fail "OBP204-WEBHOOK-SOURCES: supplyChainAdmission webhook API-server source CIDRs are invalid" -}}
{{- end -}}
{{- end -}}
{{- if or (not $webhook.caBundle) (gt (len $webhook.caBundle) 262144) -}}
{{- fail "OBP204-WEBHOOK-CA: supplyChainAdmission webhook requires a bounded caBundle" -}}
{{- end -}}
{{- if or (lt (int $webhook.timeoutSeconds) 1) (gt (int $webhook.timeoutSeconds) 10) -}}
{{- fail "OBP204-WEBHOOK-TIMEOUT: supplyChainAdmission webhook timeoutSeconds must be between 1 and 10" -}}
{{- end -}}
{{- $parsed := fromJson $bundle.inline -}}
{{- if hasKey $parsed "Error" -}}
{{- fail "OBP204-BUNDLE-JSON: supplyChainAdmission.bundle.inline must be valid JSON" -}}
{{- end -}}
{{- $payload := get $parsed "payload" | default (dict) -}}
{{- $workloadPolicy := dig "payload" "workloadPolicy" (dict) $parsed -}}
{{- $auxiliaryContainers := get $workloadPolicy "auxiliaryContainers" -}}
{{- $schemaVersion := int (dig "schemaVersion" 0 $payload) -}}
{{- $policyVersion := dig "policy" "version" "" $payload -}}
{{- $isV1 := and (eq $schemaVersion 1) (eq $policyVersion "oxibelt-admission-v1") (not (hasKey $payload "workloadPolicy")) -}}
{{- $isV2 := and (eq $schemaVersion 2) (eq $policyVersion "oxibelt-admission-v2") (eq (int (dig "schemaVersion" 0 $workloadPolicy)) 1) (hasKey $workloadPolicy "auxiliaryContainers") (kindIs "slice" $auxiliaryContainers) (le (len $auxiliaryContainers) 63) -}}
{{- if not (or $isV1 $isV2) -}}
{{- fail "OBP204-BUNDLE-VERSION: supply-chain bundle schema, policy, and workload policy are inconsistent" -}}
{{- end -}}
{{- if ne (dig "signature" "payloadSha256" "" $parsed) $bundle.payloadDigest -}}
{{- fail "OBP204-BUNDLE-IDENTITY: configured bundle digest does not match signature.payloadSha256" -}}
{{- end -}}
{{- if or (ne (dig "signature" "keyId" "" $parsed) $bundle.keyId) (ne (dig "payload" "policy" "bundleSigningKeyId" "" $parsed) $bundle.keyId) -}}
{{- fail "OBP204-BUNDLE-KEY-ID: configured key id does not match the bundle" -}}
{{- end -}}
{{- if ne (dig "payload" "decision" "status" "" $parsed) "pass" -}}
{{- fail "OBP204-BUNDLE-DECISION: supply-chain bundle decision must pass" -}}
{{- end -}}
{{- $repository := .Values.image.repository | default "ghcr.io/oxibelt/oxibelt-dataplane-strict" -}}
{{- if or (ne (dig "payload" "artifact" "repository" "" $parsed) $repository) (ne (dig "payload" "artifact" "digest" "" $parsed) .Values.image.digest) (ne (dig "payload" "artifact" "role" "" $parsed) .Values.image.role) (ne (dig "payload" "artifact" "imageReference" "" $parsed) (printf "%s@%s" $repository .Values.image.digest)) -}}
{{- fail "OBP204-BUNDLE-ARTIFACT: supply-chain bundle does not match the exact Helm image repository, role, and digest" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "oxibelt.validateOperationalProfileV2" -}}
{{- if eq (include "oxibelt.isOperationalProfileV2" .) "true" -}}
{{- $officialRepository := "ghcr.io/oxibelt/oxibelt-dataplane-strict" -}}
{{- if ne .Values.image.role "dataplane-strict" -}}
{{- fail "OBP106-IMAGE-ROLE: operationalProfile edge-secure-medium v2 requires image.role=dataplane-strict" -}}
{{- end -}}
{{- if and .Values.image.repository (ne .Values.image.repository $officialRepository) -}}
{{- fail (printf "OBP106-IMAGE-REPOSITORY: operationalProfile edge-secure-medium v2 requires image.repository=%s or the empty official alias" $officialRepository) -}}
{{- end -}}
{{- if not (regexMatch "^sha256:[0-9a-f]{64}$" .Values.image.digest) -}}
{{- fail "OBP106-IMAGE-DIGEST: operationalProfile edge-secure-medium v2 requires image.digest to be a lower-case sha256 digest" -}}
{{- end -}}
{{- if not .Values.supplyChainAdmission.enabled -}}
{{- fail "OBP204-ADMISSION-REQUIRED: operationalProfile edge-secure-medium v2 requires supplyChainAdmission.enabled=true" -}}
{{- end -}}
{{- include "oxibelt.validateSupplyChainAdmission" . -}}
{{- if not .Values.networkPolicy.enabled -}}
{{- fail "OBP106-NETWORK-POLICY: operationalProfile edge-secure-medium v2 requires networkPolicy.enabled=true" -}}
{{- end -}}

{{- $hasPublicListener := or .Values.service.ports.http.enabled .Values.service.ports.https.enabled .Values.service.ports.http3.enabled (gt (len (.Values.service.additionalPorts | default (list))) 0) -}}
{{- if and $hasPublicListener (not .Values.networkPolicy.ingress.public.allowAll) (eq (len .Values.networkPolicy.ingress.public.from) 0) -}}
{{- fail "OBP106-PUBLIC-INGRESS: operationalProfile edge-secure-medium v2 requires explicit public ingress peers or ingress.public.allowAll=true for enabled public listeners" -}}
{{- end -}}
{{- if or (ne .Values.cacheVolume.mode "auto") .Values.cacheVolume.sizeLimit -}}
{{- fail "OBP106-LEGACY-CACHE: operationalProfile edge-secure-medium v2 requires cacheVolume.mode=auto with an empty sizeLimit; declare writable cache storage through writableVolumes" -}}
{{- end -}}
{{- if or (gt (len .Values.extraVolumes) 0) (gt (len .Values.extraVolumeMounts) 0) -}}
{{- fail "OBP106-UNTYPED-VOLUME: operationalProfile edge-secure-medium v2 rejects extraVolumes and extraVolumeMounts; use writableVolumes or chart-owned read-only projections" -}}
{{- end -}}
{{- $manifestDigest := .Values.runtimeHardening.filesystemManifest.expectedDigest -}}
{{- if not (regexMatch "^sha256:[0-9a-f]{64}$" $manifestDigest) -}}
{{- fail "OBP106-FILESYSTEM-MANIFEST: operationalProfile edge-secure-medium v2 requires runtimeHardening.filesystemManifest.expectedDigest to be a lower-case sha256 digest" -}}
{{- end -}}
{{- if regexMatch "(?m)^[[:space:]]*\\[runtime[.]hardening[.]filesystem_manifest\\]" (tpl .Values.config.inline .) -}}
{{- fail "OBP106-FILESYSTEM-CONFIG: runtimeHardening.filesystemManifest cannot be combined with a [runtime.hardening.filesystem_manifest] section in config.inline" -}}
{{- end -}}

{{- $pod := .Values.podSecurityContext -}}
{{- $container := .Values.securityContext -}}
{{- range $key, $_ := $pod -}}
{{- if not (has $key (list "runAsNonRoot" "runAsUser" "runAsGroup" "fsGroup" "seccompProfile")) -}}
{{- fail (printf "OBP106-POD-SECURITY-KEY: operationalProfile edge-secure-medium v2 rejects podSecurityContext key %s" $key) -}}
{{- end -}}
{{- end -}}
{{- range $key, $_ := $container -}}
{{- if not (has $key (list "privileged" "allowPrivilegeEscalation" "readOnlyRootFilesystem" "capabilities")) -}}
{{- fail (printf "OBP106-CONTAINER-SECURITY-KEY: operationalProfile edge-secure-medium v2 rejects securityContext key %s" $key) -}}
{{- end -}}
{{- end -}}
{{- range $key, $_ := $container.capabilities -}}
{{- if not (has $key (list "drop" "add")) -}}
{{- fail (printf "OBP106-CAPABILITIES-KEY: operationalProfile edge-secure-medium v2 rejects capabilities key %s" $key) -}}
{{- end -}}
{{- end -}}
{{- range $key, $_ := $pod.seccompProfile -}}
{{- if not (has $key (list "type" "localhostProfile")) -}}
{{- fail (printf "OBP106-SECCOMP-KEY: operationalProfile edge-secure-medium v2 rejects seccompProfile key %s" $key) -}}
{{- end -}}
{{- end -}}
{{- if or (not $pod.runAsNonRoot) (ne (int $pod.runAsUser) 10001) (ne (int $pod.runAsGroup) 10001) (ne (int $pod.fsGroup) 10001) -}}
{{- fail "OBP106-POD-IDENTITY: operationalProfile edge-secure-medium v2 requires runAsNonRoot=true and runAsUser/runAsGroup/fsGroup=10001" -}}
{{- end -}}
{{- if or (hasKey $container "runAsUser") (hasKey $container "runAsGroup") (hasKey $container "runAsNonRoot") (hasKey $container "seccompProfile") -}}
{{- fail "OBP106-CONTAINER-OVERRIDE: operationalProfile edge-secure-medium v2 rejects container identity and seccomp overrides" -}}
{{- end -}}
{{- if and (hasKey $container "privileged") $container.privileged -}}
{{- fail "OBP106-PRIVILEGED: operationalProfile edge-secure-medium v2 requires securityContext.privileged=false" -}}
{{- end -}}
{{- if or $container.allowPrivilegeEscalation (not $container.readOnlyRootFilesystem) -}}
{{- fail "OBP106-CONTAINER-SECURITY: operationalProfile edge-secure-medium v2 requires allowPrivilegeEscalation=false and readOnlyRootFilesystem=true" -}}
{{- end -}}
{{- $drops := $container.capabilities.drop | default (list) -}}
{{- if or (ne (len $drops) 1) (ne (index $drops 0 | toString) "ALL") ($container.capabilities.add | default (list)) -}}
{{- fail "OBP106-CAPABILITIES: operationalProfile edge-secure-medium v2 requires exactly capabilities.drop=[ALL] and no added capabilities" -}}
{{- end -}}
{{- if not (has $pod.seccompProfile.type (list "RuntimeDefault" "Localhost")) -}}
{{- fail "OBP106-SECCOMP: operationalProfile edge-secure-medium v2 requires RuntimeDefault or Localhost seccomp" -}}
{{- end -}}

{{- if not (kindIs "map" .Values.podLabels) -}}
{{- fail "OBP106-POD-LABELS: podLabels must be an object" -}}
{{- end -}}
{{- range $key, $_ := .Values.podLabels -}}
{{- if or (eq $key "app.kubernetes.io/name") (eq $key "app.kubernetes.io/instance") (hasPrefix "oxibelt.dev/" $key) -}}
{{- fail (printf "OBP106-RESERVED-LABEL: podLabels key %s is reserved by the v2 workload and policy contract" $key) -}}
{{- end -}}
{{- end -}}
{{- range $key, $_ := .Values.podAnnotations -}}
{{- if or (hasPrefix "checksum/oxibelt-" $key) (hasPrefix "seccomp.security.alpha.kubernetes.io/" $key) (hasPrefix "container.seccomp.security.alpha.kubernetes.io/" $key) (hasPrefix "container.apparmor.security.beta.kubernetes.io/" $key) (hasPrefix "apparmor.security.beta.kubernetes.io/" $key) (and (hasPrefix "oxibelt.dev/" $key) (not (has $key (list "oxibelt.dev/seccomp-profile-identity" "oxibelt.dev/seccomp-profile-digest")))) -}}
{{- fail (printf "OBP106-RESERVED-ANNOTATION: podAnnotations key %s is reserved by the v2 workload and rollout contract" $key) -}}
{{- end -}}
{{- end -}}

{{- include "oxibelt.validateWritableVolumesV2" . -}}

{{- $hasApiAccess := eq (include "oxibelt.kubernetesApiAccessEnabled" .) "true" -}}
{{- $token := .Values.kubernetesDiscovery.serviceAccountToken -}}
{{- if and $hasApiAccess (not $token.enabled) -}}
{{- fail "OBP106-SERVICE-ACCOUNT-TOKEN: Kubernetes API access in v2 requires serviceAccountToken.enabled=true" -}}
{{- end -}}
{{- if and $hasApiAccess (or (not $token.audience) (gt (len $token.audience) 253)) -}}
{{- fail "OBP106-TOKEN-AUDIENCE: projected Kubernetes API tokens in v2 require a nonempty audience of at most 253 characters" -}}
{{- end -}}
{{- $apiDestinations := 0 -}}
{{- $sharedStateDestinations := 0 -}}
{{- if and (not .Values.networkPolicy.cilium.enabled) (gt (len .Values.networkPolicy.cilium.fqdnDestinations) 0) -}}
{{- fail "OBP106-CILIUM-DISABLED: Cilium FQDN destinations require networkPolicy.cilium.enabled=true" -}}
{{- end -}}
{{- range $destination := .Values.networkPolicy.egress.destinations -}}
{{- if eq $destination.category "kubernetes-api" -}}{{- $apiDestinations = add1 $apiDestinations -}}{{- end -}}
{{- if eq $destination.category "shared-state" -}}{{- $sharedStateDestinations = add1 $sharedStateDestinations -}}{{- end -}}
{{- if eq $destination.category "control-plane" -}}
{{- fail "OBP106-CONTROL-PLANE: the Admin-free v2 strict role rejects control-plane egress" -}}
{{- end -}}
{{- include "oxibelt.validateUnrestrictedCidrsV2" (dict "destination" $destination) -}}
{{- end -}}
{{- range $destination := .Values.networkPolicy.cilium.fqdnDestinations -}}
{{- if eq $destination.category "kubernetes-api" -}}{{- $apiDestinations = add1 $apiDestinations -}}{{- end -}}
{{- if eq $destination.category "shared-state" -}}{{- $sharedStateDestinations = add1 $sharedStateDestinations -}}{{- end -}}
{{- if eq $destination.category "control-plane" -}}
{{- fail "OBP106-CONTROL-PLANE: the Admin-free v2 strict role rejects control-plane egress, including Cilium FQDN destinations" -}}
{{- end -}}
{{- end -}}
{{- if and $hasApiAccess (ne (int $apiDestinations) 1) -}}
{{- fail "OBP106-KUBERNETES-API-DEPENDENCY: Kubernetes API access in v2 requires exactly one kubernetes-api egress destination" -}}
{{- end -}}
{{- if and (not $hasApiAccess) (ne (int $apiDestinations) 0) -}}
{{- fail "OBP106-UNUSED-KUBERNETES-API-DEPENDENCY: kubernetes-api egress requires explicit projected API access" -}}
{{- end -}}
{{- if and (gt (len .Values.sharedState.redisSecretProjections) 0) (eq (int $sharedStateDestinations) 0) -}}
{{- fail "OBP106-SHARED-STATE-DEPENDENCY: Redis secret projections in v2 require a shared-state egress destination" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "oxibelt.validateUnrestrictedCidrsV2" -}}
{{- $destination := .destination -}}
{{- $escape := $destination.unrestrictedCidrs | default (dict "enabled" false "justification" "") -}}
{{- if not (kindIs "map" $escape) -}}
{{- fail "OBP106-UNRESTRICTED-CIDR-CONTRACT: unrestrictedCidrs must be an object" -}}
{{- end -}}
{{- $world := false -}}
{{- range $peer := $destination.to -}}
{{- if and (hasKey $peer "ipBlock") (regexMatch "/0+$" $peer.ipBlock.cidr) -}}{{- $world = true -}}{{- end -}}
{{- end -}}
{{- if and $world (not ($escape.enabled | default false)) -}}
{{- fail (printf "OBP106-UNRESTRICTED-CIDR: destination %s contains a world CIDR without unrestrictedCidrs.enabled=true" $destination.name) -}}
{{- end -}}
{{- if and $world (or (not ($escape.justification | default "")) (gt (len $escape.justification) 512)) -}}
{{- fail (printf "OBP106-UNRESTRICTED-CIDR-JUSTIFICATION: destination %s requires a nonempty unrestrictedCidrs.justification of at most 512 characters" $destination.name) -}}
{{- end -}}
{{- if and (not $world) ($escape.enabled | default false) -}}
{{- fail (printf "OBP106-UNUSED-UNRESTRICTED-CIDR: destination %s enables unrestrictedCidrs without a world CIDR" $destination.name) -}}
{{- end -}}
{{- end -}}

{{- define "oxibelt.validateWritableVolumesV2" -}}
{{- $volumes := .Values.writableVolumes | default (list) -}}
{{- if not (kindIs "slice" $volumes) -}}{{- fail "OBP106-WRITABLE-VOLUMES: writableVolumes must be an array" -}}{{- end -}}
{{- if gt (len $volumes) 16 -}}{{- fail "OBP106-WRITABLE-VOLUME-LIMIT: writableVolumes must contain at most 16 entries" -}}{{- end -}}
{{- $names := dict -}}
{{- $paths := dict -}}
{{- range $index, $volume := $volumes -}}
{{- if not (kindIs "map" $volume) -}}{{- fail (printf "OBP106-WRITABLE-VOLUME: writableVolumes[%d] must be an object" $index) -}}{{- end -}}
{{- if or (not $volume.name) (gt (len $volume.name) 63) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" $volume.name)) (has $volume.name (list "config" "tls" "oxirule" "kube-api-access")) -}}
{{- fail (printf "OBP106-WRITABLE-VOLUME-NAME: writableVolumes[%d].name must be a safe non-reserved DNS label" $index) -}}
{{- end -}}
{{- if hasKey $names $volume.name -}}{{- fail "OBP106-WRITABLE-VOLUME-NAME-DUPLICATE: writableVolumes names must be unique" -}}{{- end -}}
{{- $_ := set $names $volume.name true -}}
{{- $path := $volume.mountPath | default "" -}}
{{- if or (eq $path "/") (ne (clean $path) $path) (not (regexMatch "^/[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$" $path)) -}}
{{- fail (printf "OBP106-WRITABLE-PATH: writableVolumes[%d].mountPath must be a normalized absolute non-root path" $index) -}}
{{- end -}}
{{- range $priorPath, $_ := $paths -}}
{{- if or (eq $path $priorPath) (hasPrefix (printf "%s/" $path) $priorPath) (hasPrefix (printf "%s/" $priorPath) $path) -}}
{{- fail "OBP106-WRITABLE-PATH-OVERLAP: writableVolumes mount paths must be unique and non-overlapping" -}}
{{- end -}}
{{- end -}}
{{- $_ := set $paths $path true -}}
{{- if or (not $volume.purpose) (gt (len $volume.purpose) 64) (not (regexMatch "^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$" $volume.purpose)) -}}
{{- fail (printf "OBP106-WRITABLE-PURPOSE: writableVolumes[%d].purpose must be a safe lower-case identifier" $index) -}}
{{- end -}}
{{- $hasEmptyDir := hasKey $volume "emptyDir" -}}
{{- $hasPvc := hasKey $volume "persistentVolumeClaim" -}}
{{- if eq $hasEmptyDir $hasPvc -}}{{- fail (printf "OBP106-WRITABLE-STORAGE: writableVolumes[%d] must select exactly one of emptyDir or persistentVolumeClaim" $index) -}}{{- end -}}
{{- if $hasEmptyDir -}}
{{- if or (not (kindIs "map" $volume.emptyDir)) (not ($volume.emptyDir.sizeLimit | default "")) -}}{{- fail (printf "OBP106-EMPTYDIR-LIMIT: writableVolumes[%d].emptyDir.sizeLimit is required" $index) -}}{{- end -}}
{{- else -}}
{{- if or (not (kindIs "map" $volume.persistentVolumeClaim)) (not ($volume.persistentVolumeClaim.claimName | default "")) (gt (len $volume.persistentVolumeClaim.claimName) 253) (not (regexMatch "^[a-z0-9]([a-z0-9-]*[a-z0-9])?$" $volume.persistentVolumeClaim.claimName)) -}}
{{- fail (printf "OBP106-PVC-CLAIM: writableVolumes[%d].persistentVolumeClaim.claimName must be a safe Kubernetes claim name" $index) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "oxibelt.containerSecurityContext" -}}
{{- $context := deepCopy .Values.securityContext -}}
{{- if eq (include "oxibelt.isOperationalProfileV2" .) "true" -}}{{- $_ := set $context "privileged" false -}}{{- end -}}
{{- toYaml $context -}}
{{- end -}}

{{- define "oxibelt.secretReferencesDigest" -}}
{{- $references := dict
      "publicTls" (dict "enabled" .Values.tls.enabled "secretName" .Values.tls.secretName)
      "quicHostKey" (dict "secretName" .Values.quic.hostKeySecretName "key" .Values.quic.hostKeySecretKey)
      "redis" .Values.sharedState.redisSecretProjections
      "adminToken" (dict "secretName" .Values.admin.tokenSecretName "key" .Values.admin.tokenSecretKey)
      "adminTls" (dict "secretName" .Values.admin.tls.secretName "certKey" .Values.admin.tls.certKey "privateKeyKey" .Values.admin.tls.privateKeyKey)
      "adminClientCa" (dict "secretName" .Values.admin.mtls.clientCaSecretName "key" .Values.admin.mtls.clientCaSecretKey) -}}
{{- printf "oxibelt-helm-secret-references-v1\n%s" ($references | toJson) | sha256sum -}}
{{- end -}}

{{- define "oxibelt.hardeningProfileDigest" -}}
{{- $hardening := dict "seccomp" .Values.runtimeHardening.seccomp "filesystemManifest" .Values.runtimeHardening.filesystemManifest "podSecurityContext" .Values.podSecurityContext "securityContext" .Values.securityContext "writableVolumes" .Values.writableVolumes -}}
{{- printf "oxibelt-helm-hardening-profile-v1\n%s" ($hardening | toJson) | sha256sum -}}
{{- end -}}

{{- define "oxibelt.profileReportContent" -}}
{{- $repository := .Values.image.repository | default (include "oxibelt.imageRepositoryForRole" .) -}}
{{- $destinations := list -}}
{{- range $destination := .Values.networkPolicy.egress.destinations -}}
{{- $destinations = append $destinations (dict "name" $destination.name "category" $destination.category "unrestrictedCidrs" ($destination.unrestrictedCidrs | default (dict "enabled" false "justification" ""))) -}}
{{- end -}}
{{- $fqdnDestinations := list -}}
{{- if .Values.networkPolicy.cilium.enabled -}}
{{- range $destination := .Values.networkPolicy.cilium.fqdnDestinations -}}
{{- $fqdnDestinations = append $fqdnDestinations (dict "name" $destination.name "category" $destination.category "matchNames" $destination.matchNames) -}}
{{- end -}}
{{- end -}}
{{- $mounts := list -}}
{{- range $volume := .Values.writableVolumes -}}
{{- $storage := ternary "emptyDir" "persistentVolumeClaim" (hasKey $volume "emptyDir") -}}
{{- $mounts = append $mounts (dict "name" $volume.name "mountPath" $volume.mountPath "purpose" $volume.purpose "storage" $storage) -}}
{{- end -}}
{{- $publicPorts := list -}}
{{- if .Values.service.ports.http.enabled -}}{{- $publicPorts = append $publicPorts "http" -}}{{- end -}}
{{- if .Values.service.ports.https.enabled -}}{{- $publicPorts = append $publicPorts "https" -}}{{- end -}}
{{- if .Values.service.ports.http3.enabled -}}{{- $publicPorts = append $publicPorts "http3" -}}{{- end -}}
{{- range $port := .Values.service.additionalPorts -}}{{- $publicPorts = append $publicPorts $port.name -}}{{- end -}}
{{- $tokenEnabled := eq (include "oxibelt.kubernetesApiAccessEnabled" .) "true" -}}
{{- $report := dict
      "schemaVersion" 1
      "profile" (dict "name" .Values.operationalProfile.name "version" (int .Values.operationalProfile.version) "wafMode" .Values.operationalProfile.wafMode)
      "image" (dict "role" .Values.image.role "reference" (printf "%s@%s" $repository .Values.image.digest) "configuredTag" .Values.image.tag)
      "podSecurity" (dict "hostNetwork" false "hostPID" false "hostIPC" false "runAsUser" 10001 "runAsGroup" 10001 "fsGroup" 10001 "allowPrivilegeEscalation" false "privileged" false "readOnlyRootFilesystem" true "capabilitiesDrop" (list "ALL"))
      "seccomp" (dict "type" .Values.podSecurityContext.seccompProfile.type "expectation" .Values.runtimeHardening.seccomp.expectation "externalAssertionConfigured" (ne .Values.runtimeHardening.seccomp.externalProfile.identity ""))
      "serviceAccountToken" (dict "ambient" false "projected" $tokenEnabled "audience" (ternary .Values.kubernetesDiscovery.serviceAccountToken.audience "" $tokenEnabled) "expirationSeconds" (ternary (int .Values.kubernetesDiscovery.serviceAccountToken.expirationSeconds) 0 $tokenEnabled))
      "network" (dict "defaultDenyIngress" true "defaultDenyEgress" true "ingress" (dict "public" (dict "allowAll" .Values.networkPolicy.ingress.public.allowAll "peerCount" (len .Values.networkPolicy.ingress.public.from) "ports" $publicPorts) "metrics" (dict "peerCount" (len .Values.networkPolicy.ingress.metrics.from)) "admin" (dict "peerCount" (len .Values.networkPolicy.ingress.admin.from))) "dnsEgressEnabled" .Values.networkPolicy.egress.dns.enabled "egressDestinations" $destinations "fqdnDestinations" $fqdnDestinations)
      "writableMounts" $mounts
      "availability" (dict "workloadKind" .Values.workload.kind "podDisruptionBudget" .Values.podDisruptionBudget "podDistribution" .Values.podDistribution)
      "artifactIdentities" (dict "configDigest" (include "oxibelt.configDigest" .) "oxiruleDigest" (include "oxibelt.oxiruleConfigMapDigest" .) "secretReferencesDigest" (include "oxibelt.secretReferencesDigest" .) "tlsReferences" (dict "publicSecretName" .Values.tls.secretName "quicHostKeySecretName" .Values.quic.hostKeySecretName) "hardeningProfileDigest" (include "oxibelt.hardeningProfileDigest" .) "filesystemManifestExpectationPresent" true "filesystemManifestDigestWithheld" true)
      "supplyChainBundle" (dict "payloadDigest" .Values.supplyChainAdmission.bundle.payloadDigest "keyId" .Values.supplyChainAdmission.bundle.keyId "imageReference" (printf "%s@%s" $repository .Values.image.digest) "admissionRequired" true)
      "unmetRequirements" (list) -}}
{{- $report | toPrettyJson -}}
{{- end -}}

{{- define "oxibelt.profileReportDigest" -}}
{{- printf "oxibelt-helm-profile-report-v1\n%s" (include "oxibelt.profileReportContent" .) | sha256sum -}}
{{- end -}}

{{- define "oxibelt.profileReportName" -}}
{{- printf "%s-profile-report-%s" (include "oxibelt.name" . | trunc 35 | trimSuffix "-") (include "oxibelt.profileReportDigest" . | trunc 12) -}}
{{- end -}}
