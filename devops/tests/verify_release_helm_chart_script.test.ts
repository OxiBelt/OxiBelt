import * as Assert from 'node:assert/strict'
import * as Fs from 'node:fs'
import * as Os from 'node:os'
import * as Path from 'node:path'
import * as Crypto from 'node:crypto'
import { execFileSync } from 'node:child_process'
import test from 'node:test'

const Root = Path.resolve(Path.dirname(new URL(import.meta.url).pathname), '../..')
const Script = Path.join(Root, 'tests/scripts/verify-release-helm-chart.sh')

function WriteExecutable(PathValue: string, Content: string): void { Fs.writeFileSync(PathValue, `#!/usr/bin/env bash\nset -euo pipefail\n${Content}\n`, { mode: 0o755 }) }

function RunScript(Arguments: string[], Environment: NodeJS.ProcessEnv): void {
  try { execFileSync('bash', [Script, ...Arguments], { env: Environment, stdio: 'pipe' }) } catch (ErrorValue) {
    const ErrorRecord = ErrorValue as NodeJS.ErrnoException
    const Status = (ErrorValue as Record<string, unknown>)['status']
    if (ErrorRecord.code === 'EPERM' && Status === 0) return
    const StandardError = (ErrorValue as Record<string, unknown>)['stderr']
    if (Buffer.isBuffer(StandardError)) throw new Error(StandardError.toString('utf8'))
    throw ErrorValue
  }
}

test('read-only Helm OCI verifier accepts injected consumption tools and rejects mutable input', () => {
  const Directory = Fs.mkdtempSync(Path.join(Os.tmpdir(), 'oxibelt-helm-oci-script-'))
  try {
    const Bin = Path.join(Directory, 'bin'); const Work = Path.join(Directory, 'work'); const RebuildWork = Path.join(Directory, 'rebuild-work'); const Archive = Path.join(Directory, 'oxibelt-1.2.3.tgz'); const RegistryArchive = Path.join(Directory, 'registry-oxibelt-1.2.3.tgz'); const CommandLog = Path.join(Directory, 'commands.log')
    Fs.mkdirSync(Bin); Fs.mkdirSync(Work); Fs.mkdirSync(RebuildWork); Fs.writeFileSync(Archive, 'chart'); Fs.copyFileSync(Archive, RegistryArchive)
    const ArchiveSha = Crypto.createHash('sha256').update('chart').digest('hex')
    const Config = Path.join(Directory, 'config.json'); const ConfigText = '{"chart":"oci"}'; Fs.writeFileSync(Config, ConfigText)
    const ConfigDigest = Crypto.createHash('sha256').update(ConfigText).digest('hex')
    const Manifest = Path.join(Directory, 'manifest.json')
    const ManifestText = `{\n  "schemaVersion": 2,\n  "config": {"digest":"sha256:${ConfigDigest}","mediaType":"application/vnd.cncf.helm.config.v1+json","size":${Buffer.byteLength(ConfigText)}},\n  "layers": [{"digest":"sha256:${ArchiveSha}","mediaType":"application/vnd.cncf.helm.chart.content.v1.tar+gzip","size":5}]\n}\n`
    Fs.writeFileSync(Manifest, ManifestText)
    const Digest = `sha256:${Crypto.createHash('sha256').update(ManifestText).digest('hex')}`
    const Helm4Manifest = Path.join(Directory, 'helm4-manifest.json')
    const Helm4ManifestText = `{\n  "schemaVersion": 2,\n  "config": {"digest":"sha256:${ConfigDigest}","mediaType":"application/vnd.cncf.helm.config.v1+json","size":${Buffer.byteLength(ConfigText)}},\n  "layers": [{"digest":"sha256:${ArchiveSha}","mediaType":"application/vnd.cncf.helm.chart.content.v1.tar+gzip","size":5}],\n  "annotations": {"org.opencontainers.image.created":"2026-08-18T11:25:22Z","org.opencontainers.image.description":"OxiBelt reverse proxy and WAF data plane","org.opencontainers.image.title":"oxibelt","org.opencontainers.image.version":"1.2.3","oxibelt.dev/feature-status":"experimental","oxibelt.dev/kubernetes-support-policy":"1"}\n}\n`
    Fs.writeFileSync(Helm4Manifest, Helm4ManifestText)
    const Helm4Digest = `sha256:${Crypto.createHash('sha256').update(Helm4ManifestText).digest('hex')}`
    const WriteManifestVariant = (name: string, text: string) => {
      const PathValue = Path.join(Directory, `${name}-manifest.json`)
      Fs.writeFileSync(PathValue, text)
      return { path: PathValue, digest: `sha256:${Crypto.createHash('sha256').update(text).digest('hex')}` }
    }
    const PartialAnnotations = WriteManifestVariant('partial-annotations', Helm4ManifestText.replace('"org.opencontainers.image.created":"2026-08-18T11:25:22Z",', ''))
    const ExtraAnnotations = WriteManifestVariant('extra-annotations', Helm4ManifestText.replace('"oxibelt.dev/kubernetes-support-policy":"1"', '"oxibelt.dev/kubernetes-support-policy":"1","unexpected":"value"'))
    const SubstitutedAnnotations = WriteManifestVariant('substituted-annotations', Helm4ManifestText.replace('"org.opencontainers.image.title":"oxibelt"', '"org.opencontainers.image.title":"substituted"'))
    const InvalidCreated = WriteManifestVariant('invalid-created', Helm4ManifestText.replace('2026-08-18T11:25:22Z', '2026-02-31T11:25:22Z'))
    const WrongVersion = WriteManifestVariant('wrong-version', Helm4ManifestText.replace('"org.opencontainers.image.version":"1.2.3"', '"org.opencontainers.image.version":"1.2.4"'))
    const WrongPolicy = WriteManifestVariant('wrong-policy', Helm4ManifestText.replace('"oxibelt.dev/feature-status":"experimental"', '"oxibelt.dev/feature-status":"stable"'))
    WriteExecutable(Path.join(Bin, 'helm'), `
[[ -z "\${COMMAND_LOG:-}" ]] || printf 'helm:%s\\n' "$*" >>"\${COMMAND_LOG}"
if [[ "$1 $2" == "version --short" ]]; then echo v3.21.4; exit 0; fi
case "$1" in
  show) [[ "$2" == chart && "$3" == */oxibelt-1.2.3.tgz ]] || exit 8; if [[ "\${APP_VERSION_QUOTED:-}" == 1 ]]; then app_version='"1.2.3"'; else app_version='1.2.3'; fi; printf 'apiVersion: v2\\nname: oxibelt\\nversion: 1.2.3\\nappVersion: %s\\nannotations:\\n  oxibelt.dev/feature-status: experimental\\n  oxibelt.dev/kubernetes-support-policy: "1"\\n' "$app_version" ;;
  lint|template) : ;;
  install) [[ " $* " == *" --dry-run=client "* ]] || exit 7 ;;
  *) exit 9 ;;
esac`)
    WriteExecutable(Path.join(Bin, 'oras'), `
[[ -z "\${COMMAND_LOG:-}" ]] || printf 'oras:%s\\n' "$*" >>"\${COMMAND_LOG}"
if [[ "$1" == version ]]; then echo "\${ORAS_VERSION:-Version: 1.3.4}"; exit 0; fi
case "\${MANIFEST_VARIANT:-legacy}" in
  legacy) active_manifest='${Manifest}'; active_digest='${Digest}' ;;
  helm4) active_manifest='${Helm4Manifest}'; active_digest='${Helm4Digest}' ;;
  partial-annotations) active_manifest='${PartialAnnotations.path}'; active_digest='${PartialAnnotations.digest}' ;;
  extra-annotations) active_manifest='${ExtraAnnotations.path}'; active_digest='${ExtraAnnotations.digest}' ;;
  substituted-annotations) active_manifest='${SubstitutedAnnotations.path}'; active_digest='${SubstitutedAnnotations.digest}' ;;
  invalid-created) active_manifest='${InvalidCreated.path}'; active_digest='${InvalidCreated.digest}' ;;
  wrong-version) active_manifest='${WrongVersion.path}'; active_digest='${WrongVersion.digest}' ;;
  wrong-policy) active_manifest='${WrongPolicy.path}'; active_digest='${WrongPolicy.digest}' ;;
  *) exit 6 ;;
esac
if [[ "$1 $2" == "blob fetch" ]]; then
  if [[ "$5" == *'@sha256:${ConfigDigest}' ]]; then
    case "\${BAD_CONFIG:-}" in
      1) printf 'substituted' >"$4" ;;
      oversize) printf '%*s' $((128 * 1024 + 1)) '' >"$4" ;;
      *) cp "${Config}" "$4" ;;
    esac
  elif [[ "$5" == *'@sha256:${ArchiveSha}' ]]; then
    if [[ "\${BAD_LAYER:-}" == oversize ]]; then printf '%*s' $((16 * 1024 * 1024 + 1)) '' >"$4"; else cp "${RegistryArchive}" "$4"; fi
  else exit 6
  fi
  exit 0
fi
[[ "$1 $2" == "manifest fetch" ]] || exit 6
if [[ "$3" == "--descriptor" ]]; then
  [[ "$4" == *':1.2.3' || "$4" == *"@\${active_digest}" ]] || exit 6
  [[ "\${MUTATE_EXPECTED:-}" != 1 ]] || printf 'changed' >"\${EXPECTED_ARCHIVE}"
  case "\${BAD_DESCRIPTOR:-}" in
    extra) printf '{"digest":"${Digest}","extra":true,"mediaType":"application/vnd.oci.image.manifest.v1+json","size":${Buffer.byteLength(ManifestText)}}\\n' ;;
    duplicate) printf '{"digest":"${Digest}","digest":"${Digest}","mediaType":"application/vnd.oci.image.manifest.v1+json","size":${Buffer.byteLength(ManifestText)}}\\n' ;;
    size) printf '{"digest":"${Digest}","mediaType":"application/vnd.oci.image.manifest.v1+json","size":1}\\n' ;;
    digest) printf '{"digest":"sha256:${'0'.repeat(64)}","mediaType":"application/vnd.oci.image.manifest.v1+json","size":${Buffer.byteLength(ManifestText)}}\\n' ;;
    tag) [[ "$4" == *':1.2.3' ]] && printf '{"digest":"sha256:${'0'.repeat(64)}","mediaType":"application/vnd.oci.image.manifest.v1+json","size":%s}\\n' "$(stat -c%s "\${active_manifest}")" || printf '{"digest":"%s","mediaType":"application/vnd.oci.image.manifest.v1+json","size":%s}\\n' "\${active_digest}" "$(stat -c%s "\${active_manifest}")" ;;
    *) printf '{"digest":"%s","mediaType":"application/vnd.oci.image.manifest.v1+json","size":%s}\\n' "\${active_digest}" "$(stat -c%s "\${active_manifest}")" ;;
  esac
else
  [[ "$5" == *"@\${active_digest}" ]] || exit 6
  if [[ "\${BAD_MANIFEST:-}" == oversize ]]; then printf '%*s' $((128 * 1024 + 1)) '' >"$4"; else cp "\${active_manifest}" "$4"; fi
fi`)
    const Environment = { ...process.env, COMMAND_LOG: CommandLog, HELM_BIN: Path.join(Bin, 'helm'), ORAS_BIN: Path.join(Bin, 'oras') }
    const Arguments = (WorkDirectory: string, Version = '1.2.3', ExpectedDigest = Digest) => ['--mode', 'consume', '--repository', 'ghcr.io/oxibelt/charts/oxibelt', '--digest', ExpectedDigest, '--version', Version, '--chart-name', 'oxibelt', '--expected-archive', Archive, '--work-directory', WorkDirectory]
    RunScript(Arguments(Work), Environment)
    const Helm4Work = Path.join(Directory, 'helm4-work'); Fs.mkdirSync(Helm4Work)
    Assert.doesNotThrow(() => RunScript(Arguments(Helm4Work, '1.2.3', Helm4Digest), { ...Environment, MANIFEST_VARIANT: 'helm4' }))
    for (const [Variant, VariantDigest, Expected] of [
      ['partial-annotations', PartialAnnotations.digest, /unexpected JSON keys/],
      ['extra-annotations', ExtraAnnotations.digest, /unexpected JSON keys/],
      ['substituted-annotations', SubstitutedAnnotations.digest, /manifest annotations/],
      ['invalid-created', InvalidCreated.digest, /manifest annotations/],
      ['wrong-version', WrongVersion.digest, /manifest annotations/],
      ['wrong-policy', WrongPolicy.digest, /manifest annotations/]
    ] as const) {
      const VariantWork = Path.join(Directory, `${Variant}-work`); Fs.mkdirSync(VariantWork)
      Assert.throws(() => RunScript(Arguments(VariantWork, '1.2.3', VariantDigest), { ...Environment, MANIFEST_VARIANT: Variant }), Expected)
    }
    const Commands = Fs.readFileSync(CommandLog, 'utf8')
    Assert.match(Commands, /oras:manifest fetch --descriptor ghcr\.io\/oxibelt\/charts\/oxibelt:1\.2\.3/)
    Assert.match(Commands, new RegExp(`oras:manifest fetch --descriptor ghcr\\.io/oxibelt/charts/oxibelt@${Digest}`))
    Assert.match(Commands, new RegExp(`oras:blob fetch --output .* ghcr\\.io/oxibelt/charts/oxibelt@sha256:${ConfigDigest}`))
    Assert.match(Commands, new RegExp(`oras:blob fetch --output .* ghcr\\.io/oxibelt/charts/oxibelt@sha256:${ArchiveSha}`))
    Assert.match(Commands, /helm:show chart .*\/oxibelt-1\.2\.3\.tgz/)
    Assert.match(Commands, /helm:install .*--dry-run=client/)
    Assert.doesNotMatch(Commands, /helm:pull/)
    Assert.throws(() => RunScript(Arguments(Directory), Environment), /work directory must be empty/)
    Assert.throws(() => RunScript(['--mode', 'rebuild', ...Arguments(RebuildWork).slice(2), '--workspace-path', Directory, '--release-ref', 'refs/tags/1.2.3', '--revision', 'a'.repeat(40)], Environment), /byte rebuild requires Helm v4\.2\.4/)
    for (const [Name, Expected] of [['extra', /unexpected JSON keys/], ['duplicate', /duplicate JSON key/], ['size', /exact raw manifest bytes/], ['digest', /exact raw manifest bytes/]] as const) {
      const BadDescriptorWork = Path.join(Directory, `bad-descriptor-${Name}-work`); Fs.mkdirSync(BadDescriptorWork)
      Assert.throws(() => RunScript(Arguments(BadDescriptorWork), { ...Environment, BAD_DESCRIPTOR: Name }), Expected)
    }
    const BadTagDescriptorWork = Path.join(Directory, 'bad-tag-descriptor-work'); Fs.mkdirSync(BadTagDescriptorWork)
    Assert.throws(() => RunScript(Arguments(BadTagDescriptorWork), { ...Environment, BAD_DESCRIPTOR: 'tag' }), /tag and immutable manifest descriptors/)
    const BadConfigWork = Path.join(Directory, 'bad-config-work'); Fs.mkdirSync(BadConfigWork)
    Assert.throws(() => RunScript(Arguments(BadConfigWork), { ...Environment, COMMAND_LOG: '/dev/null', BAD_CONFIG: '1' }), /config blob does not match/)
    for (const [Name, Override] of [
      ['manifest', { BAD_MANIFEST: 'oversize' }],
      ['config', { BAD_CONFIG: 'oversize' }],
      ['layer', { BAD_LAYER: 'oversize' }]
    ] as const) {
      const BoundedOutputWork = Path.join(Directory, `bounded-${Name}-work`); Fs.mkdirSync(BoundedOutputWork)
      Assert.throws(() => RunScript(Arguments(BoundedOutputWork), { ...Environment, COMMAND_LOG: '/dev/null', ...Override }), /bounded output contract/)
    }
    const RcWork = Path.join(Directory, 'rc-work'); Fs.mkdirSync(RcWork)
    Assert.throws(() => RunScript(Arguments(RcWork, '1.2.3-rc.1'), Environment), /usage/)
    const DuplicateWork = Path.join(Directory, 'duplicate-work'); Fs.mkdirSync(DuplicateWork)
    Assert.throws(() => RunScript([...Arguments(DuplicateWork), '--mode', 'consume'], Environment), /usage/)
    const OrasVersionWork = Path.join(Directory, 'oras-version-work'); Fs.mkdirSync(OrasVersionWork)
    Assert.throws(() => RunScript(Arguments(OrasVersionWork), { ...Environment, ORAS_VERSION: 'Version: 9.9.9' }), /approved 1\.3\.4/)
    const OversizedArchive = Path.join(Directory, 'oversized.tgz'); Fs.writeFileSync(OversizedArchive, Buffer.alloc(16 * 1024 * 1024 + 1))
    const OversizedWork = Path.join(Directory, 'oversized-work'); Fs.mkdirSync(OversizedWork)
    Assert.throws(() => RunScript([...Arguments(OversizedWork).map(Value => Value === Archive ? OversizedArchive : Value)], Environment), /source archive is outside/)
    const QuotedWork = Path.join(Directory, 'quoted-work'); Fs.mkdirSync(QuotedWork)
    Assert.doesNotThrow(() => RunScript(Arguments(QuotedWork), { ...Environment, APP_VERSION_QUOTED: '1' }))
    const ParentAlias = Path.join(Directory, 'parent-alias'); Fs.symlinkSync(Directory, ParentAlias)
    const ParentAliasWork = Path.join(Directory, 'parent-alias-work'); Fs.mkdirSync(ParentAliasWork)
    Assert.throws(() => RunScript([...Arguments(ParentAliasWork).map(Value => Value === Archive ? Path.join(ParentAlias, Path.basename(Archive)) : Value)], Environment), /must not contain symlinks/)
    const WorkAlias = Path.join(Directory, 'work-alias'); Fs.symlinkSync(Work, WorkAlias)
    Assert.throws(() => RunScript(Arguments(WorkAlias), Environment), /must not contain symlinks/)
    const SnapshotWork = Path.join(Directory, 'snapshot-work'); Fs.mkdirSync(SnapshotWork)
    Assert.doesNotThrow(() => RunScript(Arguments(SnapshotWork), { ...Environment, MUTATE_EXPECTED: '1', EXPECTED_ARCHIVE: Archive }))
    Assert.equal(Fs.readFileSync(Archive, 'utf8'), 'changed')
  } finally { Fs.rmSync(Directory, { recursive: true, force: true }) }
})
