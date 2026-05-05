import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const PackageDirectory = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const SourceDirectory = resolve(PackageDirectory, 'source')
const RepositoryDirectory = resolve(PackageDirectory, '../..')
const OutputPath = resolve(RepositoryDirectory, 'source/assets/person-proof-challenge.html')

const ReadUtf8 = (InputPath: string): Promise<string> => readFile(InputPath, 'utf8')

const EscapeClosingScript = (ScriptText: string): string => ScriptText.replaceAll('</script', '<\\/script')

const Build = async (): Promise<void> => {
  const TemplateText = await ReadUtf8(resolve(SourceDirectory, 'challenge.template.html'))
  const StyleText = await ReadUtf8(resolve(SourceDirectory, 'challenge.css'))
  const ScriptText = await ReadUtf8(resolve(PackageDirectory, 'dist/challenge.js'))
  const HtmlText = TemplateText
    .replace('<!-- OXIBELT_STYLE -->', `<style nonce="__CSP_NONCE__">\n${StyleText}\n</style>`)
    .replace('<!-- OXIBELT_SCRIPT -->', `<script type="module" nonce="__CSP_NONCE__">\n${EscapeClosingScript(ScriptText)}\n</script>`)

  await mkdir(dirname(OutputPath), { recursive: true })
  await writeFile(OutputPath, HtmlText, 'utf8')
}

await Build()
