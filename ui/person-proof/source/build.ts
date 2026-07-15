import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const PackageDirectory = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const SourceDirectory = resolve(PackageDirectory, 'source')
const RepositoryDirectory = resolve(PackageDirectory, '../..')
const OutputPath = resolve(RepositoryDirectory, 'source/assets/person-proof-challenge.html')

const ReadUtf8 = (InputPath: string): Promise<string> => readFile(InputPath, 'utf8')

const EscapeClosingScript = (ScriptText: string): string => ScriptText.replaceAll('</script', '<\\/script')

const ReplaceExactlyOnce = (Input: string, Marker: string, Replacement: string): string => {
  const FirstIndex = Input.indexOf(Marker)
  if (FirstIndex < 0 || Input.indexOf(Marker, FirstIndex + Marker.length) >= 0) {
    throw new Error(`expected exactly one ${Marker} build marker`)
  }
  return `${Input.slice(0, FirstIndex)}${Replacement}${Input.slice(FirstIndex + Marker.length)}`
}

const Build = async (): Promise<void> => {
  const TemplateText = await ReadUtf8(resolve(SourceDirectory, 'challenge.template.html'))
  const StyleText = await ReadUtf8(resolve(SourceDirectory, 'challenge.css'))
  const ScriptText = await ReadUtf8(resolve(PackageDirectory, 'dist/challenge.js'))
  const WithStyle = ReplaceExactlyOnce(
    TemplateText,
    '<!-- OXIBELT_STYLE -->',
    `<style nonce="__CSP_NONCE__">\n${StyleText}\n</style>`,
  )
  const HtmlText = ReplaceExactlyOnce(
    WithStyle,
    '<!-- OXIBELT_SCRIPT -->',
    `<script type="module" nonce="__CSP_NONCE__">\n${EscapeClosingScript(ScriptText)}\n</script>`,
  )

  await mkdir(dirname(OutputPath), { recursive: true })
  await writeFile(OutputPath, HtmlText, 'utf8')
}

await Build()
