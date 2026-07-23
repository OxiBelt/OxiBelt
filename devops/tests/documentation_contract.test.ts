import * as Assert from 'node:assert/strict'
import * as Fs from 'node:fs'
import * as Path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { BuildImageRoleContracts } from '../sources/docker_image_release.js'

type ImageRoleDocumentation = {
  Label: string
  Image: string
  Binaries: string[]
}

const RepoRoot = Path.resolve(Path.dirname(fileURLToPath(import.meta.url)), '../..')

function ReadRepositoryFile(RelativePath: string): string {
  return Fs.readFileSync(Path.join(RepoRoot, RelativePath), 'utf8')
}

function MarkdownCodeValues(Value: string): string[] {
  return [...Value.matchAll(/`([^`]+)`/g)].map(Match => Match[1])
}

function MarkdownCodeValue(Value: string, Label: string): string {
  const Values = MarkdownCodeValues(Value)
  Assert.equal(Values.length, 1, `${Label} must contain exactly one Markdown code value`)
  return Values[0]
}

function ParseMarkdownTable(
  Document: string,
  SectionMarker: string,
  ExpectedHeaders: string[]
): Array<Record<string, string>> {
  const MarkerPosition = Document.indexOf(SectionMarker)
  Assert.notEqual(MarkerPosition, -1, `documentation must retain section marker ${SectionMarker}`)
  const Lines = Document.slice(MarkerPosition + SectionMarker.length).split('\n')
  const HeaderPosition = Lines.findIndex(Line => Line.trimStart().startsWith('|'))
  Assert.notEqual(HeaderPosition, -1, `documentation after ${SectionMarker} must contain a Markdown table`)

  const BoundedTableLines: string[] = []
  for (const Line of Lines.slice(HeaderPosition)) {
    if (!Line.trimStart().startsWith('|')) {
      break
    }
    BoundedTableLines.push(Line)
  }
  Assert.ok(BoundedTableLines.length >= 3, `documentation after ${SectionMarker} must contain table rows`)

  const Cells = (Line: string): string[] => Line
    .trim()
    .replace(/^\|/, '')
    .replace(/\|$/, '')
    .split('|')
    .map(Cell => Cell.trim())
  const Headers = Cells(BoundedTableLines[0])
  Assert.deepEqual(Headers, ExpectedHeaders)
  const Separator = Cells(BoundedTableLines[1])
  Assert.equal(Separator.length, Headers.length)
  Assert.ok(Separator.every(Cell => /^:?-{3,}:?$/.test(Cell)), 'Markdown table separator is invalid')

  return BoundedTableLines.slice(2).map(Line => {
    const Values = Cells(Line)
    Assert.equal(Values.length, Headers.length, `Markdown table row has the wrong number of cells: ${Line}`)
    return Object.fromEntries(Headers.map((Header, Index) => [Header, Values[Index]]))
  })
}

function SortedRoleDocumentation(Values: ImageRoleDocumentation[]): ImageRoleDocumentation[] {
  return Values
    .map(Value => ({ ...Value, Binaries: [...Value.Binaries] }))
    .sort((Left, Right) => Left.Label.localeCompare(Right.Label))
}

test('public image-role documentation matches the canonical release-plan contracts', () => {
  const Canonical = BuildImageRoleContracts()
  const ExpectedReadme = SortedRoleDocumentation(Canonical.map(Contract => ({
    Label: Contract.dockerTarget,
    Image: Contract.image,
    Binaries: Contract.binaries
  })))

  const ReadmeRows = ParseMarkdownTable(
    ReadRepositoryFile('README.md'),
    'Official releases publish these role-specific repositories from the same\nversion and source revision:',
    ['Repository', 'Docker target', 'Executable inventory', 'Purpose']
  )
  const Readme = SortedRoleDocumentation(ReadmeRows.map(Row => ({
    Label: MarkdownCodeValue(Row['Docker target'], 'README Docker target'),
    Image: MarkdownCodeValue(Row.Repository, 'README repository'),
    Binaries: MarkdownCodeValues(Row['Executable inventory'])
  })))
  Assert.deepEqual(
    Readme,
    ExpectedReadme,
    'README image-role table must match BuildImageRoleContracts()'
  )

  const ExpectedSupplyChain = SortedRoleDocumentation(Canonical.map(Contract => ({
    Label: Contract.role,
    Image: Contract.image,
    Binaries: Contract.binaries
  })))
  const SupplyChainRows = ParseMarkdownTable(
    ReadRepositoryFile('docs/SupplyChain.md'),
    'Only the following repositories are official OxiBelt image sources:',
    ['Role', 'OCI repository', 'Expected executable inventory']
  )
  const SupplyChain = SortedRoleDocumentation(SupplyChainRows.map(Row => ({
    Label: MarkdownCodeValue(Row.Role, 'SupplyChain role'),
    Image: MarkdownCodeValue(Row['OCI repository'], 'SupplyChain OCI repository'),
    Binaries: MarkdownCodeValues(Row['Expected executable inventory'])
  })))
  Assert.deepEqual(
    SupplyChain,
    ExpectedSupplyChain,
    'docs/SupplyChain.md image-role table must match BuildImageRoleContracts()'
  )

  const AdminApi = ReadRepositoryFile('docs/AdminAPI.md')
  const Availability = /Admin API image roles:\s+with Admin and its OpenAPI asset:\s+([^;]+);\s+without Admin and its OpenAPI asset:\s+([^.]+)\./s.exec(AdminApi)
  Assert.notEqual(
    Availability,
    null,
    'docs/AdminAPI.md must retain the explicit Admin API image-role statement'
  )
  const WithAdmin = MarkdownCodeValues(Availability?.[1] ?? '').sort()
  const WithoutAdmin = MarkdownCodeValues(Availability?.[2] ?? '').sort()
  const ExpectedWithAdmin = Canonical
    .filter(Contract => Contract.embeddedAssets.includes('admin-openapi'))
    .map(Contract => Contract.role)
    .sort()
  const ExpectedWithoutAdmin = Canonical
    .filter(Contract => !Contract.embeddedAssets.includes('admin-openapi'))
    .map(Contract => Contract.role)
    .sort()
  Assert.deepEqual(
    WithAdmin,
    ExpectedWithAdmin,
    'Admin API availability must follow release roles embedding admin-openapi'
  )
  Assert.deepEqual(
    WithoutAdmin,
    ExpectedWithoutAdmin,
    'Admin API unavailability must follow release roles without admin-openapi'
  )
})
