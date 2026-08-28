import Assert from 'node:assert/strict'
import { readFileSync, rmSync, writeFileSync, mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import Path from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'
import test from 'node:test'

const RepositoryRoot = Path.resolve(Path.dirname(fileURLToPath(import.meta.url)), '../..')
const Oxlint = Path.join(RepositoryRoot, 'node_modules', '.bin', 'oxlint')
const Plugin = Path.join(RepositoryRoot, 'devops', 'oxlint-plugin.mjs')

const LintFixture = (Source: string, Rules: Record<string, 'error'>, Fix = false) => {
  const Directory = mkdtempSync(Path.join(tmpdir(), 'oxibelt-oxlint-plugin-'))
  const SourcePath = Path.join(Directory, 'fixture.ts')
  const ConfigPath = Path.join(Directory, '.oxlintrc.json')
  writeFileSync(SourcePath, Source)
  writeFileSync(ConfigPath, JSON.stringify({
    plugins: [],
    jsPlugins: [Plugin],
    categories: { correctness: 'off' },
    rules: Rules,
  }))

  const Arguments = ['-c', ConfigPath, SourcePath]
  if (Fix) Arguments.unshift('--fix')
  const Result = spawnSync(Oxlint, Arguments, { encoding: 'utf8' })
  const Output = `${Result.stdout}${Result.stderr}`
  const ResultSource = readFileSync(SourcePath, 'utf8')
  rmSync(Directory, { recursive: true, force: true })
  return { Output, ResultSource, Status: Result.status }
}

test('pascal-case enforces declaration selectors and format contract', () => {
  const Valid = LintFixture(`
import { lower as ImportedValue } from './external.js'
const $Value = 1
const { lower: RenamedValue, Nested: { lower: InnerValue }, ...RestValue } = ExternalValue
function Handler({ lower: BoundValue } = ExternalValue, ...MoreValues: unknown[]) {}
try {} catch (lowerError) {}
const ObjectValue = { lower: 1 }
ObjectValue.lower
class ExampleValue {
  ['lowerMethod']() {}
  #PrivateValue = 1
  PropertyValue = 1
  ['lower'] = 2
  constructor(public ParameterValue: number) {}
  get AccessorValue() { return 1 }
  MethodValue() {}
}
abstract class AbstractValue {
  abstract MethodValue(): void
}
interface TypeValue {
  PropertyValue: string
  ['lower']: string
  ['lowerMethod'](): void
  MethodValue(): void
}
void ImportedValue
void $Value
void RenamedValue
void InnerValue
void RestValue
void Handler
void ObjectValue
void ExampleValue
`, { 'oxibelt/pascal-case': 'error' })
  Assert.equal(Valid.Status, 0, Valid.Output)

  const Invalid = LintFixture(`
const lower_value = 1
function lowerFunction(lowerParameter: string) {}
const ArrowValue = (lowerArrow: string) => lowerArrow
class ExampleValue {
  #lowerPrivate = 1
  lowerProperty = 1
  constructor(public lowerParameterProperty: number) {}
  get lowerGetter() { return 1 }
  set lowerSetter(Value: number) {}
  lowerMethod() {}
}
abstract class AbstractValue {
  abstract lowerAbstractMethod(): void
}
interface TypeValue {
  lowerTypeProperty: string
  lowerTypeMethod(): void
}
`, { 'oxibelt/pascal-case': 'error' })
  Assert.equal(Invalid.Status, 1, Invalid.Output)
  Assert.match(Invalid.Output, /oxibelt\(pascal-case\)/)
  Assert.match(Invalid.Output, /Identifier 'lowerGetter' must be in PascalCase/)
  Assert.match(Invalid.Output, /Identifier 'lowerSetter' must be in PascalCase/)
  Assert.match(Invalid.Output, /Identifier 'lowerMethod' must be in PascalCase/)
  Assert.match(Invalid.Output, /Identifier 'lowerAbstractMethod' must be in PascalCase/)
  Assert.match(Invalid.Output, /Identifier 'lowerTypeMethod' must be in PascalCase/)
})

test('pascal-case honors narrow Oxlint suppression directives', () => {
  const Result = LintFixture(`
/* oxlint-disable oxibelt/pascal-case -- External wire name. */
const lowerWireName = 1
/* oxlint-enable oxibelt/pascal-case */
const LocalName = lowerWireName
void LocalName
`, { 'oxibelt/pascal-case': 'error' })
  Assert.equal(Result.Status, 0, Result.Output)
})

test('no-semicolons rejects only safely removable statement terminators', () => {
  const Valid = LintFixture(`
for (let Index = 0; Index < 1; Index += 1) {}
const First = () => {}; const Second = First
const Callable = () => {}
;(Callable)()
class ExampleValue {
  get;
  value() {}
}
void Second
`, { 'oxibelt/no-semicolons': 'error' })
  Assert.equal(Valid.Status, 0, Valid.Output)

  const Invalid = LintFixture('const Value = 1;\nvoid Value\n', { 'oxibelt/no-semicolons': 'error' })
  Assert.equal(Invalid.Status, 1, Invalid.Output)
  Assert.match(Invalid.Output, /oxibelt\(no-semicolons\)/)
})

test('single-quotes rejects double quotes and simple templates', () => {
  const Valid = LintFixture(`
const Name = 'value'
const Interpolated = \`value: \${Name}\`
const Tagged = String.raw\`value\`
void Interpolated
void Tagged
`, { 'oxibelt/single-quotes': 'error' })
  Assert.equal(Valid.Status, 0, Valid.Output)

  const DoubleQuoted = LintFixture('"use strict"\nconst Value = "can\\\'t"\nvoid Value\n', { 'oxibelt/single-quotes': 'error' })
  Assert.equal(DoubleQuoted.Status, 1, DoubleQuoted.Output)
  Assert.match(DoubleQuoted.Output, /oxibelt\(single-quotes\)/)

  const SimpleTemplate = LintFixture('const Value = `value`\nvoid Value\n', { 'oxibelt/single-quotes': 'error' })
  Assert.equal(SimpleTemplate.Status, 1, SimpleTemplate.Output)
})

test('custom compatibility rules remain diagnostic-only', () => {
  const Source = 'const lower = "value";\nvoid lower\n'
  const Result = LintFixture(Source, {
    'oxibelt/no-semicolons': 'error',
    'oxibelt/pascal-case': 'error',
    'oxibelt/single-quotes': 'error',
  }, true)
  Assert.equal(Result.Status, 1, Result.Output)
  Assert.equal(Result.ResultSource, Source)
})
