const fs = require('node:fs')
const path = require('node:path')
const { execSync } = require('node:child_process')
const { gzipSync } = require('node:zlib')
const amaro = require('amaro')

const PUBLIC_ENTRIES = [
  'index',
  'v1/local',
  'v1/public',
  'v2/local',
  'v2/public',
  'v3/local',
  'v3/public',
  'v4/local',
  'v4/public',
]

const runtimeSources = getRuntimeSources()

for (const entry of PUBLIC_ENTRIES) {
  const source = `${entry}.ts`
  if (!fs.existsSync(source)) throw new Error(`${source} not found`)
}

execSync('npx tsc', { stdio: 'inherit' })
execSync('npx tsc -p ./examples/noble-suite', { stdio: 'inherit' })

for (const source of runtimeSources) {
  const output = source.replace(/\.ts$/, '.js')
  const input = fs.readFileSync(source, 'utf8')
  let js = amaro.transformSync(input, { mode: 'strip-only' }).code
  js = rewriteRelativeTypeScriptSpecifiers(js)

  fs.mkdirSync(path.dirname(output), { recursive: true })
  fs.writeFileSync(output, js)
  const before = getFileSizes(output)

  js = cleanJavaScript(js)
  checkPureAnnotations(input, js)
  fs.writeFileSync(output, js)

  const after = getFileSizes(output)
  printSizes(output, before, after)
}

for (const source of runtimeSources) {
  const declaration = source.replace(/\.ts$/, '.d.ts')
  const declarationMap = `${declaration}.map`
  if (!fs.existsSync(declaration)) throw new Error(`${declaration} not found`)
  if (!fs.existsSync(declarationMap)) throw new Error(`${declarationMap} not found`)

  let dts = fs.readFileSync(declaration, 'utf8')
  const before = { uncompressed: dts.length, compressed: gzipSync(dts).length }

  dts = rewriteRelativeTypeScriptSpecifiers(dts)
  dts = rewritePublicDeclarationImports(source, dts)
  dts = cleanDeclarationDocs(dts)
  fs.writeFileSync(declaration, dts)

  const after = getFileSizes(declaration)
  printSizes(declaration, before, after)
}

for (const entry of PUBLIC_ENTRIES) {
  const output = `${entry}.js`
  const declaration = `${entry}.d.ts`
  const declarationMap = `${declaration}.map`

  if (!fs.existsSync(output)) throw new Error(`${output} not found`)
  if (!fs.existsSync(declaration)) throw new Error(`${declaration} not found`)
  if (!fs.existsSync(declarationMap)) throw new Error(`${declarationMap} not found`)

  try {
    require(path.resolve(output))
  } catch (cause) {
    throw new Error(`${output} is not valid JavaScript`, { cause })
  }
}

{
  const input = './examples/noble-suite/index.ts'
  const output = './examples/noble-suite/index.js'
  const source = fs.readFileSync(input, 'utf8')
  let noble = amaro.transformSync(source, { mode: 'strip-only' }).code

  // Match the package boundary used by runtime test bundles and third-party implementations.
  noble = noble.replace(/(['"])\.\.\/\.\.\/index\.ts\1/g, "'paseto'")
  noble = rewriteRelativeTypeScriptSpecifiers(noble)

  fs.writeFileSync(output, noble)
  const before = getFileSizes(output)

  noble = cleanJavaScript(noble)
  checkPureAnnotations(source, noble)
  fs.writeFileSync(output, noble)

  const after = getFileSizes(output)
  printSizes(output, before, after)
}

function getRuntimeSources() {
  const sources = ['index.ts']

  for (const root of ['_internal', 'v1', 'v2', 'v3', 'v4']) {
    if (fs.existsSync(root)) collectRuntimeSources(root, sources)
  }

  return sources.sort()
}

function collectRuntimeSources(directory, sources) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const filename = path.join(directory, entry.name)
    if (entry.isDirectory()) {
      collectRuntimeSources(filename, sources)
    } else if (entry.isFile() && filename.endsWith('.ts') && !filename.endsWith('.d.ts')) {
      sources.push(filename)
    }
  }
}

function rewriteRelativeTypeScriptSpecifiers(code) {
  return code.replace(/(['"])(\.\.?\/[^'"\r\n]+)\1/g, (match, quote, specifier) => {
    if (!specifier.endsWith('.ts') || specifier.endsWith('.d.ts')) return match
    return `${quote}${specifier.slice(0, -3)}.js${quote}`
  })
}

function rewritePublicDeclarationImports(source, code) {
  if (!/^v[1-4]\/(?:local|public)\.ts$/u.test(source)) return code
  return code.replace(/(['"])\.\.\/index\.js\1/g, "'paseto'")
}

function cleanDeclarationDocs(code) {
  return code.replace(/[ \t]*\*[ \t]*@example[\s\S]*?```\n[ \t]*\*[ \t]*\n/g, (match) => {
    const lineCount = (match.match(/\n/g) || []).length
    return '\n'.repeat(lineCount)
  })
}

function checkPureAnnotations(source, output) {
  const annotation = /\/\*\s*[@#]__PURE__\s*\*\//g
  if ((source.match(annotation)?.length ?? 0) !== (output.match(annotation)?.length ?? 0)) {
    throw new Error('Build must preserve PURE annotations')
  }
}

function cleanJavaScript(code) {
  code = code.replace(/^[ \t]*\/\*\*[\s\S]*?\*\/[ \t]*$/gm, (match) => {
    const lineCount = (match.match(/\n/g) || []).length
    return '\n'.repeat(lineCount)
  })
  code = code.replace(/^[ \t]*\/\/.*$/gm, '')
  code = code.replace(/^(.+?)\/\/.*$/gm, (match, code) => code.trimEnd())
  code = code.replace(/^.*\/\*\s*c8\s+ignore\s+next.*$/gm, '')
  return code.replace(/^[ \t]+$/gm, '')
}

function getFileSizes(path) {
  const content = fs.readFileSync(path)
  return { uncompressed: content.length, compressed: gzipSync(content).length }
}

function formatSize(bytes) {
  return `${(bytes / 1024).toFixed(2)} KB`
}

function formatDifference(before, after) {
  if (before === 0) return '0.0%'
  return `${(((after - before) / before) * 100).toFixed(1)}%`
}

function printSizes(label, before, after) {
  console.log(`${label}:`)
  console.log(
    `  Uncompressed: ${formatSize(before.uncompressed)} → ${formatSize(after.uncompressed)} (${formatDifference(before.uncompressed, after.uncompressed)})`,
  )
  console.log(
    `  Compressed:   ${formatSize(before.compressed)} → ${formatSize(after.compressed)} (${formatDifference(before.compressed, after.compressed)})`,
  )
  console.log()
}
