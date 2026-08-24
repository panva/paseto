import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { createServer } from 'node:http'
import { chromium, firefox, webkit } from 'playwright'

execFileSync(process.execPath, ['--run', 'build'], { stdio: 'inherit' })
execFileSync(
  './node_modules/.bin/esbuild',
  [
    '--log-level=warning',
    '--format=esm',
    '--bundle',
    '--platform=browser',
    '--target=esnext',
    '--alias:paseto=./index.js',
    '--outfile=test/run-browser.bundle.js',
    'test/run-browser.js',
  ],
  { stdio: 'inherit' },
)

const bundle = readFileSync(new URL('./run-browser.bundle.js', import.meta.url))
const html = Buffer.from(
  '<!doctype html><meta charset="utf-8"><title>PASETO runtime tests</title>' +
    '<script type="module" src="/run-browser.bundle.js"></script>',
)

function startServer() {
  const server = createServer((request, response) => {
    if (new URL(request.url, 'http://localhost').pathname === '/run-browser.bundle.js') {
      response.writeHead(200, { 'content-type': 'text/javascript; charset=utf-8' })
      response.end(bundle)
      return
    }
    response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
    response.end(html)
  })

  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      if (address === null || typeof address === 'string') {
        reject(new Error('Browser test server did not bind a TCP port'))
        return
      }
      resolve({ server, origin: `http://127.0.0.1:${address.port}` })
    })
  })
}

async function closeServer(server) {
  await new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()))
  })
}

async function runBrowser({ type, name }, origin) {
  console.log(`\nTesting with ${name}...`)
  const browser = await type.launch()
  const results = []

  try {
    for (const query of ['?native', '?noble', '']) {
      const label = query || '?native+noble'
      console.log(`  Testing ${label}`)
      const context = await browser.newContext()
      const page = await context.newPage()
      page.setDefaultTimeout(180_000)
      page.on('console', (message) => {
        if (message.type() === 'error') console.error(`  [${name}] ${message.text()}`)
      })
      page.on('pageerror', (error) => console.error(`  [${name}] ${error.stack ?? error}`))

      try {
        await page.goto(`${origin}/${query}`, { waitUntil: 'load' })
        await page.waitForFunction(
          () => globalThis.pasetoTestResults?.complete === true,
          undefined,
          { timeout: 180_000 },
        )
        const result = await page.evaluate(() => globalThis.pasetoTestResults)
        console.log(`    ${result.passed}/${result.total} passed`)
        for (const test of result.tests) {
          if (test.status === 'failed') console.error(`    FAIL ${test.name}\n${test.error}`)
        }
        results.push({ label, result })
      } finally {
        await context.close()
      }
    }
  } finally {
    await browser.close()
  }

  return results
}

async function main() {
  const available = [
    { type: chromium, name: 'Chromium', aliases: ['chromium'] },
    { type: firefox, name: 'Firefox', aliases: ['firefox'] },
    { type: webkit, name: 'Safari', aliases: ['safari', 'webkit'] },
  ]
  const requested = process.env.BROWSER?.toLowerCase()
  const browsers = requested
    ? available.filter(
        (browser) =>
          browser.name.toLowerCase() === requested || browser.aliases.includes(requested),
      )
    : available
  if (browsers.length === 0) throw new Error(`Unknown browser: ${process.env.BROWSER}`)

  const { server, origin } = await startServer()
  let failures = 0
  try {
    for (const browser of browsers) {
      const results = await runBrowser(browser, origin)
      for (const { label, result } of results) {
        const status = result.failed === 0 ? '✓' : '✗'
        console.log(`${status} ${browser.name} ${label}`)
        failures += result.failed
      }
    }
  } finally {
    await closeServer(server)
  }

  if (failures !== 0) throw new Error(`${failures} browser runtime test(s) failed`)
  console.log(`\nAll ${browsers.length} browser(s) passed`)
}

main().catch((error) => {
  console.error(error)
  process.exitCode = 1
})
