const { x } = require('tar')

const { execSync } = require('child_process')
const { version } = require('../package.json')

const opts = { stdio: 'inherit' }

execSync('npm pack', opts)
execSync('rm -rf dist', opts)
x({
  f: `paseto-${version}.tgz`,
  strip: true,
  filter(loc) {
    return loc.startsWith('package/dist/')
  },
  sync: true,
})
execSync('npm run build:deno', opts)
execSync('cp README.md dist/deno/README.md')
execSync('git add dist/**/* -f', opts)
