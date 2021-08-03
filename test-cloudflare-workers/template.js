import * as paseto from '../dist/web/index.js'

const headers = { 'content-type': 'application/json' }
function respond(status, error) {
  const body = {}
  if (status !== 200) {
    body.error = error.stack
  }
  return new Response(JSON.stringify(body), { headers, status })
}
const success = respond.bind(undefined, 200)
const failure = respond.bind(undefined, 400)
addEventListener('fetch', (event) => {
  event.respondWith(test().then(success, failure))
})
