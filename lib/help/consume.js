const assert = require('assert')

const { PasetoInvalid } = require('../errors')
const assertPayload = require('./assert_payload')
const { decode } = require('./base64url')
const parse = require('./parse_paseto_payload')

function pre(h, token) {
  if (typeof token !== 'string') {
    throw new TypeError(`token must be a string, got: ${typeof token}`)
  }

  if (token.slice(0, h.length) !== h) {
    throw new PasetoInvalid(`token is not a ${h.slice(0, h.length - 1)} PASETO`)
  }

  let { 0: raw, 1: f = '', length } = token.slice(h.length).split('.')

  try {
    assert(length <= 2)
    raw = decode(raw)
    f = decode(f)
  } catch {
    throw new PasetoInvalid('token is not a PASETO formatted value')
  }

  return { raw, f }
}

function post(version, buffer, options, complete, m, f, purpose) {
  if (buffer) {
    if (Object.keys(options).length !== 0) {
      throw new TypeError('options cannot contain claims when options.buffer is true')
    }
    if (complete) {
      return { payload: m, footer: f?.length ? f : undefined, version, purpose }
    }

    return m
  }

  const payload = parse(m)

  assertPayload(options, payload)

  if (complete) {
    return { payload, footer: f?.length ? f : undefined, version, purpose }
  }

  return payload
}

module.exports = {
  post,
  pre,
}
