import * as paseto from '../dist/web/index.js'

const kNonce = Object.getOwnPropertySymbols(paseto.V1Local)[0]

const buf = TextEncoder.prototype.encode.bind(new TextEncoder())
const fromHexString = (hex) => {
  if (!hex) return new Uint8Array()
  return new Uint8Array(hex.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)))
}

async function testLocal(vector, version, assert) {
  const footer = buf(vector.footer)
  const assertion = buf(vector.assertion)
  const payload = buf(JSON.stringify(vector.payload))
  version[kNonce] = () => fromHexString(vector.nonce)

  const actual = await paseto.unseal(version)(vector.paserk.local, vector.token, assertion)
  assert.deepEqual([...actual.payload], [...payload])
  assert.deepEqual([...actual.footer], [...footer])
  assert.deepEqual(
    await paseto.seal(version)(vector.paserk.local, payload, footer, assertion),
    vector.token,
  )
}

async function testPublicEd25519(vector, version, assert) {
  const footer = buf(vector.footer)
  const assertion = buf(vector.assertion)
  const payload = buf(JSON.stringify(vector.payload))
  version[kNonce] = () => fromHexString(vector.nonce)

  const actual = await paseto.unseal(version)(vector.paserk.public, vector.token, assertion)
  assert.deepEqual([...actual.payload], [...payload])
  assert.deepEqual([...actual.footer], [...footer])
  assert.deepEqual(
    await paseto.seal(version)(vector.paserk.secret, payload, footer, assertion),
    vector.token,
  )
}

async function testPublic(vector, version, assert) {
  const footer = buf(vector.footer)
  const assertion = buf(vector.assertion)
  const payload = buf(JSON.stringify(vector.payload))
  version[kNonce] = () => fromHexString(vector.nonce)

  {
    const actual = await paseto.unseal(version)(vector.paserk.public, vector.token, assertion)
    assert.deepEqual([...actual.payload], [...payload])
    assert.deepEqual([...actual.footer], [...footer])
  }

  {
    const token = await paseto.seal(version)(vector.paserk.secret, payload, footer, assertion)
    const actual = await paseto.unseal(version)(vector.paserk.public, token, assertion)
    assert.deepEqual([...actual.payload], [...payload])
    assert.deepEqual([...actual.footer], [...footer])
  }
}

const { test } = QUnit

const vectors = [
  {
    name: '1-E-1',
    nonce: '0000000000000000000000000000000000000000000000000000000000000000',
    token:
      'v1.local.WzhIh1MpbqVNXNt7-HbWvL-JwAym3Tomad9Pc2nl7wK87vGraUVvn2bs8BBNo7jbukCNrkVID0jCK2vr5bP18G78j1bOTbBcP9HZzqnraEdspcjd_PvrxDEhj9cS2MG5fmxtvuoHRp3M24HvxTtql9z26KTfPWxJN5bAJaAM6gos8fnfjJO8oKiqQMaiBP_Cqncmqw8',
    payload: {
      data: 'this is a signed message',
      exp: '2019-01-01T00:00:00+00:00',
    },
    footer: '',
    assertion: '',
    paserk: {
      local: 'k1.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8',
    },
  },
  {
    name: '1-E-2',
    nonce: '0000000000000000000000000000000000000000000000000000000000000000',
    token:
      'v1.local.w_NOpjgte4bX-2i1JAiTQzHoGUVOgc2yqKqsnYGmaPaCu_KWUkRGlCRnOvZZxeH4HTykY7AE_jkzSXAYBkQ1QnwvKS16uTXNfnmp8IRknY76I2m3S5qsM8klxWQQKFDuQHl8xXV0MwAoeFh9X6vbwIqrLlof3s4PMjRDwKsxYzkMr1RvfDI8emoPoW83q4Q60_xpHaw',
    payload: {
      data: 'this is a secret message',
      exp: '2019-01-01T00:00:00+00:00',
    },
    footer: '',
    assertion: '',
    paserk: {
      local: 'k1.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8',
    },
  },
  {
    name: '1-E-3',
    nonce: '26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2',
    token:
      'v1.local.4VyfcVcFAOAbB8yEM1j1Ob7Iez5VZJy5kHNsQxmlrAwKUbOtq9cv39T2fC0MDWafX0nQJ4grFZzTdroMvU772RW-X1oTtoFBjsl_3YYHWnwgqzs0aFc3ejjORmKP4KUM339W3syBYyjKIOeWnsFQB6Yef-1ov9rvqt7TmwONUHeJUYk4IK_JEdUeo_uFRqAIgHsiGCg',
    payload: {
      data: 'this is a signed message',
      exp: '2019-01-01T00:00:00+00:00',
    },
    footer: '',
    assertion: '',
    paserk: {
      local: 'k1.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8',
    },
  },
  {
    name: '1-E-4',
    nonce: '26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2',
    token:
      'v1.local.IddlRQmpk6ojcD10z1EYdLexXvYiadtY0MrYQaRnq3dnqKIWcbbpOcgXdMIkm3_3gksirTj81bvWrWkQwcUHilt-tQo7LZK8I6HCK1V78B9YeEqGNeeWXOyWWHoJQIe0d5nTdvejdt2Srz_5Q0QG4oiz1gB_wmv4U5pifedaZbHXUTWXchFEi0etJ4u6tqgxZSklcec',
    payload: {
      data: 'this is a secret message',
      exp: '2019-01-01T00:00:00+00:00',
    },
    footer: '',
    assertion: '',
    paserk: {
      local: 'k1.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8',
    },
  },
  {
    name: '1-E-5',
    nonce: '26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2',
    token:
      'v1.local.4VyfcVcFAOAbB8yEM1j1Ob7Iez5VZJy5kHNsQxmlrAwKUbOtq9cv39T2fC0MDWafX0nQJ4grFZzTdroMvU772RW-X1oTtoFBjsl_3YYHWnwgqzs0aFc3ejjORmKP4KUM339W3szA28OabR192eRqiyspQ6xPM35NMR-04-FhRJZEWiF0W5oWjPVtGPjeVjm2DI4YtJg.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9',
    payload: {
      data: 'this is a signed message',
      exp: '2019-01-01T00:00:00+00:00',
    },
    footer: '{"kid":"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo"}',
    assertion: '',
    paserk: {
      local: 'k1.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8',
    },
  },
  {
    name: '1-E-6',
    nonce: '26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2',
    token:
      'v1.local.IddlRQmpk6ojcD10z1EYdLexXvYiadtY0MrYQaRnq3dnqKIWcbbpOcgXdMIkm3_3gksirTj81bvWrWkQwcUHilt-tQo7LZK8I6HCK1V78B9YeEqGNeeWXOyWWHoJQIe0d5nTdvcT2vnER6NrJ7xIowvFba6J4qMlFhBnYSxHEq9v9NlzcKsz1zscdjcAiXnEuCHyRSc.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9',
    payload: {
      data: 'this is a secret message',
      exp: '2019-01-01T00:00:00+00:00',
    },
    footer: '{"kid":"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo"}',
    assertion: '',
    paserk: {
      local: 'k1.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8',
    },
  },
  {
    name: '1-E-7',
    nonce: '26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2',
    token:
      'v1.local.4VyfcVcFAOAbB8yEM1j1Ob7Iez5VZJy5kHNsQxmlrAwKUbOtq9cv39T2fC0MDWafX0nQJ4grFZzTdroMvU772RW-X1oTtoFBjsl_3YYHWnwgqzs0aFc3ejjORmKP4KUM339W3szA28OabR192eRqiyspQ6xPM35NMR-04-FhRJZEWiF0W5oWjPVtGPjeVjm2DI4YtJg.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9',
    payload: {
      data: 'this is a signed message',
      exp: '2019-01-01T00:00:00+00:00',
    },
    footer: '{"kid":"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo"}',
    assertion: '',
    paserk: {
      local: 'k1.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8',
    },
  },
  {
    name: '1-E-8',
    nonce: '26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2',
    token:
      'v1.local.IddlRQmpk6ojcD10z1EYdLexXvYiadtY0MrYQaRnq3dnqKIWcbbpOcgXdMIkm3_3gksirTj81bvWrWkQwcUHilt-tQo7LZK8I6HCK1V78B9YeEqGNeeWXOyWWHoJQIe0d5nTdvcT2vnER6NrJ7xIowvFba6J4qMlFhBnYSxHEq9v9NlzcKsz1zscdjcAiXnEuCHyRSc.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9',
    payload: {
      data: 'this is a secret message',
      exp: '2019-01-01T00:00:00+00:00',
    },
    footer: '{"kid":"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo"}',
    assertion: '',
    paserk: {
      local: 'k1.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8',
    },
  },
  {
    name: '1-E-9',
    nonce: '26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2',
    token:
      'v1.local.IddlRQmpk6ojcD10z1EYdLexXvYiadtY0MrYQaRnq3dnqKIWcbbpOcgXdMIkm3_3gksirTj81bvWrWkQwcUHilt-tQo7LZK8I6HCK1V78B9YeEqGNeeWXOyWWHoJQIe0d5nTdvdgNpe3vI21jV2YL7WVG5p63_JxxzLckBu9azQ0GlDMdPxNAxoyvmU1wbpSbRB9Iw4.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24',
    payload: {
      data: 'this is a secret message',
      exp: '2019-01-01T00:00:00+00:00',
    },
    footer: "arbitrary-string-that-isn't-json",
    assertion: '',
    paserk: {
      local: 'k1.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8',
    },
  },
  {
    name: '1-S-1',
    token:
      'v1.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9cIZKahKeGM5kiAS_4D70Qbz9FIThZpxetJ6n6E6kXP_119SvQcnfCSfY_gG3D0Q2v7FEtm2Cmj04lE6YdgiZ0RwA41WuOjXq7zSnmmHK9xOSH6_2yVgt207h1_LphJzVztmZzq05xxhZsV3nFPm2cCu8oPceWy-DBKjALuMZt_Xj6hWFFie96SfQ6i85lOsTX8Kc6SQaG-3CgThrJJ6W9DC-YfQ3lZ4TJUoY3QNYdtEgAvp1QuWWK6xmIb8BwvkBPej5t88QUb7NcvZ15VyNw3qemQGn2ITSdpdDgwMtpflZOeYdtuxQr1DSGO2aQyZl7s0WYn1IjdQFx6VjSQ4yfw',
    payload: {
      data: 'this is a signed message',
      exp: '2019-01-01T00:00:00+00:00',
    },
    footer: '',
    assertion: '',
    paserk: {
      secret:
        'k1.secret.MIIEowIBAAKCAQEAyaTgTt53ph3p5GHgwoGWwz5hRfWXSQA08NCOwe0FEgALWos9GCjNFCd723nCHxBtN1qd74MSh_uN88JPIbwxKheDp4kxo4YMN5trPaF0e9G6Bj1N02HnanxFLW-gmLbgYO_SZYfWF_M8yLBcu5Y1Ot0ZxDDDXS9wIQTtBE0ne3YbxgZJAZTU5XqyQ1DxdzYyC5lF6yBaR5UQtCYTnXAApVRuUI2Sd6L1E2vl9bSBumZ5IpNxkRnAwIMjeTJB_0AIELh0mE5vwdihOCbdV6alUyhKC1-1w_FW6HWcp_JG1kKC8DPIidZ78Bbqv9YFzkAbNni5eSBOsXVBKG78Zsc8owIDAQABAoIBAF22jLDa34yKdns3qfd7to-C3D5hRzAcMn6Azvf9qc-VybEI6RnjTHxDZWK5EajSP4_sQ15e8ivUk0JoWdJ53feL-hnQvwsab28gghSghrxM2kGwGA1XgO-SVawqJt8SjvE-Q-__01ZKK0OyA0cDJjX3L9RoPUN_moMeAPFw0hqkFEhm72GSVCEY1eY-cOXmL3icxnsnlUD__SS9q33RxF2y5oiW1edqcRqhW_7L1yYMbxHFUcxWh8WUwjn1AAhoCOUzF8ZB-0X_PPh-1nYoq6xwqL0ZKDwrQ8SDhW_rNDLeO9gic5rl7EetRQRbFvsZ40AdsX2wU-lWFUkB42AjuoECgYEA5z_CXqDFfZ8MXCPAOeui8y5HNDtu30aR-HOXsBDnRI8huXsGND04FfmXR7nkghr08fFVDmE4PeKUk810YJb-IAJo8wrOZ0682n6yEMO58omqKin-iIUVrPXLSLo5CChrqw2J4vgzolzPw3N5I8FJdLomb9FkrV84H-IviPIylyECgYEA3znwAG29QX6ATEfFpGVOcogorHCntd4niaWCq5ne5sFL-EwLeVc1zD9yj1axcDelICDZxCZynU7kDnrQcFkT0bjH_gC8Jk3v7XT9l1UDDqC1b7rm_X5wFIZ_rmNa1rVZhL1o_tKx5tvM2syJ1q95v7NdygFIEIW-qbIKbc6Wz0MCgYBsUZdQD-qx_xAhELX364I2epTryHMUrs-tGygQVrqdiJX5dcDgM1TUJkdQV6jLsKjPs4Vt6OgZRMrnuLMsk02R3M8gGQ25ok4f4nyyEZxGGWnVujn55KzUiYWhGWmhgp18UCkoYa59_Q9ss-gocV9hB9j9Q43vD80QUjiF4z0DQQKBgC7XQX1VibkMim93QAnXGDcAS0ij-w02qKVBjcHkb9mMBhz8GAxGOIu7ZJafYmxhwMyVGB0I1FQeEczYCJUKnBYN6Clsjg6bnBT_z5bJx_Jx1qCzX3Uh6vLjpjc5sf4L39Tyye1u2NXQmZPwB5x9BdcsFConSq_s4K1LJtUT3KFxAoGBANGcQ8nObi3m4wROyKrkCWcWxFFMnpwxv0pW727Hn9wuaOs4UbesCnwmpcMTfzGUDuzYXCtAq2pJl64HG6wsdkWmjBTJEpm6b9ibOBN3qFV2zQ0HyyKlMWxIuVSj9gOo61hF7UH9XB6R4HRdlpBOuIbgAWZ46dkj9_HM9ovdP0Iy',
      public:
        'k1.public.MIIBCgKCAQEAyaTgTt53ph3p5GHgwoGWwz5hRfWXSQA08NCOwe0FEgALWos9GCjNFCd723nCHxBtN1qd74MSh_uN88JPIbwxKheDp4kxo4YMN5trPaF0e9G6Bj1N02HnanxFLW-gmLbgYO_SZYfWF_M8yLBcu5Y1Ot0ZxDDDXS9wIQTtBE0ne3YbxgZJAZTU5XqyQ1DxdzYyC5lF6yBaR5UQtCYTnXAApVRuUI2Sd6L1E2vl9bSBumZ5IpNxkRnAwIMjeTJB_0AIELh0mE5vwdihOCbdV6alUyhKC1-1w_FW6HWcp_JG1kKC8DPIidZ78Bbqv9YFzkAbNni5eSBOsXVBKG78Zsc8owIDAQAB',
    },
  },
  {
    name: '1-S-2',
    token:
      'v1.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9sBTIb0J_4misAuYc4-6P5iR1rQighzktpXhJ8gtrrp2MqSSDkbb8q5WZh3FhUYuW_rg2X8aflDlTWKAqJkM3otjYwtmfwfOhRyykxRL2AfmIika_A-_MaLp9F0iw4S1JetQQDV8GUHjosd87TZ20lT2JQLhxKjBNJSwWue8ucGhTgJcpOhXcthqaz7a2yudGyd0layzeWziBhdQpoBR6ryTdtIQX54hP59k3XCIxuYbB9qJMpixiPAEKBcjHT74sA-uukug9VgKO7heWHwJL4Rl9ad21xyNwaxAnwAJ7C0fN5oGv8Rl0dF11b3tRmsmbDoIokIM0Dba29x_T3YzOyg.eyJraWQiOiJkWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVxbiJ9',
    payload: {
      data: 'this is a signed message',
      exp: '2019-01-01T00:00:00+00:00',
    },
    footer: '{"kid":"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn"}',
    assertion: '',
    paserk: {
      secret:
        'k1.secret.MIIEowIBAAKCAQEAyaTgTt53ph3p5GHgwoGWwz5hRfWXSQA08NCOwe0FEgALWos9GCjNFCd723nCHxBtN1qd74MSh_uN88JPIbwxKheDp4kxo4YMN5trPaF0e9G6Bj1N02HnanxFLW-gmLbgYO_SZYfWF_M8yLBcu5Y1Ot0ZxDDDXS9wIQTtBE0ne3YbxgZJAZTU5XqyQ1DxdzYyC5lF6yBaR5UQtCYTnXAApVRuUI2Sd6L1E2vl9bSBumZ5IpNxkRnAwIMjeTJB_0AIELh0mE5vwdihOCbdV6alUyhKC1-1w_FW6HWcp_JG1kKC8DPIidZ78Bbqv9YFzkAbNni5eSBOsXVBKG78Zsc8owIDAQABAoIBAF22jLDa34yKdns3qfd7to-C3D5hRzAcMn6Azvf9qc-VybEI6RnjTHxDZWK5EajSP4_sQ15e8ivUk0JoWdJ53feL-hnQvwsab28gghSghrxM2kGwGA1XgO-SVawqJt8SjvE-Q-__01ZKK0OyA0cDJjX3L9RoPUN_moMeAPFw0hqkFEhm72GSVCEY1eY-cOXmL3icxnsnlUD__SS9q33RxF2y5oiW1edqcRqhW_7L1yYMbxHFUcxWh8WUwjn1AAhoCOUzF8ZB-0X_PPh-1nYoq6xwqL0ZKDwrQ8SDhW_rNDLeO9gic5rl7EetRQRbFvsZ40AdsX2wU-lWFUkB42AjuoECgYEA5z_CXqDFfZ8MXCPAOeui8y5HNDtu30aR-HOXsBDnRI8huXsGND04FfmXR7nkghr08fFVDmE4PeKUk810YJb-IAJo8wrOZ0682n6yEMO58omqKin-iIUVrPXLSLo5CChrqw2J4vgzolzPw3N5I8FJdLomb9FkrV84H-IviPIylyECgYEA3znwAG29QX6ATEfFpGVOcogorHCntd4niaWCq5ne5sFL-EwLeVc1zD9yj1axcDelICDZxCZynU7kDnrQcFkT0bjH_gC8Jk3v7XT9l1UDDqC1b7rm_X5wFIZ_rmNa1rVZhL1o_tKx5tvM2syJ1q95v7NdygFIEIW-qbIKbc6Wz0MCgYBsUZdQD-qx_xAhELX364I2epTryHMUrs-tGygQVrqdiJX5dcDgM1TUJkdQV6jLsKjPs4Vt6OgZRMrnuLMsk02R3M8gGQ25ok4f4nyyEZxGGWnVujn55KzUiYWhGWmhgp18UCkoYa59_Q9ss-gocV9hB9j9Q43vD80QUjiF4z0DQQKBgC7XQX1VibkMim93QAnXGDcAS0ij-w02qKVBjcHkb9mMBhz8GAxGOIu7ZJafYmxhwMyVGB0I1FQeEczYCJUKnBYN6Clsjg6bnBT_z5bJx_Jx1qCzX3Uh6vLjpjc5sf4L39Tyye1u2NXQmZPwB5x9BdcsFConSq_s4K1LJtUT3KFxAoGBANGcQ8nObi3m4wROyKrkCWcWxFFMnpwxv0pW727Hn9wuaOs4UbesCnwmpcMTfzGUDuzYXCtAq2pJl64HG6wsdkWmjBTJEpm6b9ibOBN3qFV2zQ0HyyKlMWxIuVSj9gOo61hF7UH9XB6R4HRdlpBOuIbgAWZ46dkj9_HM9ovdP0Iy',
      public:
        'k1.public.MIIBCgKCAQEAyaTgTt53ph3p5GHgwoGWwz5hRfWXSQA08NCOwe0FEgALWos9GCjNFCd723nCHxBtN1qd74MSh_uN88JPIbwxKheDp4kxo4YMN5trPaF0e9G6Bj1N02HnanxFLW-gmLbgYO_SZYfWF_M8yLBcu5Y1Ot0ZxDDDXS9wIQTtBE0ne3YbxgZJAZTU5XqyQ1DxdzYyC5lF6yBaR5UQtCYTnXAApVRuUI2Sd6L1E2vl9bSBumZ5IpNxkRnAwIMjeTJB_0AIELh0mE5vwdihOCbdV6alUyhKC1-1w_FW6HWcp_JG1kKC8DPIidZ78Bbqv9YFzkAbNni5eSBOsXVBKG78Zsc8owIDAQAB',
    },
  },
  {
    name: '1-S-3',
    token:
      'v1.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9sBTIb0J_4misAuYc4-6P5iR1rQighzktpXhJ8gtrrp2MqSSDkbb8q5WZh3FhUYuW_rg2X8aflDlTWKAqJkM3otjYwtmfwfOhRyykxRL2AfmIika_A-_MaLp9F0iw4S1JetQQDV8GUHjosd87TZ20lT2JQLhxKjBNJSwWue8ucGhTgJcpOhXcthqaz7a2yudGyd0layzeWziBhdQpoBR6ryTdtIQX54hP59k3XCIxuYbB9qJMpixiPAEKBcjHT74sA-uukug9VgKO7heWHwJL4Rl9ad21xyNwaxAnwAJ7C0fN5oGv8Rl0dF11b3tRmsmbDoIokIM0Dba29x_T3YzOyg.eyJraWQiOiJkWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVxbiJ9',
    payload: {
      data: 'this is a signed message',
      exp: '2019-01-01T00:00:00+00:00',
    },
    footer: '{"kid":"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn"}',
    assertion: '',
    paserk: {
      secret:
        'k1.secret.MIIEowIBAAKCAQEAyaTgTt53ph3p5GHgwoGWwz5hRfWXSQA08NCOwe0FEgALWos9GCjNFCd723nCHxBtN1qd74MSh_uN88JPIbwxKheDp4kxo4YMN5trPaF0e9G6Bj1N02HnanxFLW-gmLbgYO_SZYfWF_M8yLBcu5Y1Ot0ZxDDDXS9wIQTtBE0ne3YbxgZJAZTU5XqyQ1DxdzYyC5lF6yBaR5UQtCYTnXAApVRuUI2Sd6L1E2vl9bSBumZ5IpNxkRnAwIMjeTJB_0AIELh0mE5vwdihOCbdV6alUyhKC1-1w_FW6HWcp_JG1kKC8DPIidZ78Bbqv9YFzkAbNni5eSBOsXVBKG78Zsc8owIDAQABAoIBAF22jLDa34yKdns3qfd7to-C3D5hRzAcMn6Azvf9qc-VybEI6RnjTHxDZWK5EajSP4_sQ15e8ivUk0JoWdJ53feL-hnQvwsab28gghSghrxM2kGwGA1XgO-SVawqJt8SjvE-Q-__01ZKK0OyA0cDJjX3L9RoPUN_moMeAPFw0hqkFEhm72GSVCEY1eY-cOXmL3icxnsnlUD__SS9q33RxF2y5oiW1edqcRqhW_7L1yYMbxHFUcxWh8WUwjn1AAhoCOUzF8ZB-0X_PPh-1nYoq6xwqL0ZKDwrQ8SDhW_rNDLeO9gic5rl7EetRQRbFvsZ40AdsX2wU-lWFUkB42AjuoECgYEA5z_CXqDFfZ8MXCPAOeui8y5HNDtu30aR-HOXsBDnRI8huXsGND04FfmXR7nkghr08fFVDmE4PeKUk810YJb-IAJo8wrOZ0682n6yEMO58omqKin-iIUVrPXLSLo5CChrqw2J4vgzolzPw3N5I8FJdLomb9FkrV84H-IviPIylyECgYEA3znwAG29QX6ATEfFpGVOcogorHCntd4niaWCq5ne5sFL-EwLeVc1zD9yj1axcDelICDZxCZynU7kDnrQcFkT0bjH_gC8Jk3v7XT9l1UDDqC1b7rm_X5wFIZ_rmNa1rVZhL1o_tKx5tvM2syJ1q95v7NdygFIEIW-qbIKbc6Wz0MCgYBsUZdQD-qx_xAhELX364I2epTryHMUrs-tGygQVrqdiJX5dcDgM1TUJkdQV6jLsKjPs4Vt6OgZRMrnuLMsk02R3M8gGQ25ok4f4nyyEZxGGWnVujn55KzUiYWhGWmhgp18UCkoYa59_Q9ss-gocV9hB9j9Q43vD80QUjiF4z0DQQKBgC7XQX1VibkMim93QAnXGDcAS0ij-w02qKVBjcHkb9mMBhz8GAxGOIu7ZJafYmxhwMyVGB0I1FQeEczYCJUKnBYN6Clsjg6bnBT_z5bJx_Jx1qCzX3Uh6vLjpjc5sf4L39Tyye1u2NXQmZPwB5x9BdcsFConSq_s4K1LJtUT3KFxAoGBANGcQ8nObi3m4wROyKrkCWcWxFFMnpwxv0pW727Hn9wuaOs4UbesCnwmpcMTfzGUDuzYXCtAq2pJl64HG6wsdkWmjBTJEpm6b9ibOBN3qFV2zQ0HyyKlMWxIuVSj9gOo61hF7UH9XB6R4HRdlpBOuIbgAWZ46dkj9_HM9ovdP0Iy',
      public:
        'k1.public.MIIBCgKCAQEAyaTgTt53ph3p5GHgwoGWwz5hRfWXSQA08NCOwe0FEgALWos9GCjNFCd723nCHxBtN1qd74MSh_uN88JPIbwxKheDp4kxo4YMN5trPaF0e9G6Bj1N02HnanxFLW-gmLbgYO_SZYfWF_M8yLBcu5Y1Ot0ZxDDDXS9wIQTtBE0ne3YbxgZJAZTU5XqyQ1DxdzYyC5lF6yBaR5UQtCYTnXAApVRuUI2Sd6L1E2vl9bSBumZ5IpNxkRnAwIMjeTJB_0AIELh0mE5vwdihOCbdV6alUyhKC1-1w_FW6HWcp_JG1kKC8DPIidZ78Bbqv9YFzkAbNni5eSBOsXVBKG78Zsc8owIDAQAB',
    },
  },
  {
    name: '2-E-1',
    nonce: '000000000000000000000000000000000000000000000000',
    token:
      'v2.local.97TTOvgwIxNGvV80XKiGZg_kD3tsXM_-qB4dZGHOeN1cTkgQ4PnW8888l802W8d9AvEGnoNBY3BnqHORy8a5cC8aKpbA0En8XELw2yDk2f1sVODyfnDbi6rEGMY3pSfCbLWMM2oHJxvlEl2XbQ',
    payload: {
      data: 'this is a signed message',
      exp: '2019-01-01T00:00:00+00:00',
    },
    footer: '',
    assertion: '',
    paserk: {
      local: 'k2.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8',
    },
  },
  {
    name: '2-E-2',
    nonce: '000000000000000000000000000000000000000000000000',
    token:
      'v2.local.CH50H-HM5tzdK4kOmQ8KbIvrzJfjYUGuu5Vy9ARSFHy9owVDMYg3-8rwtJZQjN9ABHb2njzFkvpr5cOYuRyt7CRXnHt42L5yZ7siD-4l-FoNsC7J2OlvLlIwlG06mzQVunrFNb7Z3_CHM0PK5w',
    payload: {
      data: 'this is a secret message',
      exp: '2019-01-01T00:00:00+00:00',
    },
    footer: '',
    assertion: '',
    paserk: {
      local: 'k2.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8',
    },
  },
  {
    name: '2-E-3',
    nonce: '45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b',
    token:
      'v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-O5xRBN076fSDPo5xUCPpBA',
    payload: {
      data: 'this is a signed message',
      exp: '2019-01-01T00:00:00+00:00',
    },
    footer: '',
    assertion: '',
    paserk: {
      local: 'k2.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8',
    },
  },
  {
    name: '2-E-4',
    nonce: '45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b',
    token:
      'v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DPbIxtjGvNRAwsLK7LcV8oQ',
    payload: {
      data: 'this is a secret message',
      exp: '2019-01-01T00:00:00+00:00',
    },
    footer: '',
    assertion: '',
    paserk: {
      local: 'k2.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8',
    },
  },
  {
    name: '2-E-5',
    nonce: '45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b',
    token:
      'v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-zSLIrxZqOLwcFLYbVK1SrQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9',
    payload: {
      data: 'this is a signed message',
      exp: '2019-01-01T00:00:00+00:00',
    },
    footer: '{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}',
    assertion: '',
    paserk: {
      local: 'k2.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8',
    },
  },
  {
    name: '2-E-6',
    nonce: '45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b',
    token:
      'v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DnMXKdHn_Smp6L_NfaEnZ-A.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9',
    payload: {
      data: 'this is a secret message',
      exp: '2019-01-01T00:00:00+00:00',
    },
    footer: '{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}',
    assertion: '',
    paserk: {
      local: 'k2.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8',
    },
  },
  {
    name: '2-E-7',
    nonce: '45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b',
    token:
      'v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-zSLIrxZqOLwcFLYbVK1SrQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9',
    payload: {
      data: 'this is a signed message',
      exp: '2019-01-01T00:00:00+00:00',
    },
    footer: '{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}',
    assertion: '',
    paserk: {
      local: 'k2.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8',
    },
  },
  {
    name: '2-E-8',
    nonce: '45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b',
    token:
      'v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DnMXKdHn_Smp6L_NfaEnZ-A.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9',
    payload: {
      data: 'this is a secret message',
      exp: '2019-01-01T00:00:00+00:00',
    },
    footer: '{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}',
    assertion: '',
    paserk: {
      local: 'k2.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8',
    },
  },
  {
    name: '2-E-9',
    nonce: '45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b',
    token:
      'v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DoOJbyKBGPZG50XDZ6mbPtw.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24',
    payload: {
      data: 'this is a secret message',
      exp: '2019-01-01T00:00:00+00:00',
    },
    footer: "arbitrary-string-that-isn't-json",
    assertion: '',
    paserk: {
      local: 'k2.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8',
    },
  },
  {
    name: '2-S-1',
    token:
      'v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9HQr8URrGntTu7Dz9J2IF23d1M7-9lH9xiqdGyJNvzp4angPW5Esc7C5huy_M8I8_DjJK2ZXC2SUYuOFM-Q_5Cw',
    payload: {
      data: 'this is a signed message',
      exp: '2019-01-01T00:00:00+00:00',
    },
    footer: '',
    assertion: '',
    paserk: {
      secret:
        'k2.secret.tMv7Q99M4hByfZU-SnEzB_oZu32fhQQUONnhG5QqN3Qeudu7vAR8A_1wYE4AcfCYfhayi3VyJcEfAEFdDiCxog',
      public: 'k2.public.Hrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI',
    },
  },
  {
    name: '2-S-2',
    token:
      'v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9flsZsx_gYCR0N_Ec2QxJFFpvQAs7h9HtKwbVK2n1MJ3Rz-hwe8KUqjnd8FAnIJZ601tp7lGkguU63oGbomhoBw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9',
    payload: {
      data: 'this is a signed message',
      exp: '2019-01-01T00:00:00+00:00',
    },
    footer: '{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}',
    assertion: '',
    paserk: {
      secret:
        'k2.secret.tMv7Q99M4hByfZU-SnEzB_oZu32fhQQUONnhG5QqN3Qeudu7vAR8A_1wYE4AcfCYfhayi3VyJcEfAEFdDiCxog',
      public: 'k2.public.Hrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI',
    },
  },
  {
    name: '2-S-3',
    token:
      'v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9flsZsx_gYCR0N_Ec2QxJFFpvQAs7h9HtKwbVK2n1MJ3Rz-hwe8KUqjnd8FAnIJZ601tp7lGkguU63oGbomhoBw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9',
    payload: {
      data: 'this is a signed message',
      exp: '2019-01-01T00:00:00+00:00',
    },
    footer: '{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}',
    assertion: '',
    paserk: {
      secret:
        'k2.secret.tMv7Q99M4hByfZU-SnEzB_oZu32fhQQUONnhG5QqN3Qeudu7vAR8A_1wYE4AcfCYfhayi3VyJcEfAEFdDiCxog',
      public: 'k2.public.Hrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI',
    },
  },
  {
    name: '3-E-1',
    nonce: '0000000000000000000000000000000000000000000000000000000000000000',
    token:
      'v3.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADbfcIURX_0pVZVU1mAESUzrKZAsRm2EsD6yBoZYn6cpVZNzSJOhSDN-sRaWjfLU-yn9OJH1J_B8GKtOQ9gSQlb8yk9Iza7teRdkiR89ZFyvPPsVjjFiepFUVcMa-LP18zV77f_crJrVXWa5PDNRkCSeHfBBeg',
    payload: {
      data: 'this is a secret message',
      exp: '2022-01-01T00:00:00+00:00',
    },
    footer: '',
    assertion: '',
    paserk: {
      local: 'k3.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8',
    },
  },
  {
    name: '3-E-2',
    nonce: '0000000000000000000000000000000000000000000000000000000000000000',
    token:
      'v3.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADbfcIURX_0pVZVU1mAESUzrKZAqhWxBMDgyBoZYn6cpVZNzSJOhSDN-sRaWjfLU-yn9OJH1J_B8GKtOQ9gSQlb8yk9IzZfaZpReVpHlDSwfuygx1riVXYVs-UjcrG_apl9oz3jCVmmJbRuKn5ZfD8mHz2db0A',
    payload: {
      data: 'this is a hidden message',
      exp: '2022-01-01T00:00:00+00:00',
    },
    footer: '',
    assertion: '',
    paserk: {
      local: 'k3.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8',
    },
  },
  {
    name: '3-E-3',
    nonce: '26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2',
    token:
      'v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0ROIIykcrGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJlxnt5xyhQjFJomwnt7WW_7r2VT0G704ifult011-TgLCyQ2X8imQhniG_hAQ4BydM',
    payload: {
      data: 'this is a secret message',
      exp: '2022-01-01T00:00:00+00:00',
    },
    footer: '',
    assertion: '',
    paserk: {
      local: 'k3.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8',
    },
  },
  {
    name: '3-E-4',
    nonce: '26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2',
    token:
      'v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0X-4P3EcxGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJlBZa_gOpVj4gv0M9lV6Pwjp8JS_MmaZaTA1LLTULXybOBZ2S4xMbYqYmDRhh3IgEk',
    payload: {
      data: 'this is a hidden message',
      exp: '2022-01-01T00:00:00+00:00',
    },
    footer: '',
    assertion: '',
    paserk: {
      local: 'k3.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8',
    },
  },
  {
    name: '3-E-5',
    nonce: '26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2',
    token:
      'v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0ROIIykcrGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJlkYSIbXOgVuIQL65UMdW9WcjOpmqvjqD40NNzed-XPqn1T3w-bJvitYpUJL_rmihc.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9',
    payload: {
      data: 'this is a secret message',
      exp: '2022-01-01T00:00:00+00:00',
    },
    footer: '{"kid":"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo"}',
    assertion: '',
    paserk: {
      local: 'k3.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8',
    },
  },
  {
    name: '3-E-6',
    nonce: '26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2',
    token:
      'v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0X-4P3EcxGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJmSeEMphEWHiwtDKJftg41O1F8Hat-8kQ82ZIAMFqkx9q5VkWlxZke9ZzMBbb3Znfo.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9',
    payload: {
      data: 'this is a hidden message',
      exp: '2022-01-01T00:00:00+00:00',
    },
    footer: '{"kid":"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo"}',
    assertion: '',
    paserk: {
      local: 'k3.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8',
    },
  },
  {
    name: '3-E-7',
    nonce: '26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2',
    token:
      'v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0ROIIykcrGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJkzWACWAIoVa0bz7EWSBoTEnS8MvGBYHHo6t6mJunPrFR9JKXFCc0obwz5N-pxFLOc.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9',
    payload: {
      data: 'this is a secret message',
      exp: '2022-01-01T00:00:00+00:00',
    },
    footer: '{"kid":"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo"}',
    assertion: '{"test-vector":"3-E-7"}',
    paserk: {
      local: 'k3.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8',
    },
  },
  {
    name: '3-E-8',
    nonce: '26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2',
    token:
      'v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0X-4P3EcxGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJmZHSSKYR6AnPYJV6gpHtx6dLakIG_AOPhu8vKexNyrv5_1qoom6_NaPGecoiz6fR8.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9',
    payload: {
      data: 'this is a hidden message',
      exp: '2022-01-01T00:00:00+00:00',
    },
    footer: '{"kid":"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo"}',
    assertion: '{"test-vector":"3-E-8"}',
    paserk: {
      local: 'k3.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8',
    },
  },
  {
    name: '3-E-9',
    nonce: '26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2',
    token:
      'v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0X-4P3EcxGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJlk1nli0_wijTH_vCuRwckEDc82QWK8-lG2fT9wQF271sgbVRVPjm0LwMQZkvvamqU.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24',
    payload: {
      data: 'this is a hidden message',
      exp: '2022-01-01T00:00:00+00:00',
    },
    footer: "arbitrary-string-that-isn't-json",
    assertion: '{"test-vector":"3-E-9"}',
    paserk: {
      local: 'k3.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8',
    },
  },
  {
    name: '3-S-1',
    token:
      'v3.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9qqEwwrKHKi5lJ7b9MBKc0G4MGZy0ptUiMv3lAUAaz-JY_zjoqBSIxMxhfAoeNYiSyvfUErj76KOPWm1OeNnBPkTSespeSXDGaDfxeIrl3bRrPEIy7tLwLAIsRzsXkfph',
    payload: {
      data: 'this is a signed message',
      exp: '2022-01-01T00:00:00+00:00',
    },
    footer: '',
    assertion: '',
    paserk: {
      secret: 'k3.secret.IDR2CWB0d6yo-_vF5iGEVfMZlml5Lvi0Zvqoe9xneYFEyEjdA2Ye7VrGJGE0DOqW',
      public: 'k3.public.AvvLfGnuHGBXm-ejNBNIeNnFxb811VLatjwBQDl-0UzvY313IJJcRGmeow5yh0xy-w',
    },
  },
  {
    name: '3-S-2',
    token:
      'v3.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9ZWrbGZ6L0MDK72skosUaS0Dz7wJ_2bMcM6tOxFuCasO9GhwHrvvchqgXQNLQQyWzGC2wkr-VKII71AvkLpC8tJOrzJV1cap9NRwoFzbcXjzMZyxQ0wkshxZxx8ImmNWP.eyJraWQiOiJkWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVxbiJ9',
    payload: {
      data: 'this is a signed message',
      exp: '2022-01-01T00:00:00+00:00',
    },
    footer: '{"kid":"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn"}',
    assertion: '',
    paserk: {
      secret: 'k3.secret.IDR2CWB0d6yo-_vF5iGEVfMZlml5Lvi0Zvqoe9xneYFEyEjdA2Ye7VrGJGE0DOqW',
      public: 'k3.public.AvvLfGnuHGBXm-ejNBNIeNnFxb811VLatjwBQDl-0UzvY313IJJcRGmeow5yh0xy-w',
    },
  },
  {
    name: '3-S-3',
    token:
      'v3.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ94SjWIbjmS7715GjLSnHnpJrC9Z-cnwK45dmvnVvCRQDCCKAXaKEopTajX0DKYx1Xqr6gcTdfqscLCAbiB4eOW9jlt-oNqdG8TjsYEi6aloBfTzF1DXff_45tFlnBukEX.eyJraWQiOiJkWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVxbiJ9',
    payload: {
      data: 'this is a signed message',
      exp: '2022-01-01T00:00:00+00:00',
    },
    footer: '{"kid":"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn"}',
    assertion: '{"test-vector":"3-S-3"}',
    paserk: {
      secret: 'k3.secret.IDR2CWB0d6yo-_vF5iGEVfMZlml5Lvi0Zvqoe9xneYFEyEjdA2Ye7VrGJGE0DOqW',
      public: 'k3.public.AvvLfGnuHGBXm-ejNBNIeNnFxb811VLatjwBQDl-0UzvY313IJJcRGmeow5yh0xy-w',
    },
  },
  {
    name: '4-E-1',
    nonce: '0000000000000000000000000000000000000000000000000000000000000000',
    token:
      'v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAr68PS4AXe7If_ZgesdkUMvSwscFlAl1pk5HC0e8kApeaqMfGo_7OpBnwJOAbY9V7WU6abu74MmcUE8YWAiaArVI8XJ5hOb_4v9RmDkneN0S92dx0OW4pgy7omxgf3S8c3LlQg',
    payload: {
      data: 'this is a secret message',
      exp: '2022-01-01T00:00:00+00:00',
    },
    footer: '',
    assertion: '',
    paserk: {
      local: 'k4.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8',
    },
  },
  {
    name: '4-E-2',
    nonce: '0000000000000000000000000000000000000000000000000000000000000000',
    token:
      'v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAr68PS4AXe7If_ZgesdkUMvS2csCgglvpk5HC0e8kApeaqMfGo_7OpBnwJOAbY9V7WU6abu74MmcUE8YWAiaArVI8XIemu9chy3WVKvRBfg6t8wwYHK0ArLxxfZP73W_vfwt5A',
    payload: {
      data: 'this is a hidden message',
      exp: '2022-01-01T00:00:00+00:00',
    },
    footer: '',
    assertion: '',
    paserk: {
      local: 'k4.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8',
    },
  },
  {
    name: '4-E-3',
    nonce: 'df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8',
    token:
      'v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t6-tyebyWG6Ov7kKvBdkrrAJ837lKP3iDag2hzUPHuMKA',
    payload: {
      data: 'this is a secret message',
      exp: '2022-01-01T00:00:00+00:00',
    },
    footer: '',
    assertion: '',
    paserk: {
      local: 'k4.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8',
    },
  },
  {
    name: '4-E-4',
    nonce: 'df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8',
    token:
      'v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t4gt6TiLm55vIH8c_lGxxZpE3AWlH4WTR0v45nsWoU3gQ',
    payload: {
      data: 'this is a hidden message',
      exp: '2022-01-01T00:00:00+00:00',
    },
    footer: '',
    assertion: '',
    paserk: {
      local: 'k4.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8',
    },
  },
  {
    name: '4-E-5',
    nonce: 'df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8',
    token:
      'v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t4x-RMNXtQNbz7FvFZ_G-lFpk5RG3EOrwDL6CgDqcerSQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9',
    payload: {
      data: 'this is a secret message',
      exp: '2022-01-01T00:00:00+00:00',
    },
    footer: '{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}',
    assertion: '',
    paserk: {
      local: 'k4.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8',
    },
  },
  {
    name: '4-E-6',
    nonce: 'df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8',
    token:
      'v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t6pWSA5HX2wjb3P-xLQg5K5feUCX4P2fpVK3ZLWFbMSxQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9',
    payload: {
      data: 'this is a hidden message',
      exp: '2022-01-01T00:00:00+00:00',
    },
    footer: '{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}',
    assertion: '',
    paserk: {
      local: 'k4.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8',
    },
  },
  {
    name: '4-E-7',
    nonce: 'df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8',
    token:
      'v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t40KCCWLA7GYL9KFHzKlwY9_RnIfRrMQpueydLEAZGGcA.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9',
    payload: {
      data: 'this is a secret message',
      exp: '2022-01-01T00:00:00+00:00',
    },
    footer: '{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}',
    assertion: '{"test-vector":"4-E-7"}',
    paserk: {
      local: 'k4.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8',
    },
  },
  {
    name: '4-E-8',
    nonce: 'df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8',
    token:
      'v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t5uvqQbMGlLLNYBc7A6_x7oqnpUK5WLvj24eE4DVPDZjw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9',
    payload: {
      data: 'this is a hidden message',
      exp: '2022-01-01T00:00:00+00:00',
    },
    footer: '{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}',
    assertion: '{"test-vector":"4-E-8"}',
    paserk: {
      local: 'k4.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8',
    },
  },
  {
    name: '4-E-9',
    nonce: 'df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8',
    token:
      'v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t6tybdlmnMwcDMw0YxA_gFSE_IUWl78aMtOepFYSWYfQA.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24',
    payload: {
      data: 'this is a hidden message',
      exp: '2022-01-01T00:00:00+00:00',
    },
    footer: "arbitrary-string-that-isn't-json",
    assertion: '{"test-vector":"4-E-9"}',
    paserk: {
      local: 'k4.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8',
    },
  },
  {
    name: '4-S-1',
    token:
      'v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9bg_XBBzds8lTZShVlwwKSgeKpLT3yukTw6JUz3W4h_ExsQV-P0V54zemZDcAxFaSeef1QlXEFtkqxT1ciiQEDA',
    payload: {
      data: 'this is a signed message',
      exp: '2022-01-01T00:00:00+00:00',
    },
    footer: '',
    assertion: '',
    paserk: {
      secret:
        'k4.secret.tMv7Q99M4hByfZU-SnEzB_oZu32fhQQUONnhG5QqN3Qeudu7vAR8A_1wYE4AcfCYfhayi3VyJcEfAEFdDiCxog',
      public: 'k4.public.Hrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI',
    },
  },
  {
    name: '4-S-2',
    token:
      'v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9v3Jt8mx_TdM2ceTGoqwrh4yDFn0XsHvvV_D0DtwQxVrJEBMl0F2caAdgnpKlt4p7xBnx1HcO-SPo8FPp214HDw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9',
    payload: {
      data: 'this is a signed message',
      exp: '2022-01-01T00:00:00+00:00',
    },
    footer: '{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}',
    assertion: '',
    paserk: {
      secret:
        'k4.secret.tMv7Q99M4hByfZU-SnEzB_oZu32fhQQUONnhG5QqN3Qeudu7vAR8A_1wYE4AcfCYfhayi3VyJcEfAEFdDiCxog',
      public: 'k4.public.Hrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI',
    },
  },
  {
    name: '4-S-3',
    token:
      'v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9NPWciuD3d0o5eXJXG5pJy-DiVEoyPYWs1YSTwWHNJq6DZD3je5gf-0M4JR9ipdUSJbIovzmBECeaWmaqcaP0DQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9',
    payload: {
      data: 'this is a signed message',
      exp: '2022-01-01T00:00:00+00:00',
    },
    footer: '{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}',
    assertion: '{"test-vector":"4-S-3"}',
    paserk: {
      secret:
        'k4.secret.tMv7Q99M4hByfZU-SnEzB_oZu32fhQQUONnhG5QqN3Qeudu7vAR8A_1wYE4AcfCYfhayi3VyJcEfAEFdDiCxog',
      public: 'k4.public.Hrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI',
    },
  },
]
const locals = [paseto.V1Local, paseto.V2Local, paseto.V3Local, paseto.V4Local]
const publics = [paseto.V1Public, paseto.V2Public, paseto.V3Public, paseto.V4Public]

for (let index = 0; index < locals.length; index++) {
  const version = locals[index]
  QUnit.module(`v${index + 1}.local.`, (hooks) => {
    const orig = version[kNonce]
    hooks.afterEach(() => (version[kNonce] = orig))
    for (const vector of vectors.filter(({ name }) => name.startsWith(`${index + 1}-E-`))) {
      test(vector.name, testLocal.bind(undefined, vector, version))
    }
  })
}

for (let index = 0; index < publics.length; index++) {
  const version = publics[index]
  QUnit.module(`v${index + 1}.public.`, () => {
    for (const vector of vectors.filter(({ name }) => name.startsWith(`${index + 1}-S-`))) {
      if (name.startsWith('2') || name.startsWith('4')) {
        test(vector.name, testPublicEd25519.bind(undefined, vector, version))
      } else {
        test(vector.name, testPublic.bind(undefined, vector, version))
      }
    }
  })
}
