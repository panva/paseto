const test = require('ava')

const privateRsaKey = '-----BEGIN RSA PRIVATE KEY-----\n' +
  'MIIEowIBAAKCAQEAyaTgTt53ph3p5GHgwoGWwz5hRfWXSQA08NCOwe0FEgALWos9\n' +
  'GCjNFCd723nCHxBtN1qd74MSh/uN88JPIbwxKheDp4kxo4YMN5trPaF0e9G6Bj1N\n' +
  '02HnanxFLW+gmLbgYO/SZYfWF/M8yLBcu5Y1Ot0ZxDDDXS9wIQTtBE0ne3YbxgZJ\n' +
  'AZTU5XqyQ1DxdzYyC5lF6yBaR5UQtCYTnXAApVRuUI2Sd6L1E2vl9bSBumZ5IpNx\n' +
  'kRnAwIMjeTJB/0AIELh0mE5vwdihOCbdV6alUyhKC1+1w/FW6HWcp/JG1kKC8DPI\n' +
  'idZ78Bbqv9YFzkAbNni5eSBOsXVBKG78Zsc8owIDAQABAoIBAF22jLDa34yKdns3\n' +
  'qfd7to+C3D5hRzAcMn6Azvf9qc+VybEI6RnjTHxDZWK5EajSP4/sQ15e8ivUk0Jo\n' +
  'WdJ53feL+hnQvwsab28gghSghrxM2kGwGA1XgO+SVawqJt8SjvE+Q+//01ZKK0Oy\n' +
  'A0cDJjX3L9RoPUN/moMeAPFw0hqkFEhm72GSVCEY1eY+cOXmL3icxnsnlUD//SS9\n' +
  'q33RxF2y5oiW1edqcRqhW/7L1yYMbxHFUcxWh8WUwjn1AAhoCOUzF8ZB+0X/PPh+\n' +
  '1nYoq6xwqL0ZKDwrQ8SDhW/rNDLeO9gic5rl7EetRQRbFvsZ40AdsX2wU+lWFUkB\n' +
  '42AjuoECgYEA5z/CXqDFfZ8MXCPAOeui8y5HNDtu30aR+HOXsBDnRI8huXsGND04\n' +
  'FfmXR7nkghr08fFVDmE4PeKUk810YJb+IAJo8wrOZ0682n6yEMO58omqKin+iIUV\n' +
  'rPXLSLo5CChrqw2J4vgzolzPw3N5I8FJdLomb9FkrV84H+IviPIylyECgYEA3znw\n' +
  'AG29QX6ATEfFpGVOcogorHCntd4niaWCq5ne5sFL+EwLeVc1zD9yj1axcDelICDZ\n' +
  'xCZynU7kDnrQcFkT0bjH/gC8Jk3v7XT9l1UDDqC1b7rm/X5wFIZ/rmNa1rVZhL1o\n' +
  '/tKx5tvM2syJ1q95v7NdygFIEIW+qbIKbc6Wz0MCgYBsUZdQD+qx/xAhELX364I2\n' +
  'epTryHMUrs+tGygQVrqdiJX5dcDgM1TUJkdQV6jLsKjPs4Vt6OgZRMrnuLMsk02R\n' +
  '3M8gGQ25ok4f4nyyEZxGGWnVujn55KzUiYWhGWmhgp18UCkoYa59/Q9ss+gocV9h\n' +
  'B9j9Q43vD80QUjiF4z0DQQKBgC7XQX1VibkMim93QAnXGDcAS0ij+w02qKVBjcHk\n' +
  'b9mMBhz8GAxGOIu7ZJafYmxhwMyVGB0I1FQeEczYCJUKnBYN6Clsjg6bnBT/z5bJ\n' +
  'x/Jx1qCzX3Uh6vLjpjc5sf4L39Tyye1u2NXQmZPwB5x9BdcsFConSq/s4K1LJtUT\n' +
  '3KFxAoGBANGcQ8nObi3m4wROyKrkCWcWxFFMnpwxv0pW727Hn9wuaOs4UbesCnwm\n' +
  'pcMTfzGUDuzYXCtAq2pJl64HG6wsdkWmjBTJEpm6b9ibOBN3qFV2zQ0HyyKlMWxI\n' +
  'uVSj9gOo61hF7UH9XB6R4HRdlpBOuIbgAWZ46dkj9/HM9ovdP0Iy\n' +
  '-----END RSA PRIVATE KEY-----'

const { decode, V1 } = require('../../lib')

test('A.1.2.1.  Test Vector v1-S-1', async t => {
  const token = 'v1.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiw' +
                'iZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9cIZKahKeGM5k' +
                'iAS_4D70Qbz9FIThZpxetJ6n6E6kXP_119SvQcnfCSfY_gG3D0Q2v7FEt' +
                'm2Cmj04lE6YdgiZ0RwA41WuOjXq7zSnmmHK9xOSH6_2yVgt207h1_LphJ' +
                'zVztmZzq05xxhZsV3nFPm2cCu8oPceWy-DBKjALuMZt_Xj6hWFFie96Sf' +
                'Q6i85lOsTX8Kc6SQaG-3CgThrJJ6W9DC-YfQ3lZ4TJUoY3QNYdtEgAvp1' +
                'QuWWK6xmIb8BwvkBPej5t88QUb7NcvZ15VyNw3qemQGn2ITSdpdDgwMtp' +
                'flZOeYdtuxQr1DSGO2aQyZl7s0WYn1IjdQFx6VjSQ4yfw'
  const pem = '-----BEGIN PUBLIC KEY-----\n' +
              'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyaTgTt53ph3p\n' +
              '5GHgwoGWwz5hRfWXSQA08NCOwe0FEgALWos9GCjNFCd723nCHxBtN1qd\n' +
              '74MSh/uN88JPIbwxKheDp4kxo4YMN5trPaF0e9G6Bj1N02HnanxFLW+g\n' +
              'mLbgYO/SZYfWF/M8yLBcu5Y1Ot0ZxDDDXS9wIQTtBE0ne3YbxgZJAZTU\n' +
              '5XqyQ1DxdzYyC5lF6yBaR5UQtCYTnXAApVRuUI2Sd6L1E2vl9bSBumZ5\n' +
              'IpNxkRnAwIMjeTJB/0AIELh0mE5vwdihOCbdV6alUyhKC1+1w/FW6HWc\n' +
              'p/JG1kKC8DPIidZ78Bbqv9YFzkAbNni5eSBOsXVBKG78Zsc8owIDAQAB\n' +
              '-----END PUBLIC KEY-----'
  const expected = { data: 'this is a signed message', exp: '2019-01-01T00:00:00+00:00' }

  t.deepEqual(await V1.verify(token, pem, { ignoreExp: true }), expected)
  t.deepEqual(await V1.verify(await V1.sign(expected, privateRsaKey, { iat: false }), pem, { ignoreExp: true }), expected)
  t.deepEqual(decode(token, { parse: false }), { purpose: 'public', version: 'v1', footer: undefined, payload: Buffer.from(JSON.stringify(expected)) })
})

test('A.1.2.2.  Test Vector v1-S-2', async t => {
  const token = 'v1.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiw' +
                'iZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9sBTIb0J_4mis' +
                'AuYc4-6P5iR1rQighzktpXhJ8gtrrp2MqSSDkbb8q5WZh3FhUYuW_rg2X' +
                '8aflDlTWKAqJkM3otjYwtmfwfOhRyykxRL2AfmIika_A-_MaLp9F0iw4S' +
                '1JetQQDV8GUHjosd87TZ20lT2JQLhxKjBNJSwWue8ucGhTgJcpOhXcthq' +
                'az7a2yudGyd0layzeWziBhdQpoBR6ryTdtIQX54hP59k3XCIxuYbB9qJM' +
                'pixiPAEKBcjHT74sA-uukug9VgKO7heWHwJL4Rl9ad21xyNwaxAnwAJ7C' +
                '0fN5oGv8Rl0dF11b3tRmsmbDoIokIM0Dba29x_T3YzOyg.eyJraWQiOiJ' +
                'kWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVx' +
                'biJ9'
  const pem = '-----BEGIN PUBLIC KEY-----\n' +
              'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyaTgTt53ph3p\n' +
              '5GHgwoGWwz5hRfWXSQA08NCOwe0FEgALWos9GCjNFCd723nCHxBtN1qd\n' +
              '74MSh/uN88JPIbwxKheDp4kxo4YMN5trPaF0e9G6Bj1N02HnanxFLW+g\n' +
              'mLbgYO/SZYfWF/M8yLBcu5Y1Ot0ZxDDDXS9wIQTtBE0ne3YbxgZJAZTU\n' +
              '5XqyQ1DxdzYyC5lF6yBaR5UQtCYTnXAApVRuUI2Sd6L1E2vl9bSBumZ5\n' +
              'IpNxkRnAwIMjeTJB/0AIELh0mE5vwdihOCbdV6alUyhKC1+1w/FW6HWc\n' +
              'p/JG1kKC8DPIidZ78Bbqv9YFzkAbNni5eSBOsXVBKG78Zsc8owIDAQAB\n' +
              '-----END PUBLIC KEY-----'
  const expected = {
    payload: { data: 'this is a signed message', exp: '2019-01-01T00:00:00+00:00' },
    footer: Buffer.from(JSON.stringify({ kid: 'dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn' }), 'utf8'),
    version: 'v1',
    purpose: 'public'
  }

  t.deepEqual(await V1.verify(token, pem, { complete: true, ignoreExp: true }), expected)
  t.deepEqual(await V1.verify(await V1.sign(expected.payload, privateRsaKey, { footer: expected.footer, iat: false }), pem, { complete: true, ignoreExp: true }), expected)
  t.deepEqual(decode(token, { parse: false }), { purpose: 'public', version: 'v1', footer: expected.footer, payload: Buffer.from(JSON.stringify(expected.payload)) })
})
