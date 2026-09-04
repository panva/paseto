


















































































































































































































































































































































































































































































































































































const capabilityFactoryMarker = /* @__PURE__ */ Symbol.for('panva.paseto.capabilityFactory')






















































































































































































































































































































































































































































































































































































































































function validVersion(value         )                   {
  return value === 1 || value === 2 || value === 3 || value === 4
}

function signatureLength(version         )         {
  switch (version) {
    case 1:
      return 256
    case 2:
    case 4:
      return 64
    case 3:
      return 96
  }
}

function createOperation 





 (
  implementation                                         ,
  purpose   ,
  operation   ,
  adapt                                                                ,
)                                {
  const factory = function () {
    if (implementation === null || typeof implementation !== 'object') {
      throw new TypeError('implementation must be an object')
    }
    const version = implementation.version
    const sourceRun = implementation.run
    if (!validVersion(version)) {
      throw new TypeError('implementation has an invalid version')
    }
    if (typeof sourceRun !== 'function') {
      throw new TypeError('implementation has an invalid run function')
    }
    const snapshot                                          = Object.freeze({
      version,
      run: (async (...args         ) => {
        const changed = () => implementation.version !== version || implementation.run !== sourceRun
        if (changed()) {
          throw new TypeError('implementation version or run changed after composition')
        }
        const result = await Reflect.apply(
          sourceRun                               ,
          implementation,
          args,
        )
        if (changed()) {
          throw new TypeError('implementation version or run changed after composition')
        }
        return result
      })     ,
    })
    const run = adapt(snapshot)
    if (typeof run !== 'function') {
      throw new TypeError('capability adapter returned an invalid run function')
    }
    return Object.freeze({ purpose, version: snapshot.version, operation, run })
  }
  Object.defineProperty(factory, capabilityFactoryMarker, { value: true })
  return factory                                 
}

function implementationRun                                              (
  implementation                                         ,
)    {
  return implementation.run
}

function runTokenImplementation   (
  version         ,
  run                  ,
  parameters           ,
  implicitAssertion            ,
)             {
  if (version >= 3) parameters.push(implicitAssertion)
  return Reflect.apply(run, undefined, parameters)              
}









export function LocalGenerateKey                                  (
  implementation                                      ,
)                                                                                     {
  return createOperation(
    implementation,
    'local',
    'GenerateKey',
    (value) => async (options             ) => await value.run(keyExtractable(options)),
  )
}











export function LocalEncrypt                                  (
  implementation                                  ,
)                    








  {
  return createOperation(implementation, 'local', 'Encrypt', (value)                           => {
    return async (key, claims, options) => {
      const resolved                    = optionsObject(options)
      const footer = optionalBytes(resolved.footer, 'footer')
      const implicit = implicitAssertion(value.version, resolved)
      const payload = await runTokenImplementation(
        value.version,
        value.run,
        [key, prepareClaims(claims, resolved), footer],
        implicit,
      )
      checkBytes(payload, 'implementation Encrypt result')
      return formatToken(tokenHeader(value.version, 'local'), payload, footer)
    }
  })
}











export function LocalDecrypt                                  (
  implementation                                  ,
)                    








  {
  return createOperation(implementation, 'local', 'Decrypt', (value)                           => {
    return async (key, token, options) => {
      const resolved                    = optionsObject(options)
      const implicit = implicitAssertion(value.version, resolved)
      const { payload, footer } = parseToken(token, value.version, 'local', resolved)
      const plaintext = await runTokenImplementation(
        value.version,
        value.run,
        [key, payload, footer],
        implicit,
      )
      checkBytes(plaintext, 'implementation Decrypt result')
      const claims = parseClaims(plaintext)
      validateClaims(claims, resolved)
      return { claims, footer: copyBytes(footer) }
    }
  })
}









export function LocalImportKey                                  (
  implementation                                    ,
)                    




  {
  return createOperation(
    implementation,
    'local',
    'ImportKey',
    (value) => async (paserk, options) => await value.run(paserk, keyExtractable(options)),
  )
}









export function LocalExportKey                                  (
  implementation                                    ,
)                                                                                           {
  return createOperation(implementation, 'local', 'ExportKey', implementationRun)
}








export function LocalKeyID                   (
  implementation                             ,
)                    




  {
  return createOperation(implementation, 'local', 'KeyID', implementationRun)
}









export function LocalGenerateWrappingKey                                  (
  implementation                                              ,
)                                                                                             {
  return createOperation(
    implementation,
    'local',
    'GenerateWrappingKey',
    (value) => async (options             ) => await value.run(keyExtractable(options)),
  )
}









export function LocalImportWrappingKey                                  (
  implementation                                            ,
)                    




  {
  return createOperation(
    implementation,
    'local',
    'ImportWrappingKey',
    (value) => async (material, options) => await value.run(material, keyExtractable(options)),
  )
}









export function LocalExportWrappingKey                                  (
  implementation                                            ,
)                                                                                      {
  return createOperation(implementation, 'local', 'ExportWrappingKey', implementationRun)
}











export function LocalWrapKey 




 (
  implementation                                             ,
)                    




  {
  return createOperation(implementation, 'local', 'WrapKey', implementationRun)
}











export function LocalUnwrapKey 




 (
  implementation                                               ,
)                    








  {
  return createOperation(
    implementation,
    'local',
    'UnwrapKey',
    (value) => async (paserk, wrappingKey, options) =>
      await value.run(paserk, wrappingKey, keyExtractable(options)),
  )
}











export function LocalWrapKeyWithPassword                                  (
  implementation                                              ,
)                    








  {
  return createOperation(
    implementation,
    'local',
    'WrapKeyWithPassword',
    (value) => async (key, password, options) => {
      const resolved                         = optionsObject(options)
      validatePasswordWrapOptions(value.version, resolved)
      return await value.run(key, password, resolved)
    },
  )
}











export function LocalUnwrapKeyWithPassword                                  (
  implementation                                                ,
)                    








  {
  return createOperation(
    implementation,
    'local',
    'UnwrapKeyWithPassword',
    (value) => async (paserk, password, options) => {
      const resolved                           = optionsObject(options)
      validatePasswordUnwrapOptions(value.version, resolved)
      const extractable = booleanOption(resolved.extractable, 'extractable', false)
      const limits = { ...resolved }
      delete limits.extractable
      return await value.run(paserk, password, limits                           , extractable)
    },
  )
}













export function LocalGenerateSealingKeyPair                                                   (
  implementation                                                      ,
)                    




  {
  return createOperation(
    implementation,
    'local',
    'GenerateSealingKeyPair',
    (value) => async (options             ) => await value.run(keyExtractable(options)),
  )
}









export function LocalImportSealingPublicKey                                   (
  implementation                                                  ,
)                                                                                                 {
  return createOperation(implementation, 'local', 'ImportSealingPublicKey', implementationRun)
}









export function LocalImportSealingSecretKey                                   (
  implementation                                                  ,
)                    




  {
  return createOperation(
    implementation,
    'local',
    'ImportSealingSecretKey',
    (value) => async (material, options) => await value.run(material, keyExtractable(options)),
  )
}









export function LocalExportSealingPublicKey                                   (
  implementation                                                  ,
)                                                                                            {
  return createOperation(implementation, 'local', 'ExportSealingPublicKey', implementationRun)
}









export function LocalExportSealingSecretKey                                   (
  implementation                                                  ,
)                                                                                            {
  return createOperation(implementation, 'local', 'ExportSealingSecretKey', implementationRun)
}










export function LocalSealKey                                                  (
  implementation                                      ,
)                    




  {
  return createOperation(implementation, 'local', 'SealKey', implementationRun)
}










export function LocalUnsealKey                                                  (
  implementation                                        ,
)                    




  {
  return createOperation(
    implementation,
    'local',
    'UnsealKey',
    (value) => async (paserk, recipient, options) =>
      await value.run(paserk, recipient, keyExtractable(options)),
  )
}













export function PublicGenerateKeyPair                                                 (
  implementation                                              ,
)                    




  {
  return createOperation(
    implementation,
    'public',
    'GenerateKeyPair',
    (value) => async (options             ) => await value.run(keyExtractable(options)),
  )
}











export function PublicSign                                  (
  implementation                                ,
)                    








  {
  return createOperation(implementation, 'public', 'Sign', (value)                         => {
    return async (key, claims, options) => {
      const resolved                    = optionsObject(options)
      const footer = optionalBytes(resolved.footer, 'footer')
      const implicit = implicitAssertion(value.version, resolved)
      const message = prepareClaims(claims, resolved)
      const signature = await runTokenImplementation(
        value.version,
        value.run,
        [key, message, footer],
        implicit,
      )
      checkBytes(signature, 'implementation Sign result', signatureLength(value.version))
      return formatToken(tokenHeader(value.version, 'public'), concat(message, signature), footer)
    }
  })
}











export function PublicVerify                                  (
  implementation                                  ,
)                    








  {
  return createOperation(implementation, 'public', 'Verify', (value)                           => {
    return async (key, token, options) => {
      const resolved                    = optionsObject(options)
      const implicit = implicitAssertion(value.version, resolved)
      const { payload, footer } = parseToken(token, value.version, 'public', resolved)
      const length = signatureLength(value.version)
      if (payload.byteLength <= length) {
        throw new InvalidTokenError('Truncated v' + value.version + '.public payload')
      }
      const message = payload.subarray(0, -length)
      const signature = payload.subarray(-length)
      if (
        (await runTokenImplementation(
          value.version,
          value.run,
          [key, message, signature, footer],
          implicit,
        )) !== true
      ) {
        throw new InvalidTokenError('Token signature verification failed')
      }
      const claims = parseClaims(message)
      validateClaims(claims, resolved)
      return { claims, footer: copyBytes(footer) }
    }
  })
}









export function PublicImportPublicKey                                  (
  implementation                                           ,
)                    




  {
  return createOperation(implementation, 'public', 'ImportPublicKey', implementationRun)
}









export function PublicExportPublicKey                                  (
  implementation                                           ,
)                    




  {
  return createOperation(implementation, 'public', 'ExportPublicKey', implementationRun)
}









export function PublicImportSecretKey                                  (
  implementation                                           ,
)                    




  {
  return createOperation(
    implementation,
    'public',
    'ImportSecretKey',
    (value) => async (paserk, options) => await value.run(paserk, keyExtractable(options)),
  )
}









export function PublicExportSecretKey                                  (
  implementation                                           ,
)                    




  {
  return createOperation(implementation, 'public', 'ExportSecretKey', implementationRun)
}










export function PublicGetPublicKey                                                 (
  implementation                                           ,
)                                                                         {
  return createOperation(implementation, 'public', 'GetPublicKey', implementationRun)
}








export function PublicKeyID                   (
  implementation                              ,
)                    




  {
  return createOperation(implementation, 'public', 'PublicKeyID', implementationRun)
}








export function SecretKeyID                   (
  implementation                              ,
)                    




  {
  return createOperation(implementation, 'public', 'SecretKeyID', implementationRun)
}









export function PublicGenerateWrappingKey                                  (
  implementation                                               ,
)                                                                                              {
  return createOperation(
    implementation,
    'public',
    'GenerateWrappingKey',
    (value) => async (options             ) => await value.run(keyExtractable(options)),
  )
}









export function PublicImportWrappingKey                                  (
  implementation                                             ,
)                    




  {
  return createOperation(
    implementation,
    'public',
    'ImportWrappingKey',
    (value) => async (material, options) => await value.run(material, keyExtractable(options)),
  )
}









export function PublicExportWrappingKey                                  (
  implementation                                             ,
)                                                                                       {
  return createOperation(implementation, 'public', 'ExportWrappingKey', implementationRun)
}











export function PublicWrapSecretKey 




 (
  implementation                                                    ,
)                    




  {
  return createOperation(implementation, 'public', 'WrapSecretKey', implementationRun)
}











export function PublicUnwrapSecretKey 




 (
  implementation                                                      ,
)                    








  {
  return createOperation(
    implementation,
    'public',
    'UnwrapSecretKey',
    (value) => async (paserk, wrappingKey, options) =>
      await value.run(paserk, wrappingKey, keyExtractable(options)),
  )
}











export function PublicWrapSecretKeyWithPassword                                  (
  implementation                                                     ,
)                    








  {
  return createOperation(
    implementation,
    'public',
    'WrapSecretKeyWithPassword',
    (value) => async (key, password, options) => {
      const resolved                         = optionsObject(options)
      validatePasswordWrapOptions(value.version, resolved)
      return await value.run(key, password, resolved)
    },
  )
}











export function PublicUnwrapSecretKeyWithPassword                                  (
  implementation                                                       ,
)                    








  {
  return createOperation(
    implementation,
    'public',
    'UnwrapSecretKeyWithPassword',
    (value) => async (paserk, password, options) => {
      const resolved                           = optionsObject(options)
      validatePasswordUnwrapOptions(value.version, resolved)
      const extractable = booleanOption(resolved.extractable, 'extractable', false)
      const limits = { ...resolved }
      delete limits.extractable
      return await value.run(paserk, password, limits                           , extractable)
    },
  )
}























export class PasetoError                                              extends Error {

           code   






  constructor(code   , message        , options               ) {
    super(message, options)
    this.code = code
    this.name = this.constructor.name
  }
}






export class InvalidTokenError extends PasetoError                             {




  constructor(message         = 'Invalid token', options               ) {
    super('ERR_PASETO_INVALID_TOKEN', message, options)
  }
}






export class InvalidPASERKError extends PasetoError                       {




  constructor(message         = 'Invalid PASERK', options               ) {
    super('ERR_PASERK_INVALID', message, options)
  }
}






export class InvalidKeyError extends PasetoError                           {




  constructor(message         = 'Invalid key', options               ) {
    super('ERR_PASETO_INVALID_KEY', message, options)
  }
}






export class ClaimValidationError extends PasetoError                                {

           claim         






  constructor(message        , claim         , options               ) {
    super('ERR_PASETO_CLAIM_VALIDATION', message, options)
    if (claim !== undefined) this.claim = claim
  }
}






export class UnsupportedAlgorithmError extends PasetoError                                     {




  constructor(message        , options               ) {
    super('ERR_PASETO_UNSUPPORTED_ALGORITHM', message, options)
  }
}

function normalizePasetoError(cause         )          {
  if (cause instanceof PasetoError || cause === null || typeof cause !== 'object') return cause
  const error = cause     




  if (typeof error.message !== 'string') return cause
  const options               = { cause }
  switch (error.code) {
    case 'ERR_PASETO_INVALID_TOKEN':
      return new InvalidTokenError(error.message, options)
    case 'ERR_PASERK_INVALID':
      return new InvalidPASERKError(error.message, options)
    case 'ERR_PASETO_INVALID_KEY':
      return new InvalidKeyError(error.message, options)
    case 'ERR_PASETO_CLAIM_VALIDATION':
      return new ClaimValidationError(
        error.message,
        typeof error.claim === 'string' ? error.claim : undefined,
        options,
      )
    case 'ERR_PASETO_UNSUPPORTED_ALGORITHM':
      return new UnsupportedAlgorithmError(error.message, options)
    default:
      return cause
  }
}





const encoder = /* @__PURE__ */ new TextEncoder()
const decoder = /* @__PURE__ */ new TextDecoder('utf-8', { fatal: true })
const empty = /* @__PURE__ */ new Uint8Array()

function checkBytes(value         , name        , length         )                              {
  if (!(value instanceof Uint8Array) || !(value.buffer instanceof ArrayBuffer)) {
    throw new TypeError(`\"${name}\" must be a Uint8Array backed by an ArrayBuffer`)
  }
  if (length !== undefined && value.byteLength !== length) {
    throw new TypeError(`\"${name}\" must be ${length} bytes`)
  }
}

function copyBytes(value            )             {
  return new Uint8Array(value)
}

function optionalBytes(value                        , name        )             {
  if (value === undefined) return empty
  checkBytes(value, name)
  return copyBytes(value)
}

function concat(...pieces                       )             {
  let length = 0
  for (const piece of pieces) length += piece.byteLength
  const output = new Uint8Array(length)
  let offset = 0
  for (const piece of pieces) {
    output.set(piece, offset)
    offset += piece.byteLength
  }
  return output
}

function ascii(value        )             {
  return encoder.encode(value)
}

function equalBytes(left            , right            )          {
  let mismatch = left.byteLength ^ right.byteLength
  const length = Math.max(left.byteLength, right.byteLength)
  for (let i = 0; i < length; i++) {
    mismatch |=
      (left[i % Math.max(left.byteLength, 1)] ?? 0) ^
      (right[i % Math.max(right.byteLength, 1)] ?? 0)
  }
  return mismatch === 0
}

function fromBase64(input        )             {
  input = input.replaceAll('-', '+').replaceAll('_', '/')
  const binary = atob(input)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

function toBase64Url(input            )         {
  let binary = ''
  const chunk = 0x8000
  for (let offset = 0; offset < input.byteLength; offset += chunk) {
    binary += String.fromCharCode(...input.subarray(offset, offset + chunk))
  }
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '')
}

function toB64u(input            )         {

  return input.toBase64?.({ alphabet: 'base64url', omitPadding: true }) || toBase64Url(input)
}

function b64u(input        )             {

  return Uint8Array.fromBase64?.(input, { alphabet: 'base64url' }) || fromBase64(input)
}

function decodeBase64url(input        , name        )             {
  if (typeof input !== 'string' || !/^[A-Za-z0-9_-]*$/u.test(input) || input.length % 4 === 1) {
    throw new InvalidTokenError(`Invalid base64url in ${name}`)
  }
  try {
    const output = b64u(input)
    if (toB64u(output) !== input) throw new Error('non-canonical')
    return output
  } catch (cause) {
    throw new InvalidTokenError(`Invalid base64url in ${name}`, { cause })
  }
}

function le64(value        )             {
  if (!Number.isSafeInteger(value) || value < 0)
    throw new RangeError('value must be a safe integer')
  const output = new Uint8Array(8)
  let remainder = value
  for (let i = 0; i < 8; i++) {
    output[i] = remainder & 0xff
    remainder = Math.floor(remainder / 256)
  }
  output[7] = output[7]  & 0x7f
  return output
}








export function PAE(pieces                       )             {
  if (!Array.isArray(pieces)) throw new TypeError('"pieces" must be an array')
  const encoded               = [le64(pieces.length)]
  for (const [index, piece] of pieces.entries()) {
    checkBytes(piece, `pieces[${index}]`)
    encoded.push(le64(piece.byteLength), piece)
  }
  return concat(...encoded)
}





function parseClaims(input            )         {
  let json        
  try {
    json = decoder.decode(input)
  } catch (cause) {
    throw new InvalidTokenError('Claims are not valid UTF-8', { cause })
  }
  let claims         
  try {
    claims = JSON.parse(json)
  } catch (cause) {
    throw new InvalidTokenError('Claims are not valid JSON', { cause })
  }
  if (claims === null || typeof claims !== 'object' || Array.isArray(claims)) {
    throw new InvalidTokenError('Claims must be a JSON object')
  }
  return claims          
}

function positiveInteger(value        , name        )         {
  if (!Number.isSafeInteger(value) || value <= 0)
    throw new TypeError(`\"${name}\" must be a positive safe integer`)
  return value
}

function nonnegativeNumber(value        , name        )         {
  if (!Number.isFinite(value) || value < 0)
    throw new TypeError(`\"${name}\" must be a non-negative number`)
  return value
}

function optionsObject                  (value               )    {
  if (value === undefined) return {}     
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('"options" must be an object')
  }
  return value
}

function booleanOption(value         , name        , defaultValue         )          {
  if (value === undefined) return defaultValue
  if (typeof value !== 'boolean') throw new TypeError(`\"${name}\" must be a boolean`)
  return value
}

function stringOption(value         , name        )                     {
  if (value === undefined) return undefined
  if (typeof value !== 'string') throw new TypeError(`\"${name}\" must be a string`)
  return value
}

function currentDate(value                  )       {
  const date = value === undefined ? new Date() : value
  if (!(date instanceof Date) || Number.isNaN(date.valueOf()))
    throw new TypeError('"now" must be a valid Date')
  return new Date(date)
}

function numericDate(value      )         {
  return value.toISOString().replace(/\.\d{3}Z$/u, 'Z')
}

const rfc3339 =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|([+-])(\d{2}):(\d{2}))$/u

function validDay(year        , month        , day        )          {
  if (month < 1 || month > 12 || day < 1) return false
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0)
  const days =
    month === 2
      ? leapYear
        ? 29
        : 28
      : month === 4 || month === 6 || month === 9 || month === 11
        ? 30
        : 31
  return day <= days
}

function claimDate(claims        , name                       )                     {
  const value = claims[name]
  if (value === undefined) return undefined
  if (typeof value !== 'string') {
    throw new ClaimValidationError(`\"${name}\" must be an RFC 3339 date-time string`, name)
  }
  const match = rfc3339.exec(value)
  if (match === null) {
    throw new ClaimValidationError(`\"${name}\" must be an RFC 3339 date-time string`, name)
  }
  const year = Number(match[1])
  const month = Number(match[2])
  const day = Number(match[3])
  const hour = Number(match[4])
  const minute = Number(match[5])
  const second = Number(match[6])
  const offsetHour = match[10] === undefined ? 0 : Number(match[10])
  const offsetMinute = match[11] === undefined ? 0 : Number(match[11])
  if (
    !validDay(year, month, day) ||
    hour > 23 ||
    minute > 59 ||
    second > 59 ||
    offsetHour > 23 ||
    offsetMinute > 59
  ) {
    throw new ClaimValidationError(`\"${name}\" must be a valid RFC 3339 date-time`, name)
  }
  const milliseconds = Number((match[7] ?? '').padEnd(3, '0').slice(0, 3))
  const instant = new Date(0)
  instant.setUTCFullYear(year, month - 1, day)
  instant.setUTCHours(hour, minute, second, milliseconds)
  let timestamp = instant.valueOf()
  if (match[8] !== 'Z') {
    const direction = match[9] === '+' ? 1 : -1
    timestamp -= direction * (offsetHour * 60 + offsetMinute) * 60_000
  }
  return timestamp
}

function stringClaim(claims        , name                               )                     {
  const value = claims[name]
  if (value === undefined) return undefined
  if (typeof value !== 'string')
    throw new ClaimValidationError(`\"${name}\" must be a string`, name)
  return value
}

function prepareClaims(input        , options                       )             {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    throw new TypeError('"claims" must be a JSON object')
  }
  const now = currentDate(options.now)
  const claims = { ...input }          
  const addIssuedAt = booleanOption(options.addIssuedAt, 'addIssuedAt', true)
  const nonExpiring = booleanOption(options.nonExpiring, 'nonExpiring', false)
  const expiresIn =
    options.expiresIn === undefined ? undefined : nonnegativeNumber(options.expiresIn, 'expiresIn')
  if (addIssuedAt && claims.iat === undefined) claims.iat = numericDate(now)
  if (nonExpiring) {
    if (expiresIn !== undefined)
      throw new TypeError('"expiresIn" and "nonExpiring" are mutually exclusive')
    delete claims.exp
  } else if (expiresIn !== undefined) {
    claims.exp = numericDate(new Date(now.valueOf() + expiresIn * 1000))
  } else if (claims.exp === undefined) {
    claims.exp = numericDate(new Date(now.valueOf() + 3_600_000))
  }
  for (const name of ['aud', 'iss', 'sub', 'jti']         ) stringClaim(claims, name)
  for (const name of ['exp', 'iat', 'nbf']         ) claimDate(claims, name)
  let json                    
  try {
    json = JSON.stringify(claims)
  } catch (cause) {
    throw new TypeError('"claims" must be JSON serializable', { cause })
  }
  if (json === undefined) throw new TypeError('"claims" must be JSON serializable')
  const encoded = encoder.encode(json)
  parseClaims(encoded)
  return encoded
}

function expectedValues(value                            )                    {
  if (typeof value === 'string') return [value]
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    value.some((entry) => typeof entry !== 'string')
  ) {
    throw new TypeError('Expected claim values must be a string or non-empty array of strings')
  }
  return value
}

function validateClaims(claims        , options                       )       {
  const now = currentDate(options.now).valueOf()
  const tolerance = nonnegativeNumber(options.clockTolerance ?? 0, 'clockTolerance') * 1000
  const allowNonExpiring = booleanOption(options.allowNonExpiring, 'allowNonExpiring', false)
  const exp = claimDate(claims, 'exp')
  const iat = claimDate(claims, 'iat')
  const nbf = claimDate(claims, 'nbf')
  for (const name of ['aud', 'iss', 'sub', 'jti']         ) stringClaim(claims, name)

  if (exp === undefined && !allowNonExpiring) {
    throw new ClaimValidationError('Missing required "exp" claim', 'exp')
  }
  if (exp !== undefined && now > exp + tolerance) {
    throw new ClaimValidationError('Token has expired', 'exp')
  }
  if (nbf !== undefined && now + tolerance < nbf) {
    throw new ClaimValidationError('Token is not active yet', 'nbf')
  }
  if (iat !== undefined && now + tolerance < iat) {
    throw new ClaimValidationError('Token was issued in the future', 'iat')
  }
  if (options.maxTokenAge !== undefined) {
    const maximum = nonnegativeNumber(options.maxTokenAge, 'maxTokenAge') * 1000
    if (iat === undefined) throw new ClaimValidationError('Missing required "iat" claim', 'iat')
    if (now - tolerance > iat + maximum) throw new ClaimValidationError('Token is too old', 'iat')
  }
  const comparisons                                                                       = [
    ['audience', 'aud'],
    ['issuer', 'iss'],
  ]
  for (const [option, claim] of comparisons) {
    const expected = options[option]
    if (
      expected !== undefined &&
      !expectedValues(expected                              ).includes(claims[claim]          )
    ) {
      throw new ClaimValidationError(`Unexpected \"${claim}\" claim`, claim)
    }
  }
  const subject = stringOption(options.subject, 'subject')
  if (subject !== undefined && claims.sub !== subject) {
    throw new ClaimValidationError('Unexpected "sub" claim', 'sub')
  }
  const tokenIdentifier = stringOption(options.tokenIdentifier, 'tokenIdentifier')
  if (tokenIdentifier !== undefined && claims.jti !== tokenIdentifier) {
    throw new ClaimValidationError('Unexpected "jti" claim', 'jti')
  }
  if (options.requiredClaims !== undefined) {
    if (
      !Array.isArray(options.requiredClaims) ||
      options.requiredClaims.some((name) => typeof name !== 'string')
    ) {
      throw new TypeError('"requiredClaims" must be an array of strings')
    }
    for (const name of options.requiredClaims) {
      if (!Object.hasOwn(claims, name))
        throw new ClaimValidationError(`Missing required \"${name}\" claim`, name)
    }
  }
}





function webCryptoBytes(input            )                          {
  checkBytes(input, 'Web Cryptography input')
  return input                           
}

function unsupportedPrimitive(name        , cause          )                            {
  return new UnsupportedAlgorithmError(
    `${name} is not available from the Web Cryptography runtime API`,
    { cause },
  )
}









export const KDF_ARGON2ID                  = function ()           {
  return {
    type: 'KDF',
    name: 'Argon2id',
    async Derive(password, salt, parameters) {
      checkBytes(password, 'password')
      checkBytes(salt, 'salt')
      const memory = positiveInteger(parameters.memory, 'memory')
      const passes = positiveInteger(parameters.passes, 'passes')
      const parallelism = positiveInteger(parameters.parallelism, 'parallelism')
      const length = positiveInteger(parameters.length, 'length')
      if (memory % 1024 !== 0) {
        throw new RangeError('"memory" must be a whole number of kibibytes')
      }
      if (length > Math.floor(Number.MAX_SAFE_INTEGER / 8)) {
        throw new RangeError('"length" is too large')
      }
      try {
        const key = await crypto.subtle.importKey(
          'raw-secret'         ,
          webCryptoBytes(password),
          { name: 'Argon2id' },
          false,
          ['deriveBits'],
        )
        return new Uint8Array(
          await crypto.subtle.deriveBits(
            {
              name: 'Argon2id',
              nonce: webCryptoBytes(salt),
              memory: memory / 1024,
              passes,
              parallelism,
              version: 0x13,
            }                       ,
            key,
            length * 8,
          ),
        )
      } catch (cause) {
        if (
          cause instanceof TypeError ||
          (typeof DOMException !== 'undefined' &&
            cause instanceof DOMException &&
            cause.name === 'NotSupportedError')
        ) {
          throw unsupportedPrimitive('Argon2id', cause)
        }
        throw cause
      }
    },
  }
}










function tokenHeader(version         , purpose                    )             {
  return ascii(`v${version}.${purpose}.`)
}

function formatToken(header            , payload            , footer            )         {
  const base = `${decoder.decode(header)}${toB64u(payload)}`
  return footer.byteLength === 0 ? base : `${base}.${toB64u(footer)}`
}

function parseToken(
  token        ,
  version         ,
  purpose                    ,
  options                       ,
)              {
  if (typeof token !== 'string') throw new TypeError('"token" must be a string')
  const parts = token.split('.')
  if (parts.length !== 3 && parts.length !== 4) throw new InvalidTokenError('Malformed token')
  if (parts[0] !== `v${version}` || parts[1] !== purpose || parts[2] === '') {
    throw new InvalidTokenError(`Expected a v${version}.${purpose} token`)
  }
  if (parts.length === 4 && parts[3] === '') throw new InvalidTokenError('Empty footer segment')
  const payload = decodeBase64url(parts[2] , 'token payload')
  const footer = parts[3] === undefined ? empty : decodeBase64url(parts[3], 'token footer')
  if (options.footer !== undefined) {
    checkBytes(options.footer, 'footer')
    if (!equalBytes(footer, options.footer))
      throw new InvalidTokenError('Token footer does not match')
  }
  return { payload, footer }
}











export function InspectFooter(token        )             {
  if (typeof token !== 'string') throw new TypeError('"token" must be a string')
  const parts = token.split('.')
  if (parts.length !== 3 && parts.length !== 4) throw new InvalidTokenError('Malformed token')
  if (
    !/^v[1-4]$/u.test(parts[0] ) ||
    (parts[1] !== 'local' && parts[1] !== 'public') ||
    parts[2] === ''
  ) {
    throw new InvalidTokenError('Malformed token header')
  }
  if (parts.length === 4 && parts[3] === '') throw new InvalidTokenError('Empty footer segment')
  return parts[3] === undefined ? copyBytes(empty) : decodeBase64url(parts[3], 'token footer')
}

function implicitAssertion(version         , options        )             {
  if (version < 3 && 'implicitAssertion' in options) {
    throw new TypeError(`v${version} does not support implicit assertions`)
  }
  const value =
    'implicitAssertion' in options
      ? (options                                      ).implicitAssertion
      : undefined
  return optionalBytes(value, 'implicitAssertion')
}

function rejectPasswordOption(version         , options        , name        )       {
  if (name in options) {
    throw new TypeError(`PASERK v${version} does not support "${name}"`)
  }
}

function validatePasswordWrapOptions(version         , options        )       {
  if (version === 1 || version === 3) {
    rejectPasswordOption(version, options, 'memory')
    rejectPasswordOption(version, options, 'passes')
    rejectPasswordOption(version, options, 'parallelism')
    const iterations = (options                          ).iterations
    if (iterations !== undefined) positiveInteger(iterations, 'iterations')
  } else {
    rejectPasswordOption(version, options, 'iterations')
    const { memory, passes, parallelism } = options                          
    if (memory !== undefined) positiveInteger(memory, 'memory')
    if (passes !== undefined) positiveInteger(passes, 'passes')
    if (parallelism !== undefined) positiveInteger(parallelism, 'parallelism')
  }
}

function validatePasswordUnwrapOptions(version         , options        )       {
  if (version === 1 || version === 3) {
    rejectPasswordOption(version, options, 'maxMemory')
    rejectPasswordOption(version, options, 'maxPasses')
    rejectPasswordOption(version, options, 'maxParallelism')
    const maxIterations = (options                            ).maxIterations
    if (maxIterations !== undefined) positiveInteger(maxIterations, 'maxIterations')
  } else {
    rejectPasswordOption(version, options, 'maxIterations')
    const { maxMemory, maxPasses, maxParallelism } = options                            
    if (maxMemory !== undefined) positiveInteger(maxMemory, 'maxMemory')
    if (maxPasses !== undefined) positiveInteger(maxPasses, 'maxPasses')
    if (maxParallelism !== undefined) positiveInteger(maxParallelism, 'maxParallelism')
  }
}






































































































































































































































































































































































































function keyExtractable(options                        )          {
  const resolved = optionsObject(options)
  return booleanOption(resolved.extractable, 'extractable', false)
}








function loadCapability(
  value         ,
  purpose         ,
  version                     ,
)                    {
  let operation                    
  try {
    if (typeof value !== 'function') throw new TypeError('capability factory must be a function')
    if ((value                                           )[capabilityFactoryMarker] !== true) {
      throw new TypeError('capability factory is not recognized; use a paseto operation creator')
    }
    const capability = value()
    if (capability === null || typeof capability !== 'object') {
      throw new TypeError('capability factory must return an object')
    }
    const record = capability                           
    if (typeof record.operation !== 'string' || record.operation.length === 0) {
      throw new TypeError('capability operation is invalid')
    }
    operation = record.operation
    if (record.purpose !== purpose) throw new TypeError('capability purpose does not match')
    if (!validVersion(record.version)) throw new TypeError('capability version is invalid')
    if (version !== undefined && record.version !== version) {
      throw new TypeError('capability version does not match')
    }
    if (typeof record.run !== 'function') throw new TypeError('capability run must be a function')
    return record                                
  } catch (cause) {
    throw new TypeError(
      operation === undefined ? 'Invalid capability factory' : `Invalid "${operation}" capability`,
      { cause },
    )
  }
}

function installCapability(capability                   , methods                         )       {
  if (Object.hasOwn(methods, capability.operation)) {
    throw new TypeError(`Duplicate "${capability.operation}" capability`)
  }
  methods[capability.operation] = async (...args         ) => {
    try {
      return await capability.run(...args)
    } catch (cause) {
      throw normalizePasetoError(cause)
    }
  }
}

const LocalProtocolRuntime = class LocalProtocol {
           version         
           purpose = 'local'         

  constructor(...factories           ) {
    if (factories.length === 0) throw new TypeError('at least one capability factory is required')
    const methods                          = {}
    let version                     
    for (const factory of factories) {
      const capability = loadCapability(factory, 'local', version)
      version ??= capability.version
      installCapability(capability, methods)
    }
    this.version = version 
    Object.assign(this, methods)
    Object.freeze(this)
  }
}

const PublicProtocolRuntime = class PublicProtocol {
           version         
           purpose = 'public'         

  constructor(...factories           ) {
    if (factories.length === 0) throw new TypeError('at least one capability factory is required')
    const methods                          = {}
    let version                     
    for (const factory of factories) {
      const capability = loadCapability(factory, 'public', version)
      version ??= capability.version
      installCapability(capability, methods)
    }
    this.version = version 
    Object.assign(this, methods)
    Object.freeze(this)
  }
}






export const LocalProtocol = LocalProtocolRuntime                                       






export const PublicProtocol = PublicProtocolRuntime                                        
