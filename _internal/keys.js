import { InvalidKeyError,                                        } from '../index.js'

import { copyBytes } from './bytes.js'














































































const localKeys = /* @__PURE__ */ new WeakMap                               ()
const publicKeys = /* @__PURE__ */ new WeakMap                                ()
const secretKeys = /* @__PURE__ */ new WeakMap                                ()
const wrappingKeys = /* @__PURE__ */ new WeakMap                          ()
const sealingPublicKeys = /* @__PURE__ */ new WeakMap                          ()
const sealingSecretKeys = /* @__PURE__ */ new WeakMap                                       ()

export class LocalKeyImpl                                           {
           #brand           
           algorithm                                         
           type = 'secret'         
           kind = 'local'         
           version   
           extractable         

  constructor(
    version   ,
    material                        ,
    extractable         ,
    cryptoKey            ,
  ) {
    this.#brand = undefined
    void this.#brand
    this.algorithm = { name: `PASETO v${version}.local` }
    this.version = version
    this.extractable = extractable
    localKeys.set(this, {
      version,
      material: material === undefined ? undefined : copyBytes(material),
      cryptoKey,
      extractable,
    })
  }
}

export class PublicKeyImpl                                            {
           #brand           
           algorithm                                          
           type = 'public'         
           kind = 'public'         
           version   
           extractable         

  constructor(version   , material                        , cryptoKey           ) {
    this.#brand = undefined
    void this.#brand
    this.algorithm = { name: `PASETO v${version}.public` }
    this.version = version
    this.extractable = cryptoKey.extractable
    publicKeys.set(this, {
      version,
      material: material === undefined ? undefined : copyBytes(material),
      cryptoKey,
      extractable: this.extractable,
    })
  }
}

export class SecretKeyImpl                                            {
           #brand           
           algorithm                                          
           type = 'secret'         
           kind = 'secret'         
           version   
           extractable         

  constructor(
    version   ,
    cryptoKey           ,
    material                        ,
    publicMaterial            ,
    rawPublicMaterial                        ,
    publicCryptoKey           ,
  ) {
    this.#brand = undefined
    void this.#brand
    this.algorithm = { name: `PASETO v${version}.public` }
    this.version = version
    this.extractable = cryptoKey.extractable
    secretKeys.set(this, {
      version,
      material: material === undefined ? undefined : copyBytes(material),
      cryptoKey,
      publicCryptoKey,
      publicMaterial: publicMaterial === undefined ? undefined : copyBytes(publicMaterial),
      rawPublicMaterial: rawPublicMaterial === undefined ? undefined : copyBytes(rawPublicMaterial),
      extractable: cryptoKey.extractable,
    })
  }
}

export class WrappingKeyImpl                                              {
           #brand           
           algorithm                                        
           type = 'secret'         
           kind = 'wrapping'         
           version   
           extractable         

  constructor(version   , material            , extractable         ) {
    this.#brand = undefined
    void this.#brand
    this.algorithm = { name: `PASERK k${version}.wrap` }
    this.version = version
    this.extractable = extractable
    wrappingKeys.set(this, { version, material: copyBytes(material), extractable })
  }
}

export class SealingPublicKeyImpl                                                   {
           #brand           
           algorithm                                        
           type = 'public'         
           kind = 'sealing-public'         
           version   
           extractable = true

  constructor(version   , material            ) {
    this.#brand = undefined
    void this.#brand
    this.algorithm = { name: `PASERK k${version}.seal` }
    this.version = version
    sealingPublicKeys.set(this, { version, material: copyBytes(material), extractable: true })
  }
}

export class SealingSecretKeyImpl                                                   {
           #brand           
           algorithm                                        
           type = 'secret'         
           kind = 'sealing-secret'         
           version   
           extractable         

  constructor(version   , material            , publicMaterial            , extractable         ) {
    this.#brand = undefined
    void this.#brand
    this.algorithm = { name: `PASERK k${version}.seal` }
    this.version = version
    this.extractable = extractable
    sealingSecretKeys.set(this, {
      version,
      material: copyBytes(material),
      publicMaterial: copyBytes(publicMaterial),
      extractable,
    })
  }
}

function keyData                   (
  map                                   ,
  key        ,
  version   ,
  name        ,
)             {
  const data = map.get(key)
  if (!data || data.version !== version) {
    throw new InvalidKeyError(`"${name}" is not a v${version} key for this operation`)
  }
  return data              
}

export function localKeyData                   (
  key        ,
  version   ,
  name         = 'key',
)                  {
  const data = localKeys.get(key)
  if (!data || data.version !== version) {
    throw new InvalidKeyError(`"${name}" is not a v${version} key for this operation`)
  }
  return data                   
}

export function publicKeyData                   (
  key        ,
  version   ,
  name         = 'key',
)                   {
  const data = publicKeys.get(key)
  if (!data || data.version !== version) {
    throw new InvalidKeyError(`"${name}" is not a v${version} key for this operation`)
  }
  return data                    
}

export function secretKeyData                   (key        , version   )                   {
  const data = secretKeys.get(key)
  if (!data || data.version !== version) {
    throw new InvalidKeyError(`"key" is not a v${version} secret key`)
  }
  return data                    
}

export function wrappingKeyData                   (
  key        ,
  version   ,
  name         = 'key',
)             {
  return keyData(wrappingKeys, key, version, name)
}

export function sealingPublicKeyData                   (
  key        ,
  version   ,
  name         = 'key',
)             {
  return keyData(sealingPublicKeys, key, version, name)
}

export function sealingSecretKeyData                   (
  key        ,
  version   ,
)                          {
  const data = sealingSecretKeys.get(key)
  if (!data || data.version !== version) {
    throw new InvalidKeyError(`"key" is not a k${version}.seal secret key`)
  }
  return data                           
}

export function requireExtractable(data                                   )       {
  if (!data.extractable) throw new InvalidKeyError('Key is not extractable')
}
