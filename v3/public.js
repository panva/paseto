






















import {
  PublicExportPublicKey,
  PublicExportSecretKey,
  PublicExportWrappingKey,
  PublicGenerateKeyPair,
  PublicGenerateWrappingKey,
  PublicGetPublicKey,
  PublicImportPublicKey,
  PublicImportSecretKey,
  PublicImportWrappingKey,
  PublicKeyID,
  SecretKeyID,
  PublicSign,
  PublicUnwrapSecretKey,
  PublicUnwrapSecretKeyWithPassword,
  PublicVerify,
  PublicWrapSecretKey,
  PublicWrapSecretKeyWithPassword,


} from '../index.js'
import {
  exportPublicKey,
  exportSecretKey,
  exportWrappingKey,
  generatePublicKeyPairV3,
  generateWrappingKey,
  getPublicKey,
  importPublicKeyV3,
  importSecretKeyV3,
  importWrappingKey,
  publicPaserkIdLegacy,
  publicKeyFromCryptoKeyV3,
  publicKeyToCryptoKey,
  secretPaserkIdLegacy,
  secretKeyFromCryptoKeyV3,
  secretKeyToCryptoKey,
  signPublicV3,
  unwrapSecretKeyLegacy,
  unwrapSecretKeyWithPasswordLegacy,
  verifyPublicV3,
  wrapSecretKeyLegacy,
  wrapSecretKeyWithPasswordLegacy,
} from '../_internal/operations.js'























export async function PublicKeyFromCryptoKey(key           )                     {
  return await publicKeyFromCryptoKeyV3(key)
}







export function PublicKeyToCryptoKey(key           )            {
  return publicKeyToCryptoKey(3, key)
}


































export async function SecretKeyFromCryptoKey(key           )                     {
  return await secretKeyFromCryptoKeyV3(key)
}










export function SecretKeyToCryptoKey(key           )            {
  return secretKeyToCryptoKey(3, key)
}






export const GenerateKeyPairFactory             

  = /* @__PURE__ */ PublicGenerateKeyPair                         ({
  version: 3,
  run: generatePublicKeyPairV3,
})






export const SignFactory                                              = /* @__PURE__ */ PublicSign 


 ({ version: 3, run: signPublicV3 })






export const VerifyFactory                                                =
  /* @__PURE__ */ PublicVerify              ({ version: 3, run: verifyPublicV3 })






export const ImportPublicKeyFactory                                                         =
  /* @__PURE__ */ PublicImportPublicKey              ({ version: 3, run: importPublicKeyV3 })






export const ExportPublicKeyFactory                                                         =
  /* @__PURE__ */ PublicExportPublicKey              ({
    version: 3,
    run: (key) => exportPublicKey(3, key),
  })






export const ImportSecretKeyFactory                                                         =
  /* @__PURE__ */ PublicImportSecretKey              ({ version: 3, run: importSecretKeyV3 })






export const ExportSecretKeyFactory                                                         =
  /* @__PURE__ */ PublicExportSecretKey              ({
    version: 3,
    run: (key) => exportSecretKey(3, key),
  })






export const GetPublicKeyFactory                                                                 =
  /* @__PURE__ */ PublicGetPublicKey                         ({
    version: 3,
    run: (key) => getPublicKey(3, key),
  })






export const PublicKeyIDFactory                                    = /* @__PURE__ */ PublicKeyID   (
  { version: 3, run: (paserk) => publicPaserkIdLegacy(3, paserk) },
)






export const SecretKeyIDFactory                                    = /* @__PURE__ */ SecretKeyID   (
  { version: 3, run: (paserk) => secretPaserkIdLegacy(3, paserk) },
)






export const GenerateWrappingKeyFactory             

  = /* @__PURE__ */ PublicGenerateWrappingKey                ({
  version: 3,
  run: (extractable) => generateWrappingKey(3, extractable),
})






export const ImportWrappingKeyFactory                                                             =
  /* @__PURE__ */ PublicImportWrappingKey                ({
    version: 3,
    run: (material, extractable) => importWrappingKey(3, material, extractable),
  })






export const ExportWrappingKeyFactory                                                             =
  /* @__PURE__ */ PublicExportWrappingKey                ({
    version: 3,
    run: (key) => exportWrappingKey(3, key),
  })






export const WrapSecretKeyFactory             

  = /* @__PURE__ */ PublicWrapSecretKey                                  ({
  version: 3,
  run: (key, wrappingKey) => wrapSecretKeyLegacy(3, key, wrappingKey),
})






export const UnwrapSecretKeyFactory             

  = /* @__PURE__ */ PublicUnwrapSecretKey                                  ({
  version: 3,
  run: (paserk, wrappingKey, extractable) =>
    unwrapSecretKeyLegacy(3, paserk, wrappingKey, extractable),
})






export const WrapSecretKeyWithPasswordFactory             

  = /* @__PURE__ */ PublicWrapSecretKeyWithPassword              ({
  version: 3,
  run: (key, password, options) => wrapSecretKeyWithPasswordLegacy(3, key, password, options ?? {}),
})






export const UnwrapSecretKeyWithPasswordFactory             

  = /* @__PURE__ */ PublicUnwrapSecretKeyWithPassword              ({
  version: 3,
  run: (paserk, password, limits, extractable) =>
    unwrapSecretKeyWithPasswordLegacy(3, paserk, password, limits, extractable),
})
