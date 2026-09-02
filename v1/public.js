






















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
  generatePublicKeyPairV1,
  generateWrappingKey,
  getPublicKey,
  importPublicKeyV1,
  importSecretKeyV1,
  importWrappingKey,
  publicPaserkIdLegacy,
  publicKeyFromCryptoKeyV1,
  publicKeyToCryptoKey,
  secretPaserkIdLegacy,
  secretKeyFromCryptoKeyV1,
  secretKeyToCryptoKey,
  signPublicV1,
  unwrapSecretKeyLegacy,
  unwrapSecretKeyWithPasswordLegacy,
  verifyPublicV1,
  wrapSecretKeyLegacy,
  wrapSecretKeyWithPasswordLegacy,
} from '../_internal/operations.js'






















export async function PublicKeyFromCryptoKey(key           )                     {
  return await publicKeyFromCryptoKeyV1(key)
}







export function PublicKeyToCryptoKey(key           )            {
  return publicKeyToCryptoKey(1, key)
}



































export async function SecretKeyFromCryptoKey(key           )                     {
  return await secretKeyFromCryptoKeyV1(key)
}










export function SecretKeyToCryptoKey(key           )            {
  return secretKeyToCryptoKey(1, key)
}






export const GenerateKeyPairFactory             

  = /* @__PURE__ */ PublicGenerateKeyPair                         ({
  version: 1,
  run: generatePublicKeyPairV1,
})






export const SignFactory                                              = /* @__PURE__ */ PublicSign 


 ({ version: 1, run: signPublicV1 })






export const VerifyFactory                                                =
  /* @__PURE__ */ PublicVerify              ({ version: 1, run: verifyPublicV1 })






export const ImportPublicKeyFactory                                                         =
  /* @__PURE__ */ PublicImportPublicKey              ({ version: 1, run: importPublicKeyV1 })






export const ExportPublicKeyFactory                                                         =
  /* @__PURE__ */ PublicExportPublicKey              ({
    version: 1,
    run: (key) => exportPublicKey(1, key),
  })






export const ImportSecretKeyFactory                                                         =
  /* @__PURE__ */ PublicImportSecretKey              ({ version: 1, run: importSecretKeyV1 })






export const ExportSecretKeyFactory                                                         =
  /* @__PURE__ */ PublicExportSecretKey              ({
    version: 1,
    run: (key) => exportSecretKey(1, key),
  })






export const GetPublicKeyFactory                                                                 =
  /* @__PURE__ */ PublicGetPublicKey                         ({
    version: 1,
    run: (key) => getPublicKey(1, key),
  })






export const PublicKeyIDFactory                                    = /* @__PURE__ */ PublicKeyID   (
  { version: 1, run: (paserk) => publicPaserkIdLegacy(1, paserk) },
)






export const SecretKeyIDFactory                                    = /* @__PURE__ */ SecretKeyID   (
  { version: 1, run: (paserk) => secretPaserkIdLegacy(1, paserk) },
)






export const GenerateWrappingKeyFactory             

  = /* @__PURE__ */ PublicGenerateWrappingKey                ({
  version: 1,
  run: (extractable) => generateWrappingKey(1, extractable),
})






export const ImportWrappingKeyFactory                                                             =
  /* @__PURE__ */ PublicImportWrappingKey                ({
    version: 1,
    run: (material, extractable) => importWrappingKey(1, material, extractable),
  })






export const ExportWrappingKeyFactory                                                             =
  /* @__PURE__ */ PublicExportWrappingKey                ({
    version: 1,
    run: (key) => exportWrappingKey(1, key),
  })






export const WrapSecretKeyFactory             

  = /* @__PURE__ */ PublicWrapSecretKey                                  ({
  version: 1,
  run: (key, wrappingKey) => wrapSecretKeyLegacy(1, key, wrappingKey),
})






export const UnwrapSecretKeyFactory             

  = /* @__PURE__ */ PublicUnwrapSecretKey                                  ({
  version: 1,
  run: (paserk, wrappingKey, extractable) =>
    unwrapSecretKeyLegacy(1, paserk, wrappingKey, extractable),
})






export const WrapSecretKeyWithPasswordFactory             

  = /* @__PURE__ */ PublicWrapSecretKeyWithPassword              ({
  version: 1,
  run: (key, password, options) => wrapSecretKeyWithPasswordLegacy(1, key, password, options ?? {}),
})






export const UnwrapSecretKeyWithPasswordFactory             

  = /* @__PURE__ */ PublicUnwrapSecretKeyWithPassword              ({
  version: 1,
  run: (paserk, password, limits, extractable) =>
    unwrapSecretKeyWithPasswordLegacy(1, paserk, password, limits, extractable),
})
