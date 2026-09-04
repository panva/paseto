



















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
  PublicSign,
  PublicVerify,


} from '../index.js'
import {
  exportPublicKey,
  exportSecretKey,
  exportWrappingKey,
  generatePublicKeyPairV2,
  generateWrappingKey,
  getPublicKey,
  importPublicKeyV2,
  importSecretKeyV2,
  importWrappingKey,
  publicKeyFromCryptoKeyV2,
  publicKeyToCryptoKey,
  secretKeyFromCryptoKeyV2,
  secretKeyToCryptoKey,
  signPublicV2,
  verifyPublicV2,
} from '../_internal/operations.js'






















export async function PublicKeyFromCryptoKey(key           )                     {
  return await publicKeyFromCryptoKeyV2(key)
}







export function PublicKeyToCryptoKey(key           )            {
  return publicKeyToCryptoKey(2, key)
}


































export async function SecretKeyFromCryptoKey(key           )                     {
  return await secretKeyFromCryptoKeyV2(key)
}










export function SecretKeyToCryptoKey(key           )            {
  return secretKeyToCryptoKey(2, key)
}






export const GenerateKeyPairFactory             

  = /* @__PURE__ */ PublicGenerateKeyPair                         ({
  version: 2,
  run: generatePublicKeyPairV2,
})






export const SignFactory                                              = /* @__PURE__ */ PublicSign 


 ({ version: 2, run: signPublicV2 })






export const VerifyFactory                                                =
  /* @__PURE__ */ PublicVerify              ({ version: 2, run: verifyPublicV2 })






export const ImportPublicKeyFactory                                                         =
  /* @__PURE__ */ PublicImportPublicKey              ({ version: 2, run: importPublicKeyV2 })






export const ExportPublicKeyFactory                                                         =
  /* @__PURE__ */ PublicExportPublicKey              ({
    version: 2,
    run: (key) => exportPublicKey(2, key),
  })






export const ImportSecretKeyFactory                                                         =
  /* @__PURE__ */ PublicImportSecretKey              ({ version: 2, run: importSecretKeyV2 })






export const ExportSecretKeyFactory                                                         =
  /* @__PURE__ */ PublicExportSecretKey              ({
    version: 2,
    run: (key) => exportSecretKey(2, key),
  })






export const GetPublicKeyFactory                                                                 =
  /* @__PURE__ */ PublicGetPublicKey                         ({
    version: 2,
    run: (key) => getPublicKey(2, key),
  })






export const GenerateWrappingKeyFactory             

  = /* @__PURE__ */ PublicGenerateWrappingKey                ({
  version: 2,
  run: (extractable) => generateWrappingKey(2, extractable),
})






export const ImportWrappingKeyFactory                                                             =
  /* @__PURE__ */ PublicImportWrappingKey                ({
    version: 2,
    run: (material, extractable) => importWrappingKey(2, material, extractable),
  })






export const ExportWrappingKeyFactory                                                             =
  /* @__PURE__ */ PublicExportWrappingKey                ({
    version: 2,
    run: (key) => exportWrappingKey(2, key),
  })
