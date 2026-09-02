



















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
  generatePublicKeyPairV4,
  generateWrappingKey,
  getPublicKey,
  importPublicKeyV4,
  importSecretKeyV4,
  importWrappingKey,
  publicKeyFromCryptoKeyV4,
  publicKeyToCryptoKey,
  secretKeyFromCryptoKeyV4,
  secretKeyToCryptoKey,
  signPublicV4,
  verifyPublicV4,
} from '../_internal/operations.js'






















export async function PublicKeyFromCryptoKey(key           )                     {
  return await publicKeyFromCryptoKeyV4(key)
}







export function PublicKeyToCryptoKey(key           )            {
  return publicKeyToCryptoKey(4, key)
}


































export async function SecretKeyFromCryptoKey(key           )                     {
  return await secretKeyFromCryptoKeyV4(key)
}










export function SecretKeyToCryptoKey(key           )            {
  return secretKeyToCryptoKey(4, key)
}






export const GenerateKeyPairFactory             

  = /* @__PURE__ */ PublicGenerateKeyPair                         ({
  version: 4,
  run: generatePublicKeyPairV4,
})






export const SignFactory                                              = /* @__PURE__ */ PublicSign 


 ({ version: 4, run: signPublicV4 })






export const VerifyFactory                                                =
  /* @__PURE__ */ PublicVerify              ({ version: 4, run: verifyPublicV4 })






export const ImportPublicKeyFactory                                                         =
  /* @__PURE__ */ PublicImportPublicKey              ({ version: 4, run: importPublicKeyV4 })






export const ExportPublicKeyFactory                                                         =
  /* @__PURE__ */ PublicExportPublicKey              ({
    version: 4,
    run: (key) => exportPublicKey(4, key),
  })






export const ImportSecretKeyFactory                                                         =
  /* @__PURE__ */ PublicImportSecretKey              ({ version: 4, run: importSecretKeyV4 })






export const ExportSecretKeyFactory                                                         =
  /* @__PURE__ */ PublicExportSecretKey              ({
    version: 4,
    run: (key) => exportSecretKey(4, key),
  })






export const GetPublicKeyFactory                                                                 =
  /* @__PURE__ */ PublicGetPublicKey                         ({
    version: 4,
    run: (key) => getPublicKey(4, key),
  })






export const GenerateWrappingKeyFactory             

  = /* @__PURE__ */ PublicGenerateWrappingKey                ({
  version: 4,
  run: (extractable) => generateWrappingKey(4, extractable),
})






export const ImportWrappingKeyFactory                                                             =
  /* @__PURE__ */ PublicImportWrappingKey                ({
    version: 4,
    run: (material, extractable) => importWrappingKey(4, material, extractable),
  })






export const ExportWrappingKeyFactory                                                             =
  /* @__PURE__ */ PublicExportWrappingKey                ({
    version: 4,
    run: (key) => exportWrappingKey(4, key),
  })
