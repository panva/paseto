

























import {
  LocalDecrypt,
  LocalEncrypt,
  LocalExportKey,
  LocalExportSealingPublicKey,
  LocalExportSealingSecretKey,
  LocalExportWrappingKey,
  LocalGenerateKey,
  LocalGenerateSealingKeyPair,
  LocalGenerateWrappingKey,
  LocalImportKey,
  LocalImportSealingPublicKey,
  LocalImportSealingSecretKey,
  LocalImportWrappingKey,
  LocalKeyID,
  LocalSealKey,
  LocalUnsealKey,
  LocalUnwrapKey,
  LocalUnwrapKeyWithPassword,
  LocalWrapKey,
  LocalWrapKeyWithPassword,


} from '../index.js'
import {
  decryptLocalV3,
  encryptLocalV3,
  exportLocalKey,
  exportSealingPublicKeyV3,
  exportSealingSecretKeyV3,
  exportWrappingKey,
  generateLocalKeyLegacy,
  generateSealingKeyPairV3,
  generateWrappingKey,
  importLocalKeyLegacy,
  localKeyFromCryptoKey,
  localKeyToCryptoKey,
  importSealingPublicKeyV3,
  importSealingSecretKeyV3,
  importWrappingKey,
  localPaserkIdLegacy,
  sealLocalKeyV3,
  unsealLocalKeyV3,
  unwrapLocalKeyLegacy,
  unwrapLocalKeyWithPasswordLegacy,
  wrapLocalKeyLegacy,
  wrapLocalKeyWithPasswordLegacy,
} from '../_internal/operations.js'



























































export function LocalKeyFromCryptoKey(key           )           {
  return localKeyFromCryptoKey(3, key)
}










export function LocalKeyToCryptoKey(key          )            {
  return localKeyToCryptoKey(3, key)
}






export const GenerateKeyFactory                                                   =
  /* @__PURE__ */ LocalGenerateKey             ({
    version: 3,
    run: (extractable) => generateLocalKeyLegacy(3, extractable),
  })






export const EncryptFactory                                               =
  /* @__PURE__ */ LocalEncrypt             ({ version: 3, run: encryptLocalV3 })






export const DecryptFactory                                               =
  /* @__PURE__ */ LocalDecrypt             ({ version: 3, run: decryptLocalV3 })






export const ImportKeyFactory                                                 =
  /* @__PURE__ */ LocalImportKey             ({
    version: 3,
    run: (paserk, extractable) => importLocalKeyLegacy(3, paserk, extractable),
  })






export const ExportKeyFactory                                                 =
  /* @__PURE__ */ LocalExportKey             ({ version: 3, run: (key) => exportLocalKey(3, key) })






export const KeyIDFactory                                   = /* @__PURE__ */ LocalKeyID   ({
  version: 3,
  run: (paserk) => localPaserkIdLegacy(3, paserk),
})






export const GenerateWrappingKeyFactory             

  = /* @__PURE__ */ LocalGenerateWrappingKey                ({
  version: 3,
  run: (extractable) => generateWrappingKey(3, extractable),
})






export const ImportWrappingKeyFactory                                                            =
  /* @__PURE__ */ LocalImportWrappingKey                ({
    version: 3,
    run: (material, extractable) => importWrappingKey(3, material, extractable),
  })






export const ExportWrappingKeyFactory                                                            =
  /* @__PURE__ */ LocalExportWrappingKey                ({
    version: 3,
    run: (key) => exportWrappingKey(3, key),
  })






export const WrapKeyFactory                                                                   =
  /* @__PURE__ */ LocalWrapKey                                 ({
    version: 3,
    run: (key, wrappingKey) => wrapLocalKeyLegacy(3, key, wrappingKey),
  })






export const UnwrapKeyFactory                                                                     =
  /* @__PURE__ */ LocalUnwrapKey                                 ({
    version: 3,
    run: (paserk, wrappingKey, extractable) =>
      unwrapLocalKeyLegacy(3, paserk, wrappingKey, extractable),
  })






export const WrapKeyWithPasswordFactory                                                           =
  /* @__PURE__ */ LocalWrapKeyWithPassword             ({
    version: 3,
    run: (key, password, options) =>
      wrapLocalKeyWithPasswordLegacy(3, key, password, options ?? {}),
  })






export const UnwrapKeyWithPasswordFactory             

  = /* @__PURE__ */ LocalUnwrapKeyWithPassword             ({
  version: 3,
  run: (paserk, password, limits, extractable) =>
    unwrapLocalKeyWithPasswordLegacy(3, paserk, password, limits, extractable),
})






export const GenerateSealingKeyPairFactory             

  = /* @__PURE__ */ LocalGenerateSealingKeyPair                                       ({
  version: 3,
  run: generateSealingKeyPairV3,
})






export const ImportSealingPublicKeyFactory             

  = /* @__PURE__ */ LocalImportSealingPublicKey                     ({
  version: 3,
  run: importSealingPublicKeyV3,
})






export const ImportSealingSecretKeyFactory             

  = /* @__PURE__ */ LocalImportSealingSecretKey                     ({
  version: 3,
  run: importSealingSecretKeyV3,
})






export const ExportSealingPublicKeyFactory             

  = /* @__PURE__ */ LocalExportSealingPublicKey                     ({
  version: 3,
  run: exportSealingPublicKeyV3,
})






export const ExportSealingSecretKeyFactory             

  = /* @__PURE__ */ LocalExportSealingSecretKey                     ({
  version: 3,
  run: exportSealingSecretKeyV3,
})






export const SealKeyFactory                                                                 =
  /* @__PURE__ */ LocalSealKey                               ({ version: 3, run: sealLocalKeyV3 })






export const UnsealKeyFactory                                                                   =
  /* @__PURE__ */ LocalUnsealKey                               ({
    version: 3,
    run: unsealLocalKeyV3,
  })
