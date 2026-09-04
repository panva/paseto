






















import {
  LocalDecrypt,
  LocalEncrypt,
  LocalExportKey,
  LocalExportWrappingKey,
  LocalGenerateKey,
  LocalGenerateWrappingKey,
  LocalImportKey,
  LocalImportWrappingKey,
  LocalKeyID,
  LocalUnwrapKey,
  LocalUnwrapKeyWithPassword,
  LocalWrapKey,
  LocalWrapKeyWithPassword,


} from '../index.js'
import {
  decryptLocalV1,
  encryptLocalV1,
  exportLocalKey,
  exportWrappingKey,
  generateLocalKeyLegacy,
  generateWrappingKey,
  importLocalKeyLegacy,
  localKeyFromCryptoKey,
  localKeyToCryptoKey,
  importWrappingKey,
  localPaserkIdLegacy,
  unwrapLocalKeyLegacy,
  unwrapLocalKeyWithPasswordLegacy,
  wrapLocalKeyLegacy,
  wrapLocalKeyWithPasswordLegacy,
} from '../_internal/operations.js'


































export function LocalKeyFromCryptoKey(key           )           {
  return localKeyFromCryptoKey(1, key)
}










export function LocalKeyToCryptoKey(key          )            {
  return localKeyToCryptoKey(1, key)
}






export const GenerateKeyFactory                                                   =
  /* @__PURE__ */ LocalGenerateKey             ({
    version: 1,
    run: (extractable) => generateLocalKeyLegacy(1, extractable),
  })






export const EncryptFactory                                               =
  /* @__PURE__ */ LocalEncrypt             ({ version: 1, run: encryptLocalV1 })






export const DecryptFactory                                               =
  /* @__PURE__ */ LocalDecrypt             ({ version: 1, run: decryptLocalV1 })






export const ImportKeyFactory                                                 =
  /* @__PURE__ */ LocalImportKey             ({
    version: 1,
    run: (paserk, extractable) => importLocalKeyLegacy(1, paserk, extractable),
  })






export const ExportKeyFactory                                                 =
  /* @__PURE__ */ LocalExportKey             ({ version: 1, run: (key) => exportLocalKey(1, key) })






export const KeyIDFactory                                   = /* @__PURE__ */ LocalKeyID   ({
  version: 1,
  run: (paserk) => localPaserkIdLegacy(1, paserk),
})






export const GenerateWrappingKeyFactory             

  = /* @__PURE__ */ LocalGenerateWrappingKey                ({
  version: 1,
  run: (extractable) => generateWrappingKey(1, extractable),
})






export const ImportWrappingKeyFactory                                                            =
  /* @__PURE__ */ LocalImportWrappingKey                ({
    version: 1,
    run: (material, extractable) => importWrappingKey(1, material, extractable),
  })






export const ExportWrappingKeyFactory                                                            =
  /* @__PURE__ */ LocalExportWrappingKey                ({
    version: 1,
    run: (key) => exportWrappingKey(1, key),
  })






export const WrapKeyFactory                                                                   =
  /* @__PURE__ */ LocalWrapKey                                 ({
    version: 1,
    run: (key, wrappingKey) => wrapLocalKeyLegacy(1, key, wrappingKey),
  })






export const UnwrapKeyFactory                                                                     =
  /* @__PURE__ */ LocalUnwrapKey                                 ({
    version: 1,
    run: (paserk, wrappingKey, extractable) =>
      unwrapLocalKeyLegacy(1, paserk, wrappingKey, extractable),
  })






export const WrapKeyWithPasswordFactory                                                           =
  /* @__PURE__ */ LocalWrapKeyWithPassword             ({
    version: 1,
    run: (key, password, options) =>
      wrapLocalKeyWithPasswordLegacy(1, key, password, options ?? {}),
  })






export const UnwrapKeyWithPasswordFactory             

  = /* @__PURE__ */ LocalUnwrapKeyWithPassword             ({
  version: 1,
  run: (paserk, password, limits, extractable) =>
    unwrapLocalKeyWithPasswordLegacy(1, paserk, password, limits, extractable),
})
