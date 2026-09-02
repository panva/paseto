











import {
  LocalExportKey,
  LocalExportWrappingKey,
  LocalGenerateKey,
  LocalGenerateWrappingKey,
  LocalImportKey,
  LocalImportWrappingKey,

} from '../index.js'
import {
  exportLocalKey,
  exportWrappingKey,
  generateLocalKeyModern,
  generateWrappingKey,
  importLocalKeyModern,
  importWrappingKey,
} from '../_internal/operations.js'






























export const GenerateKeyFactory                                                   =
  /* @__PURE__ */ LocalGenerateKey             ({
    version: 2,
    run: (extractable) => generateLocalKeyModern(2, extractable),
  })






export const ImportKeyFactory                                                 =
  /* @__PURE__ */ LocalImportKey             ({
    version: 2,
    run: (paserk, extractable) => importLocalKeyModern(2, paserk, extractable),
  })






export const ExportKeyFactory                                                 =
  /* @__PURE__ */ LocalExportKey             ({ version: 2, run: (key) => exportLocalKey(2, key) })






export const GenerateWrappingKeyFactory             

  = /* @__PURE__ */ LocalGenerateWrappingKey                ({
  version: 2,
  run: (extractable) => generateWrappingKey(2, extractable),
})






export const ImportWrappingKeyFactory                                                            =
  /* @__PURE__ */ LocalImportWrappingKey                ({
    version: 2,
    run: (material, extractable) => importWrappingKey(2, material, extractable),
  })






export const ExportWrappingKeyFactory                                                            =
  /* @__PURE__ */ LocalExportWrappingKey                ({
    version: 2,
    run: (key) => exportWrappingKey(2, key),
  })
