











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
    version: 4,
    run: (extractable) => generateLocalKeyModern(4, extractable),
  })






export const ImportKeyFactory                                                 =
  /* @__PURE__ */ LocalImportKey             ({
    version: 4,
    run: (paserk, extractable) => importLocalKeyModern(4, paserk, extractable),
  })






export const ExportKeyFactory                                                 =
  /* @__PURE__ */ LocalExportKey             ({ version: 4, run: (key) => exportLocalKey(4, key) })






export const GenerateWrappingKeyFactory             

  = /* @__PURE__ */ LocalGenerateWrappingKey                ({
  version: 4,
  run: (extractable) => generateWrappingKey(4, extractable),
})






export const ImportWrappingKeyFactory                                                            =
  /* @__PURE__ */ LocalImportWrappingKey                ({
    version: 4,
    run: (material, extractable) => importWrappingKey(4, material, extractable),
  })






export const ExportWrappingKeyFactory                                                            =
  /* @__PURE__ */ LocalExportWrappingKey                ({
    version: 4,
    run: (key) => exportWrappingKey(4, key),
  })
