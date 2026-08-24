# v4/local

Built-in PASETO and PASERK v4.local capability factories backed by standard runtime APIs.

## Key Management

The local key type and factories for generating, importing, and exporting local keys.

| Name | Description |
| :------ | :------ |
| [LocalKey](interfaces/LocalKey.md) | Key used by the built-in v4.local implementations. |
| [ExportKeyFactory](variables/ExportKeyFactory.md) | Built-in PASERK k4.local key-export capability factory. |
| [GenerateKeyFactory](variables/GenerateKeyFactory.md) | Built-in v4.local symmetric-key generation capability factory. |
| [ImportKeyFactory](variables/ImportKeyFactory.md) | Built-in PASERK k4.local key-import capability factory. |

## Key Wrapping

The wrapping key type and its generation, import, and export factories.

| Name | Description |
| :------ | :------ |
| [WrappingKey](interfaces/WrappingKey.md) | Wrapping key handled by the built-in k4 lifecycle capabilities. |
| [ExportWrappingKeyFactory](variables/ExportWrappingKeyFactory.md) | Built-in PASERK k4 wrapping-key export capability factory. |
| [GenerateWrappingKeyFactory](variables/GenerateWrappingKeyFactory.md) | Built-in PASERK k4 wrapping-key generation capability factory. |
| [ImportWrappingKeyFactory](variables/ImportWrappingKeyFactory.md) | Built-in PASERK k4 wrapping-key import capability factory. |
