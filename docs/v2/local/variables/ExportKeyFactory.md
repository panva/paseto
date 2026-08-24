# Variable: ExportKeyFactory

> `const` **ExportKeyFactory**: `CapabilityFactory`<`"local"`, `2`, `"ExportKey"`, installed operation below>

Built-in PASERK k2.local key-export capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
ExportKey(key: LocalKey): Promise<LocalPASERK<2>>
```
