# Variable: ExportKeyFactory

> `const` **ExportKeyFactory**: `CapabilityFactory`<`"local"`, `4`, `"ExportKey"`, installed operation below>

Built-in PASERK k4.local key-export capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
ExportKey(key: LocalKey): Promise<LocalPASERK<4>>
```
