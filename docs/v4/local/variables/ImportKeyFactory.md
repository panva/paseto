# Variable: ImportKeyFactory

> `const` **ImportKeyFactory**: `CapabilityFactory`<`"local"`, `4`, `"ImportKey"`, installed operation below>

Built-in PASERK k4.local key-import capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
ImportKey(paserk: LocalPASERK<4>, options?: KeyOptions): Promise<LocalKey>
```
