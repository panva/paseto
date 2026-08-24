# Variable: ImportKeyFactory

> `const` **ImportKeyFactory**: `CapabilityFactory`<`"local"`, `2`, `"ImportKey"`, installed operation below>

Built-in PASERK k2.local key-import capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
ImportKey(paserk: LocalPASERK<2>, options?: KeyOptions): Promise<LocalKey>
```
