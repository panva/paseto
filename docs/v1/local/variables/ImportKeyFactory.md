# Variable: ImportKeyFactory

> `const` **ImportKeyFactory**: `CapabilityFactory`<`"local"`, `1`, `"ImportKey"`, installed operation below>

Built-in PASERK k1.local key-import capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
ImportKey(paserk: LocalPASERK<1>, options?: KeyOptions): Promise<LocalKey>
```
