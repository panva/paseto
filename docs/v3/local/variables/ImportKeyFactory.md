# Variable: ImportKeyFactory

> `const` **ImportKeyFactory**: `CapabilityFactory`<`"local"`, `3`, `"ImportKey"`, installed operation below>

Built-in PASERK k3.local key-import capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
ImportKey(paserk: LocalPASERK<3>, options?: KeyOptions): Promise<LocalKey>
```
