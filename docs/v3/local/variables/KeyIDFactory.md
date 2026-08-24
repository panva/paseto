# Variable: KeyIDFactory

> `const` **KeyIDFactory**: `CapabilityFactory`<`"local"`, `3`, `"KeyID"`, installed operation below>

Built-in PASERK k3.lid identifier capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
KeyID(paserk: LocalKeyIDInput<3>): Promise<LocalIdPASERK<3>>
```
