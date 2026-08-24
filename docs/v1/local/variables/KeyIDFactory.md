# Variable: KeyIDFactory

> `const` **KeyIDFactory**: `CapabilityFactory`<`"local"`, `1`, `"KeyID"`, installed operation below>

Built-in PASERK k1.lid identifier capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
KeyID(paserk: LocalKeyIDInput<1>): Promise<LocalIdPASERK<1>>
```
