# Variable: SealKeyFactory

> `const` **SealKeyFactory**: `CapabilityFactory`<`"local"`, `3`, `"SealKey"`, installed operation below>

Built-in PASERK k3.seal key-sealing capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
SealKey(key: LocalKey, recipient: SealingPublicKey): Promise<SealedLocalPASERK<3>>
```
