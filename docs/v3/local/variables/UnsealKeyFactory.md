# Variable: UnsealKeyFactory

> `const` **UnsealKeyFactory**: `CapabilityFactory`<`"local"`, `3`, `"UnsealKey"`, installed operation below>

Built-in PASERK k3.seal key-unsealing capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
UnsealKey(paserk: SealedLocalPASERK<3>, recipient: SealingSecretKey, options?: KeyOptions): Promise<LocalKey>
```
