# Variable: GenerateSealingKeyPairFactory

> `const` **GenerateSealingKeyPairFactory**: `CapabilityFactory`<`"local"`, `3`, `"GenerateSealingKeyPair"`, installed operation below>

Built-in PASERK k3.seal recipient key-pair generation capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
GenerateSealingKeyPair(options?: KeyOptions): Promise<KeyPair<SealingPublicKey, SealingSecretKey>>
```
