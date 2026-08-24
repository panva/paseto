# Variable: GenerateKeyPairFactory

> `const` **GenerateKeyPairFactory**: `CapabilityFactory`<`"public"`, `3`, `"GenerateKeyPair"`, installed operation below>

Built-in v3.public signing-key-pair generation capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
GenerateKeyPair(options?: KeyOptions): Promise<KeyPair<PublicKey, SecretKey>>
```
