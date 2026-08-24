# Variable: GenerateKeyPairFactory

> `const` **GenerateKeyPairFactory**: `CapabilityFactory`<`"public"`, `2`, `"GenerateKeyPair"`, installed operation below>

Built-in v2.public signing-key-pair generation capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
GenerateKeyPair(options?: KeyOptions): Promise<KeyPair<PublicKey, SecretKey>>
```
