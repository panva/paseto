# Variable: GenerateKeyPairFactory

> `const` **GenerateKeyPairFactory**: `CapabilityFactory`<`"public"`, `1`, `"GenerateKeyPair"`, installed operation below>

Built-in v1.public signing-key-pair generation capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
GenerateKeyPair(options?: KeyOptions): Promise<KeyPair<PublicKey, SecretKey>>
```
