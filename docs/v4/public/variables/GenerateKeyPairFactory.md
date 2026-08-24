# Variable: GenerateKeyPairFactory

> `const` **GenerateKeyPairFactory**: `CapabilityFactory`<`"public"`, `4`, `"GenerateKeyPair"`, installed operation below>

Built-in v4.public signing-key-pair generation capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
GenerateKeyPair(options?: KeyOptions): Promise<KeyPair<PublicKey, SecretKey>>
```
