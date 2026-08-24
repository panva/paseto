# Variable: GetPublicKeyFactory

> `const` **GetPublicKeyFactory**: `CapabilityFactory`<`"public"`, `3`, `"GetPublicKey"`, installed operation below>

Built-in PASERK k3 public-key derivation capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
GetPublicKey(key: SecretKey): Promise<PublicKey>
```
