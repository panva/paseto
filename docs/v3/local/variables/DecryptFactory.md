# Variable: DecryptFactory

> `const` **DecryptFactory**: `CapabilityFactory`<`"local"`, `3`, `"Decrypt"`, installed operation below>

Built-in v3.local token-decryption capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
Decrypt(key: LocalKey, token: string, options?: ConsumeOptions<3>): Promise<TokenResult>
```
