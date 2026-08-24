# Variable: VerifyFactory

> `const` **VerifyFactory**: `CapabilityFactory`<`"public"`, `3`, `"Verify"`, installed operation below>

Built-in v3.public token-verification capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
Verify(key: PublicKey, token: string, options?: ConsumeOptions<3>): Promise<TokenResult>
```
