# Variable: VerifyFactory

> `const` **VerifyFactory**: `CapabilityFactory`<`"public"`, `1`, `"Verify"`, installed operation below>

Built-in v1.public token-verification capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
Verify(key: PublicKey, token: string, options?: ConsumeOptions<1>): Promise<TokenResult>
```
