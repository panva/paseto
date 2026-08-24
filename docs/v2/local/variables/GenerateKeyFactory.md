# Variable: GenerateKeyFactory

> `const` **GenerateKeyFactory**: `CapabilityFactory`<`"local"`, `2`, `"GenerateKey"`, installed operation below>

Built-in v2.local symmetric-key generation capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
GenerateKey(options?: KeyOptions): Promise<LocalKey>
```
