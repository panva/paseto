# Variable: GenerateKeyFactory

> `const` **GenerateKeyFactory**: `CapabilityFactory`<`"local"`, `3`, `"GenerateKey"`, installed operation below>

Built-in v3.local symmetric-key generation capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
GenerateKey(options?: KeyOptions): Promise<LocalKey>
```
