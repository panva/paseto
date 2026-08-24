# Variable: GenerateWrappingKeyFactory

> `const` **GenerateWrappingKeyFactory**: `CapabilityFactory`<`"local"`, `3`, `"GenerateWrappingKey"`, installed operation below>

Built-in PASERK k3 wrapping-key generation capability factory.

## Installed Operation

Composing this factory installs the following protocol method.

```text
GenerateWrappingKey(options?: KeyOptions): Promise<WrappingKey>
```
