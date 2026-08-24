# Type Alias: SecretKeyIDInput\<V>

> **SecretKeyIDInput**<`V`> = [`SecretPASERK`](SecretPASERK.md)<`V`> ∣ [`WrappedSecretPASERK`](WrappedSecretPASERK.md)<`V`> ∣ [`PasswordWrappedSecretPASERK`](PasswordWrappedSecretPASERK.md)<`V`>

A PASERK serialization accepted when deriving a secret key identifier.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | PASERK protocol version encoded by the serialization |
