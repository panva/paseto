# Function: InspectFooter()

> **InspectFooter**(`token`): `Uint8Array`

Extracts a token footer without authenticating it.

The returned bytes are suitable for routing to a key, but must not be trusted until the token is
successfully decrypted or verified. This function validates the token header and framing but
deliberately does not decode or validate its payload.

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `token` | `string` | PASETO token whose footer will be decoded |

## Returns

`Uint8Array`
