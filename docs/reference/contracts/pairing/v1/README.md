# ONE.OS pairing contract V1

Deze directory is de versioned, runtime-onafhankelijke contractbron voor Central en Edge.

- `pairing-v1.schema.json`: strict request-/responsevormen. Runtimevalidators mogen strenger zijn maar nooit extra velden of zwakkere formats accepteren.
- `signing-vectors.json`: canonical length-prefixed preimages voor first-PoP, claim-PoP en certificaat-ACK.

Canonical signingbytes gebruiken ASCII-domein plus NUL en daarna per veld `uint16 tag || uint32 length || raw value`, beide big-endian. UUID’s zijn zestien raw bytes van lowercase canonical UUID’s; uint64 is acht bytes big-endian; hashes/nonces zijn raw 32 bytes. Signatures zijn strict unpadded base64url van exact 64 raw `r||s`-bytes, P-256 ECDSA/SHA-256 en low-S.

Deze bestanden bevatten uitsluitend publieke testdata. Private keys, pairingcodes, bootstrap-/recoverysecrets en productiecertificaten horen hier nooit thuis.
