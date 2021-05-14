# signinja
Elliptic-curve toolset to extract crypto parameters from common formats (GPG, Webauthn/FIDO2), export them or serialize them for OpenSSL.

## Status
Compatible with secp256r1/prime256v1/P-256 for now, supported next: Curve 25519 and secp256k1

One can convert GPG and Webauthn (auth data, attestation, client data, ...) to OpenSSL ASN.1 DER structures.
