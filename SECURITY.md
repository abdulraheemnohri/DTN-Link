# Security Policy

## Reporting

Open a private security advisory on GitHub or contact the maintainer.

## Principles

- No secrets in the repository; credentials only via environment variables.
- Private keys never leave the device; `*.key`, `*.pem`, `.env` are gitignored.
- EIDs are not identity proofs; all trust decisions use Ed25519 signatures.
- BPSec (RFC 9172) will provide bundle integrity/confidentiality on the wire.
