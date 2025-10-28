# Secure File Transfer – Design Notes

## Objective
To create a file transfer system that ensures **confidentiality, integrity, and auditability**.

## Security Model
- AES-256-GCM for file encryption (authenticity + confidentiality)
- RSA-4096 OAEP for key encryption
- Client-side encryption only
- HTTPS for transport layer security
- SQLite-based audit logging

## Flow
1. Sender encrypts file.
2. File and encrypted AES key uploaded to server.
3. Server logs activity.
4. Recipient downloads and decrypts file using private key.

## Notes
- Server never accesses plaintext.
- Integrity verified using SHA256.
- Can be extended with JWT auth, ECDH, or blockchain-based logs.
