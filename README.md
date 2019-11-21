# Finprint Crypto Utils

Cryptographic functions for use with the
[Finprint protocol](https://github.com/finprint/protocol-pact/),
built using [libsodium](https://github.com/jedisct1/libsodium.js).

## Setup and Installation

```bash
npm install @finprint/crypto-utils
```

Before calling any finprint-crypto functions, you'll need to initialize the library by awaiting the `ready` promise.

```typescript
import * as crypto from '@finprint/crypto-utils'
await crypto.ready
```

## Supported Functions

This module supports only the algorithms and formats used by the Finprint smart contracts.

### Encryption
* X25519-Chacha20-Poly1305 key generation
* X25519-Chacha20-Poly1305 encryption/decryption

### Digest
* blake2b-256

### Encoding
* Base64Url unpadded
