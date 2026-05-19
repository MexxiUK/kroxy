# Webhook Signature Migration Guide

## Breaking Change in v1.x (Security Hardening Wave 1)

Kroxy webhook signatures were upgraded from an unsafe SHA256(secret || payload)
concatenation to proper **HMAC-SHA256**. This fixes a length-extension attack
vulnerability but is a **breaking change** for any consumer that verifies the
`X-Kroxy-Signature` header.

## What Changed

| Before (vulnerable) | After (secure) |
|---|---|
| `SHA256(secret + payload)` | `HMAC-SHA256(secret, payload)` |
| Hex-encoded 64-char string | Hex-encoded 64-char string |
| Header: `X-Kroxy-Signature` | Header: `X-Kroxy-Signature` |

The header name and format did not change, but the computed value for the same
secret + payload is now different.

## How to Update Your Webhook Consumer

### Python

```python
import hmac
import hashlib

def verify_signature(payload: bytes, secret: str, signature: str) -> bool:
    expected = hmac.new(
        secret.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)
```

### Go

```go
import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
)

func verifySignature(payload []byte, secret, signature string) bool {
    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write(payload)
    expected := hex.EncodeToString(mac.Sum(nil))
    return hmac.Equal([]byte(expected), []byte(signature))
}
```

### Node.js

```javascript
const crypto = require('crypto');

function verifySignature(payload, secret, signature) {
    const expected = crypto
        .createHmac('sha256', secret)
        .update(payload)
        .digest('hex');
    return crypto.timingSafeEqual(
        Buffer.from(expected),
        Buffer.from(signature)
    );
}
```

## Security Notes

- Always use a **constant-time comparison** (`hmac.compare_digest`,
  `crypto.timingSafeEqual`, `hmac.Equal`) to prevent timing attacks.
- The old `SHA256(secret || payload)` construction is vulnerable to
  length-extension attacks and must not be used.
