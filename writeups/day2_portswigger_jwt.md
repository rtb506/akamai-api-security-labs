# JWT Authentication Bypass - Algorithm None Attack

## Vulnerability
JWT header allows `"alg": "none"` - server doesn't verify signature

## Attack
1. Decode JWT: `eyJ0eXA...` → `{"alg":"HS256","typ":"JWT"}`
2. Modify: `{"alg":"none","typ":"JWT"}`
3. Change payload: `{"sub":"administrator"}`
4. Remove signature: `eyJhbGc...eyJzdWI....` (no third part)

## Proof
Admin panel access with tampered token

## Akamai Detection
- Posture scan flags: "JWT accepts alg:none"
- Runtime detection: Token claims changed (sub: user → admin)
- Alert: "Privilege escalation via token manipulation"

## Fix
```javascript
// Reject alg:none
if (header.alg === 'none') throw new Error('Invalid algorithm');
// Enforce strong algorithms
const allowedAlgs = ['RS256', 'ES256'];
if (!allowedAlgs.includes(header.alg)) throw error;
```
