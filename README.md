# OAuth Attack Map

## Flows & Where They Break

### Authorization Code Flow
```
Client → Authorization Server (GET /authorize?response_type=code&client_id=...&redirect_uri=...&state=...)
Authorization Server → Client (302 to redirect_uri?code=...&state=...)
Client → Authorization Server (POST /token with code + client_secret)
Authorization Server → Client (access_token + refresh_token)
```

**Attack surfaces:**
- `redirect_uri` validation bypass → code interception
- `state` missing or predictable → CSRF
- Authorization code reuse → depends on server, often works once then error leaks
- Code leakage via Referer header (code in URL, page loads external resource)
- Code leakage via browser history, logs, proxy

---

## redirect_uri Attacks

### Validation Bypass Patterns
Server validates prefix only:
```
registered:   https://app.com/callback
payload:      https://app.com/callback/../attacker
              https://app.com/callback%2f..%2fattacker
```

Server validates suffix only (rare):
```
payload:      https://attacker.com/app.com/callback
```

Exact match but open redirect exists on client:
```
registered:   https://app.com/callback
open redirect: https://app.com/redirect?url=https://attacker.com
payload:      https://app.com/redirect?url=https://attacker.com (passed as redirect_uri)
```

Subdomain matching:
```
registered:   https://*.app.com/callback
payload:      https://attacker.app.com/callback  (if attacker controls subdomain)
```

Path traversal variants:
```
https://app.com/callback%2F%2E%2E%2Fattacker.com
https://app.com/callback/..%2Fattacker.com
https://app.com:443@attacker.com/callback
```

### Stealing the Code
Once redirect_uri points to attacker:
1. Victim visits attacker-controlled page or is redirected there
2. Code lands in attacker's server logs / request handler
3. Attacker exchanges code for token using legitimate client_id + client_secret (if public client, no secret needed)

For confidential clients (secret required): code is useless without secret unless secret is also leaked or guessable.

---

## state Parameter Attacks

### CSRF via Missing state
1. Attacker initiates OAuth flow, gets authorization URL
2. Attacker does NOT follow the redirect
3. Attacker tricks victim into visiting the authorization URL (or the callback URL with attacker's code)
4. Victim's session gets linked to attacker's account (account hijack) OR attacker's session gets victim's tokens

### Predictable state
If `state` is timestamp, sequential ID, or static value — brute forceable or guessable.

### state fixation
Some implementations accept any state value and don't validate it matches what was sent. CSRF still possible.

---

## Token Leakage

### Referer Header
If access token or code appears in URL and page loads subresources (images, scripts, analytics):
```
GET /dashboard?token=eyJ...
→ Referer: https://app.com/dashboard?token=eyJ... sent to every subresource origin
```

### Fragment Leakage (Implicit Flow)
Implicit flow puts token in fragment:
```
https://app.com/callback#access_token=eyJ...
```
Fragment isn't sent to server but is accessible to JavaScript. Any XSS on `app.com` steals it. Postmessage leakage if fragment forwarded incorrectly.

### Token in Logs
- Server-side request logs
- CDN / WAF logs
- Browser history
- Shared proxy environments

---

## Implicit Flow (Deprecated but still present)

```
Client → AS (GET /authorize?response_type=token...)
AS → Client (302 to redirect_uri#access_token=...&expires_in=...)
```

No code exchange, token delivered directly in fragment.

**Attacks:**
- Token substitution: swap tokens between apps using the same AS. App A gets token issued for App B and accepts it if it doesn't validate `aud` claim.
- No refresh token → short-lived but if `expires_in` is long, single theft is enough.
- Fragment can leak via `window.opener`, `document.referrer` in some configurations.

---

## Client Credential Attacks

### Exposed client_secret
Common places:
- Mobile app binary (strings, jadx, apktool)
- JavaScript source (bundled SPAs)
- Public GitHub repos
- Browser DevTools Network tab

With client_id + client_secret on confidential client, attacker can exchange any valid authorization code.

### Weak client_secret
Some servers accept short or predictable secrets. Brute force `/token` endpoint.

---

## PKCE Downgrade

PKCE (Proof Key for Code Exchange) is meant to protect public clients.

```
Client generates: code_verifier (random), code_challenge = SHA256(code_verifier)
Sends code_challenge in /authorize request
Sends code_verifier in /token request
AS verifies: SHA256(code_verifier) == code_challenge
```

**Attacks:**
- Server doesn't enforce PKCE even if client sends it → remove `code_challenge` from authorize request entirely, exchange code without `code_verifier`
- Server accepts `code_challenge_method=plain` → `code_challenge == code_verifier`, leaking verifier in URL leaks enough to exchange
- PKCE not required at all on public clients → classic code interception applies

---

## Token Endpoint Attacks

### Authorization Code Injection
If server doesn't bind code to session/client:
1. Attacker obtains valid authorization code (their own, or stolen)
2. Injects it into victim's callback request (CSRF or open redirect)
3. Victim's session exchanges attacker's code → attacker's account linked to victim's session

### Mix-Up Attack
When client supports multiple AS:
1. Attacker controls one AS
2. Tricks client into sending authorization request to legitimate AS but with attacker's `iss` metadata
3. Client sends code meant for legitimate AS to attacker's token endpoint
4. Attacker extracts code, exchanges with legitimate AS

Requires `iss` parameter validation or JARM binding to prevent.

---

## JWT / Token Attacks (when tokens are JWTs)

### Algorithm Confusion (alg:none)
```json
{"alg":"none","typ":"JWT"}
```
Some libraries accept unsigned tokens if `alg` is set to `none`. Strip signature, modify claims, re-encode.

### RS256 → HS256 Confusion
Server uses RS256 (asymmetric). Public key is known/discoverable.
Forge token signed with HS256 using public key as HMAC secret.
If library auto-selects algorithm from token header — accepted.

### kid Injection
`kid` header specifies which key to use for verification.
```json
{"kid": "../../dev/null", "alg": "HS256"}
```
If server fetches key from filesystem or DB based on `kid`:
- Path traversal → sign with empty string (null file)
- SQL injection in kid parameter → control returned key

### JWT Claim Manipulation
Modify `sub`, `email`, `role`, `scope` claims if signature isn't validated.
Check: does the app validate signature at all? Some decode without verifying.

### Weak Secret (HS256)
Brute force with hashcat:
```
hashcat -a 0 -m 16500 <jwt> wordlist.txt
```

---

## Scope Manipulation

### Scope Upgrade
Add scopes to authorization request that weren't in original registration:
```
?scope=openid email profile admin
```
Server may grant them if not strictly validated against registered scopes.

### Scope Downgrade Attack
If server returns broader scope than requested and client doesn't check, attacker triggers flow requesting minimal scope but gets elevated access.

### Insufficient Scope Validation
Access token accepted by resource server without checking if requested scope covers the action being performed.

---

## Open Redirect Chaining

OAuth provider has open redirect:
```
https://provider.com/logout?next=https://attacker.com
```
Use as `redirect_uri` if provider validates only the domain and not the full path behaviour.

Client app has open redirect:
```
https://app.com/redirect?url=https://attacker.com
```
Register `https://app.com/redirect` as valid redirect_uri (or it's already registered).
Flow: code lands on `https://app.com/redirect?url=https://attacker.com`, app redirects to attacker with code in Referer.

---

## Account Linking / Merging Attacks

### Pre-Account Takeover
1. Attacker creates account with victim's email via OAuth provider
2. Victim later registers via email/password with same email
3. App merges accounts → attacker's OAuth session now accesses victim's account

### Account Fixation via OAuth
1. Attacker links their OAuth identity to a placeholder account
2. Victim registers, app links OAuth identity by email match
3. Attacker's OAuth session → victim's account

Condition: app links OAuth accounts by email without verifying email ownership at link time.

---

## Device Authorization Flow (Device Code)

```
Client → AS (POST /device_authorization)
AS → Client (device_code, user_code, verification_uri)
User visits verification_uri, enters user_code on separate device
Client polls /token with device_code
```

**Attacks:**
- Social engineering: trick user into entering attacker's `user_code` at legitimate `verification_uri`
- `user_code` brute force if short and numeric (e.g. 6 digits = 1,000,000 combinations, rate limiting often weak)
- Polling without user completing auth sometimes returns error details that leak account info

---

## Discovery & Enumeration

Standard endpoints (OIDC discovery):
```
GET /.well-known/openid-configuration
GET /.well-known/oauth-authorization-server
```

Returns: authorization endpoint, token endpoint, JWKS URI, supported scopes, response types, grant types.

JWKS endpoint leaks public keys — useful for RS256→HS256 attack.

Supported `grant_type` values reveal what flows are enabled. `password` grant still enabled? Test it:
```
POST /token
grant_type=password&username=admin&password=admin&client_id=...
```

---

## Checklist

| Vector | Test |
|--------|------|
| redirect_uri bypass | Append path, subdomain, encoded traversal |
| state missing | Remove state param, replay callback |
| state predictable | Observe pattern across flows |
| PKCE enforcement | Remove code_challenge, see if server still issues token |
| client_secret exposed | Check JS source, mobile binary, public repos |
| code reuse | Replay captured code to /token |
| token in Referer | Check network tab for external requests after callback |
| scope escalation | Add admin/write scopes to request |
| JWT alg:none | Modify header, strip signature |
| RS256→HS256 | Fetch public key, re-sign with HMAC |
| kid injection | SQLi or path traversal in kid header |
| account linking by email | Pre-register via OAuth, check merge behaviour |
| device code brute force | Enumerate user_code space |
| password grant enabled | Test on /token endpoint directly |
