<!-- explanation.md -->

# Cookie Tampering / Insecure Client-side Validation — Documentation

## How I Found It

### Step-by-step discovery process

#### Initial reconnaissance
- Visited the target site and opened DevTools → Application / Storage → Cookies.  
- Observed a cookie with a hashed-looking value:

cookie_name = f9aaa3ea3513c13f9b02dac9c6a580b8


*(replace `cookie_name` with the actual cookie key from your lab)*  
- Hypothesized the server accepts a hashed boolean/token in the cookie (e.g., hash("false")) and trusts it.  
- Performed quick tests by changing the cookie to random values and reloading — no access until a correct hash was provided.

#### Identified the vulnerable behaviour
- Server trusts a client-supplied cookie value as authoritative state (e.g., accepted=true) without server-side signature or server-held session binding.  
- The cookie value is a **predictable hash** so an attacker can compute the hash for the desired value (e.g., `true`) and set it in the browser.

---

## How I Exploited It

### Exact commands and payloads used

**1 Inspect the cookie (Chrome DevTools)**  
- DevTools → Application → Storage → Cookies → find cookie key and value.  
- Example found:
cookie_name = f9aaa3ea3513c13f9b02dac9c6a580b8


**2 Determine likely hash algorithm (quick tests)**  
Try common algorithms locally (no newline, exact casing):
#bash:
# MD5
echo -n "true" | md5sum

# SHA1
echo -n "true" | sha1sum

# SHA256
echo -n "true" | sha256sum

# if these don't match, test variations (capitalization, "false", suspected salt):

echo -n "False" | md5sum
echo -n "false" | md5sum
echo -n "salt:true" | md5sum   # if you suspect a salt like "salt:"


**3 Compute the correct hash for the desired value**  
(Example: app uses MD5 and desired value is true)
#bash
echo -n "true" | md5sum
# example output: b326b5062b2f0e69046810717534cb09  -
# HASH_VALUE = b326b5062b2f0e69046810717534cb09


**4 Set the cookie value in the browser (Chrome DevTools)**  
- DevTools → Application → Storage → Cookies → find cookie key and value.  
- Replace the cookie value with the correct hash.

---

## Why It Works

### Underlying vulnerability explanation

- PClient-side trust: The server trusts a cookie value sent by the client as evidence of a state (e.g., acceptance/authentication).
- Predictable hash: The cookie is a simple hash of a small set of possible values (e.g., true / false) — attacker can compute the corresponding hash.
- No signing or server-side verification: The server does not sign (HMAC) or verify the cookie against a server-side secret or session store.use easily guessed passwords (rockyou matches).
- No binding or expiry: Cookie is static and not bound to server-side session, user id, or expiry, making it forgeable/replayable.

Technical flow:
```
Client inspects cookie -> sees hashed value for 'false'
Attacker computes hash('true') -> sets cookie to that hash
Browser sends forged cookie -> server accepts it and returns protected content (flag)

```

---

## How to Fix It

### Security recommendations (short & actionable)

**Immediate / short-term**

1• Do not trust client-provided booleans or flags. Keep authoritative state on the server (session store).
2• Use signed cookies (HMAC) or encrypted cookies so tampering is detectable:
    • Server must create value.signature = HMAC(secret, value) and verify signature on each request.
3• Use HttpOnly & Secure flags on cookies to prevent modification by JS and require HTTPS:
Set-Cookie: auth=<value>;<other flags>; HttpOnly; Secure; SameSite=Lax; Path=/
4• Use opaque session identifiers (random session ID stored server-side) instead of encoding state directly in cookies.


**Medium / long-term**

1• Bind tokens to session/user and set expirations. Include user-id or session-id in the signed data.
2• Use strong MAC algorithms (HMAC-SHA256 with a secret).
3• Rotate and revoke secrets when needed and implement logout/invalidate flows. 
4• Server-side validation on sensitive actions — require server checks before revealing flags or performing privileged operations. 
5• Monitor & alert for unusual cookie values or sudden use of forged cookies.

Example: server-side signing (pseudocode)
```
# create signed cookie
value = "true"
signature = HMAC_SHA256(secret_key, value)
cookie = value + "." + signature
Set-Cookie: auth=cookie; HttpOnly; Secure

# on request
[value, signature] = split(req.cookies.auth, ".")
if HMAC_SHA256(secret_key, value) != signature:
    deny()
else:
    # accept and use server-side checked value
```

---

## Testing after fixes

- Attempt the same tampering (change cookie to a computed hash) — server should reject it.
- Verify that only server-issued signed cookies are accepted. 
- Confirm cookies are HttpOnly and Secure. 
- Ensure protected content (flags) appears only when server-side session state authorizes it.
- Check logs/alerts for tampering attempts.

---

## References

- OWASP Session Management Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- OWASP Authentication Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- OWASP Cryptographic Storage Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
- HMAC (RFC 2104) — https://tools.ietf.org/html/rfc2104