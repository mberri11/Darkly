# Cookie Tampering — Documentation

## How I Found It

**Initial reconnaissance:**
- Opened DevTools → Application → Cookies
- Found suspicious cookie: `I_am_admin=68934a3e9455fa72420237eb05902327`
- Recognized as MD5 hash (32 hex characters)
- decrypted value: `false`
- Hypothesis: Server trusts client-controlled cookie value

## How I Exploited It

**Identify hash:**
```bash
echo -n "false" | md5sum
# Output: 68934a3e9455fa72420237eb05902327  ← matches!

echo -n "true" | md5sum  
# Output: b326b5062b2f0e69046810717534cb09
```

**Exploit:**
1. Open DevTools → Application → Cookies
2. Change `I_am_admin` value to: `b326b5062b2f0e69046810717534cb09`
3. Refresh page → Flag revealed

**Flag obtained:**
```
df2eb4ba34ed059a1e3e89ff4dfc13445f104a1a52295214def1c4fb1693a5c3
```

## Why It Works

**Vulnerabilities:**
1. **Client-side trust** → Server trusts cookie from attacker-controlled browser
2. **Predictable hash** → MD5 of simple "true"/"false" value
3. **No signing** → No verification cookie wasn't tampered with
4. **No server-side session** → Authorization state stored in cookie

## How to Fix It

**Core principle:** Never trust client data. Store authorization server-side.

**Essential fixes:**
1. **Server-side sessions** - Store user state in server database/memory, not cookies
2. **Signed cookies** - Use HMAC to verify cookie integrity
3. **Secure cookie flags** - HttpOnly, Secure, SameSite
4. **Opaque tokens** - Use random session IDs, not readable data

## References

- OWASP Session Management Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- CWE-565 — https://cwe.mitre.org/data/definitions/565.html
- CWE-565: Reliance on Cookies without Validation
- OWASP A08:2021 – Software and Data Integrity Failures