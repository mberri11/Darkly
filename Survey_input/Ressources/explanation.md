# Input Validation Bypass — Documentation

## How I Found It

**Initial reconnaissance:**
- Visited `http://192.168.1.16/index.php?page=survey`
- Found survey form with dropdown (values 1-10)
- Opened Firefox DevTools → Network tab
- Submitted form, captured POST: `sujet=2&valeur=1`

**Testing:**
- Used "Edit and Resend" to change `valeur=1` to `valeur=42`
- Server accepted out-of-range value → No validation

## How I Exploited It

**Method 1: Firefox Developer Tools**
1. Submit survey normally
2. DevTools (F12) → Network → Right-click request
3. **Edit and Resend** → Change `valeur=1` to `valeur=42`
4. Send → Flag in response

**Method 2: cURL**
```bash
curl 'http://192.168.1.16/index.php?page=survey' \
  --data 'sujet=2&valeur=42'
```

**Flag obtained:**
```
03a944b434d5baff05f46c4bede5792551a2595574bcafc9a6e25f67c382ccaa
```

## Why It Works

**Vulnerabilities:**
1. **Client-side validation only** → HTML restricts values, server doesn't check
2. **No range validation** → Accepts any integer
3. **Trusts client data** → No server-side verification


## How to Fix It

**Core principle:** Always validate on server. Client validation = UX only, not security.

**Essential fixes:**
1. **Server-side range check** - Verify value is 1-10
2. **Whitelist validation** - Only accept expected values
3. **Type checking** - Ensure integer, not string/injection
4. **Rate limiting** - Prevent spam submissions


## References

- OWASP Input Validation Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html
- CWE-20 — https://cwe.mitre.org/data/definitions/20.html
- CWE-20: Improper Input Validation
- CWE-602: Client-Side Enforcement of Server-Side Security
- OWASP A04:2021 – Insecure Design