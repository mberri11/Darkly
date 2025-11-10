# Input Validation Bypass — Documentation

## How I Found It

**Initial reconnaissance:**
- Visited `http://192.168.1.16/index.php?page=survey`
- Found survey form with dropdown select fields (values 1-10)
- Submitted form normally through browser

**Testing for validation:**
- Opened Firefox DevTools → Network tab
- Captured POST request: `sujet=2&valeur=1`
- Hypothesis: Server might not validate submitted values

**Identified vulnerability:**
- Used "Edit and Resend" to modify `valeur=1` → `valeur=42`
- Server accepted out-of-range value without validation
- Response contained flag → no server-side checks

## How I Exploited It

**Method 1: Firefox Developer Tools**

1. Submit survey form normally
2. Open DevTools (F12) → Network tab
3. Right-click POST request → **Edit and Resend**
4. Change request body:
```
sujet=2&valeur=1    → sujet=2&valeur=42
```
5. Send → Flag in response

**Method 2: cURL**
```bash
curl 'http://192.168.1.16/index.php?page=survey' \
  --data 'sujet=2&valeur=42' \
  | grep 'flag is'
```

**Flag obtained:**
```
03a944b434d5baff05f46c4bede5792551a2595574bcafc9a6e25f67c382ccaa
```

## Why It Works

**Vulnerabilities:**
1. **Client-side validation only** → HTML restricts dropdown values, but server doesn't verify
2. **No input range checking** → Accepts any integer value
3. **Trusts client data** → No server-side whitelist validation
4. **Business logic flaw** → Rating scale bypassed (1-10 expected)

**Potential impacts:**
- Poll/voting manipulation
- Data integrity issues
- Skewed statistics
- Bypass rate limiting

**Related:**
- CWE-20: Improper Input Validation
- CWE-602: Client-Side Enforcement of Server-Side Security
- OWASP A03:2021 – Injection
- OWASP A04:2021 – Insecure Design

## How to Fix It

**Immediate fixes:**

1. **Server-side range validation:**
```php
$allowed_subjects = [1, 2, 3];
$allowed_values = range(1, 10);

if (!in_array($_POST['sujet'], $allowed_subjects)) die("Invalid subject");
if (!in_array($_POST['valeur'], $allowed_values)) die("Invalid rating");
```

2. **Type and range checking:**
```php
$valeur = filter_input(INPUT_POST, 'valeur', FILTER_VALIDATE_INT);
if ($valeur === false || $valeur < 1 || $valeur > 10) {
    die("Rating must be between 1 and 10");
}
```

3. **Whitelist approach:**
```php
function validate_survey($sujet, $valeur) {
    $valid = ['1' => range(1, 10), '2' => range(1, 10)];
    return isset($valid[$sujet]) && in_array($valeur, $valid[$sujet]);
}

if (!validate_survey($_POST['sujet'], $_POST['valeur'])) {
    http_response_code(400);
    die("Invalid survey data");
}
```

**Long-term improvements:**

1. **Rate limiting per IP:**
```php
$ip = $_SERVER['REMOTE_ADDR'];
if (isset($_SESSION["survey_$ip"]) && time() - $_SESSION["survey_$ip"] < 86400) {
    die("Already submitted today");
}
$_SESSION["survey_$ip"] = time();
```

2. **CSRF protection:**
```php
if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    die("Invalid request");
}
```

3. **Logging:**
```php
if ($valeur < 1 || $valeur > 10) {
    error_log("Survey manipulation: IP={$_SERVER['REMOTE_ADDR']}, val=$valeur");
}
```

4. **Require authentication** before survey submission

**Testing:**
```bash
# Should fail
curl -X POST -d "sujet=2&valeur=42" http://192.168.1.16/index.php?page=survey

# Should succeed
curl -X POST -d "sujet=2&valeur=8" http://192.168.1.16/index.php?page=survey
```

## References

- OWASP Input Validation Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html
- CWE-20: Improper Input Validation — https://cwe.mitre.org/data/definitions/20.html
- CWE-602: Client-Side Enforcement — https://cwe.mitre.org/data/definitions/602.html