# Hidden Field Manipulation Vulnerability

## How I Found It

### Step-by-Step Discovery Process

1. **Initial Reconnaissance**
   - Navigated to the password recovery page at `http://192.168.1.16/?page=recover`
   - Observed a simple form with a "Submit" button but no visible email input field

2. **Source Code Analysis**
   - Right-clicked on the page and selected "View Page Source" (or pressed `Ctrl+U`)
   - Examined the HTML form structure
   - Discovered a hidden input field:
   ```html
   <input type="hidden" name="mail" value="webmaster@borntosec.com" maxlength="15">
   ```

3. **Vulnerability Identification**
   - Recognized that the email address was hardcoded in a client-side hidden field
   - Realized that hidden fields can be modified before form submission
   - Suspected that the server might not validate ownership of the email address

## How I Exploited It

### Method 1: Using Browser Developer Tools

1. **Open Developer Tools**
   - Right-click on the page and select "Inspect Element"
   - Or press `F12` or `Ctrl+Shift+I`

2. **Locate the Hidden Field**
   - In the Elements/Inspector tab, find the form element
   - Locate the line:
   ```html
   <input type="hidden" name="mail" value="webmaster@borntosec.com" maxlength="15">
   ```

3. **Modify the Value**
   - Double-click on the value `webmaster@borntosec.com`
   - Change it to any email address (e.g., `attacker@evil.com`)
   - Or right-click the element → Edit as HTML → modify the value

4. **Submit the Form**
   - Click the "Submit" button
   - The modified email value is sent to the server

5. **Result**
   - The application accepted the modified email
   - Flag was returned, confirming the vulnerability

## Why It Works

### Technical Explanation

**Root Cause: Client-Side Trust**

The vulnerability exists because the application violates a fundamental security principle: **Never trust client-side data**.

1. **Hidden Fields Are Not Secure**
   - `type="hidden"` only hides the field from visual display
   - The field is still present in the HTML source code
   - Clients have full control over all form data they submit
   - Hidden fields can be modified using:
     - Browser Developer Tools
     - Proxy interceptors (Burp Suite, OWASP ZAP)
     - Direct HTTP requests (cURL, Postman)
     - Browser console JavaScript

2. **Missing Server-Side Validation**
   - The server accepts the `mail` parameter without validation
   - No verification that the requester owns or has permission for that email
   - No session-based authentication to link the request to a logged-in user

3. **Attack Vector**
   - Attacker modifies the hidden email field to any target email
   - Server processes the request without authorization checks
   - Password reset link/credentials sent to attacker-controlled email
   - Or in this case, reveals sensitive information (the flag)

### Security Impact

**Severity: HIGH to CRITICAL**

This vulnerability allows:
- **Account Takeover**: Request password resets for any user account
- **Broken Access Control**: Access resources belonging to other users
- **Privacy Breach**: Obtain information about other users
- **No Authentication Required**: Attack can be performed anonymously

### OWASP Classification

- **Primary**: A01:2021 – Broken Access Control
- **Secondary**: A04:2021 – Insecure Design
- **Related**: A08:2021 – Software and Data Integrity Failures
- **Legacy**: A4:2017 – Insecure Direct Object References (IDOR)

## How to Fix It

### Immediate Solutions

1. **Server-Side Email Handling**

2. **Remove Hidden Field Entirely**

### Comprehensive Security Measures

1. **Input Validation**
   - Validate all user inputs on the server side
   - Never trust any data coming from the client
   - Verify ownership/authorization for all operations

2. **Session Management**

3. **Rate Limiting**

4. **Secure Password Reset Flow**
   ```
   Proper implementation:
   1. User enters their email (visible input, not hidden)
   2. Server validates email format
   3. Server checks if email exists (don't reveal if it doesn't)
   4. Generate secure random token
   5. Store token in database with expiration
   6. Send reset link to email: /reset?token=<secure_token>
   7. Verify token on reset page
   8. Allow password change only with valid, non-expired token
   ```
5. **Security Token Implementation**

### Best Practices

- **Principle of Least Privilege**: Users should only access their own data
- **Defense in Depth**: Multiple layers of security controls
- **Fail Securely**: Default to denying access when in doubt
- **Security by Design**: Build security into the application from the start
- **Logging and Monitoring**: Log all password reset attempts for security analysis

## References

- [OWASP Top 10 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP Testing Guide - Testing for IDOR](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
- [CWE-472: External Control of Assumed-Immutable Web Parameter](https://cwe.mitre.org/data/definitions/472.html)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)

## Conclusion

Hidden form fields should never be used for security-sensitive data or access control decisions. All authorization and validation must occur server-side using trusted data sources like authenticated sessions and database records. Client-side data, including hidden fields, cookies, and URL parameters, must always be treated as untrusted input and validated thoroughly before use.