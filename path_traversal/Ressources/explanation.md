# Path Traversal Vulnerability - Documentation

## How I Found It

### Step-by-Step Discovery Process

1. **Initial Reconnaissance**
   - Explored the website systematically, examining all pages and functionality
   - Noticed a page that accepts file paths or filenames as parameters
   - Common locations: image viewers, file download features, include parameters, or template loaders

2. **Identified the Vulnerable Parameter**
   - Found a URL parameter that appeared to reference files (`?page=`)
   - Example: `http://192.168.1.16/index.php?page=survey`

3. **Initial Testing**
   - Tested basic path traversal sequences: `../` (dot-dot-slash)
   - Observed the application's response to malformed inputs
   - Confirmed the parameter was processing file paths

4. **Successful Exploitation**
   - Modified the parameter to traverse directories
   - Successfully accessed files outside the intended directory
   - Retrieved sensitive information or the flag

---

## How I Exploited It

### Exact Commands and Payloads Used

**Original URL:**
```
http://192.168.1.16/index.php?page=survey
```

**Exploitation Attempts:**

1. **Basic Traversal:**
```
http://192.168.1.16/index.php?page=../../../etc/passwd
```

**Successful Payload:**
```
http://192.168.1.16/index.php?page=../../../../../../../etc/passwd
```

**Payload Breakdown:**
- Base URL: `http://192.168.1.16/index.php`
- Vulnerable Parameter: `?page=`
- Traversal Sequence: `../../../../../../../` (7 levels up)
- Target File: `etc/passwd`

**Why 7 Directory Traversals?**

Starting from the assumed web directory (likely `/var/www/html/pages/` or similar):
1. `../` → `/var/www/html/`
2. `../` → `/var/www/`
3. `../` → `/var/`
4. `../` → `/` (root directory)
5. `../` → `/` (extra traversals to ensure we reach root)
6. `../` → `/` (redundant but harmless)
7. `../` → `/` (ensures we're at root regardless of starting depth)

Then navigated to: `etc/passwd` (which is `/etc/passwd` from root)

**Note:** Using more `../` than necessary is a common technique because:
- Once you reach the root directory `/`, additional `../` have no effect
- It ensures you reach root regardless of the actual starting directory depth
- It's safer than trying to guess the exact depth

**Result:**
- Successfully accessed: `/etc/passwd`
- Retrieved flag: `b12c4b2cb8094750ae121a676269aa9e2872d07c06e429d25a63196ec1c8c1d0`
- File accessed: System password file containing user account information

---

## Why It Works

### Underlying Vulnerability Explanation

**What is Path Traversal?**

Path Traversal (also known as Directory Traversal or dot-dot-slash attack) is a web security vulnerability that allows an attacker to access files and directories stored outside the web root folder.

**Technical Explanation:**

1. **Lack of Input Validation**
   - The application accepts user input (file path) without proper sanitization
   - No validation on special characters like `../` (parent directory reference)

2. **Direct File System Access**
   - The application directly uses user input to construct file paths
   - Example vulnerable code:
   ```php
   <?php
   $file = $_GET['page'];
   include("/var/www/html/pages/" . $file);
   ?>
   ```

3. **Directory Navigation**
   - `../` means "go up one directory level"
   - By chaining multiple `../` sequences, an attacker can navigate to any directory
   - Example: `../../../etc/passwd` traverses up three levels then into `/etc/`

4. **File System Structure**
   - Linux/Unix file systems have a hierarchical structure
   - `/etc/passwd` contains user account information
   - Other sensitive files: `/etc/shadow`, application config files, source code

**Why My Payload Worked:**

In this specific case:
- **Starting Directory:** The application was serving pages from a subdirectory (likely `/var/www/html/pages/` or `/var/www/html/includes/`)
- **Traversal Used:** `../../../../../../../` (7 levels) to guarantee reaching the root directory `/`
- **Target File:** `/etc/passwd` - a world-readable file on Linux systems
- **No Filtering:** The application accepted the `../` sequence without any sanitization or validation
- **Direct File Inclusion:** The vulnerable code likely used PHP's `include()` or `file_get_contents()` with unsanitized user input

**Technical Flow:**
```
User Input: ../../../../../../../etc/passwd
↓
Application processes: /var/www/html/pages/../../../../../../../etc/passwd
↓
Resolves to: /etc/passwd
↓
File is read and flag is exposed in the content or error message
```

---

## How to Fix It

### Security Recommendations

#### 1. **Input Validation (Primary Defense)**

**Whitelist Approach:**
```php
<?php
// Define allowed files
$allowed_files = ['home', 'about', 'contact', 'products'];
$page = $_GET['page'];

if (in_array($page, $allowed_files)) {
    include("/var/www/html/pages/" . $page . ".php");
} else {
    // Default or error page
    include("/var/www/html/pages/home.php");
}
?>
```

**Benefits:**
- Most secure approach
- Only explicitly allowed files can be accessed
- Simple to implement and maintain

#### 2. **Input Sanitization**

**Remove Dangerous Characters:**
```php
<?php
$page = $_GET['page'];

// Remove directory traversal sequences
$page = str_replace(['../', '..\\', '..', './'], '', $page);

// Ensure it's just a filename
$page = basename($page);

include("/var/www/html/pages/" . $page);
?>
```

**Warning:** Sanitization alone is not sufficient - combine with other methods.

#### 3. **Use Absolute Paths with Validation**

```php
<?php
$base_dir = '/var/www/html/pages/';
$page = $_GET['page'];
$full_path = realpath($base_dir . $page);

// Verify the resolved path is within the allowed directory
if ($full_path && strpos($full_path, $base_dir) === 0) {
    include($full_path);
} else {
    die("Access denied");
}
?>
```

**How it works:**
- `realpath()` resolves all symbolic links and relative references
- Verification ensures the final path is within the intended directory

#### 4. **File System Permissions**

- Run web server with minimal privileges
- Restrict read permissions on sensitive files
- Use containers to isolate the application

#### 5. **Web Application Firewall (WAF)**

- Deploy WAF rules to detect and block path traversal patterns
- Monitor for suspicious patterns: `../`, `..%2F`, encoded sequences

#### 6. **Framework-Level Protection**

- Use modern frameworks that handle file inclusion securely
- Example: Use routing systems instead of direct file includes

```php
// Bad - Direct file inclusion
include($_GET['page']);

// Good - Route-based approach
$routes = [
    'home' => 'HomeController',
    'about' => 'AboutController'
];
```
---

## References

- **OWASP Path Traversal:** https://owasp.org/www-community/attacks/Path_Traversal
- **CWE-22:** Improper Limitation of a Pathname to a Restricted Directory
- **OWASP Testing Guide:** Testing for Path Traversal
