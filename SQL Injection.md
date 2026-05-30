# DVWA SQL Injection Writeup

Target Application: Damn Vulnerable Web Application (DVWA)
Vulnerability: SQL Injection (SQLi module)

---

# Low Security

## Overview

Opening the SQL Injection module in DVWA at low security, I was presented
with a simple text field asking for a User ID. The page fetches and displays
user information based on whatever ID is entered. My goal was to check
whether the input was being handled safely before it reached the database
query.

---

## Testing the Vulnerability

I started by trying to break out of the expected query structure. Instead
of entering a normal ID, I submitted a classic OR-based payload:

```
' or 1=1#
```

The `'` closes the string literal in the SQL query. The `OR 1=1` condition
is always true, so the WHERE clause matches every row in the table. The `#`
comments out anything that follows in the original query, preventing syntax
errors.

<img width="1009" height="833" alt="Screenshot 2026-05-30 225334" src="https://github.com/user-attachments/assets/d82fd1ef-ec36-4a1e-abf1-193d1515741d" />

Every user in the table was returned immediately — admin, Gordon Brown,
Hack Me, Pablo Picasso, Bob Smith. No authentication, no valid ID, just
a condition that is always true. The injection worked on the first attempt
with no filtering to work around.

---

## Source Code Analysis

DVWA provides a View Source option which showed exactly why this worked:

```php
$id = $_REQUEST['id'];
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
$result = mysqli_query($GLOBALS["___mysqli_ston"], $query);
```

The user input is taken directly from the request and dropped straight
into the query string with no escaping and no parameterisation. The single
quote in the input closes the string literal in the SQL, and everything
after it is interpreted as part of the query itself. There is nothing to
bypass here because there is nothing blocking it.

---

## Impact

If this vulnerability existed in a real application, an attacker could:

- Extract all usernames, password hashes, and any other stored data
- Bypass authentication entirely by manipulating login queries
- Enumerate the full database structure via `information_schema`
- Read files from the server filesystem using `LOAD_FILE()` if permissions allow

---

## Remediation

- Use prepared statements with parameterised queries — never concatenate
  user input into SQL strings
- Use PDO or MySQLi with bound parameters
- Apply the principle of least privilege to the database user
- Never expose raw database errors to the end user

---
---

# Medium Security

## Overview

At medium security, DVWA changes the input from a text field to a dropdown
menu. The idea is that limiting the user to predefined options prevents
injection. I wanted to check whether this protection held up when the
request was intercepted and modified directly.

---

## What Changed

The input is now a dropdown that only presents valid user IDs as options.
Checking the source code revealed the following change on the backend:

```php
$id = $_POST['id'];
$id = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $id);
$query = "SELECT first_name, last_name FROM users WHERE user_id = $id;";
```

Two things stand out here. First, `mysqli_real_escape_string()` is applied —
this escapes special characters like single quotes, which blocks
string-based injection. Second, and critically, the `user_id` column is
compared without quotes around `$id`. That means the value is treated as
a numeric type, and numeric injection does not require quotes at all.
The escaping is irrelevant when the payload contains no quotes to escape.

---

## Testing the Vulnerability

Since the frontend only offers a dropdown, I intercepted the POST request
with Burp Suite and modified the `id` parameter directly before it reached
the server.


The raw request at line 23 shows the injected payload:

```
id=1 or 1=1 UNION SELECT user, password FROM users#
```

No quotes anywhere in this payload — `mysqli_real_escape_string()` has
nothing to act on. The `UNION SELECT` appends a second query that pulls
the `user` and `password` columns from the users table directly onto the
original result set.

<img width="1545" height="741" alt="Screenshot 2026-05-30 230103" src="https://github.com/user-attachments/assets/c7da18c9-b754-47f1-ba1b-cdd1cef8db16" />

The response rendered all usernames alongside their password hashes —
admin, gordonb, 1337, pablo, smithy — every account in the database,
complete with MD5 hashes ready to crack.


---

## Why the Filter Failed

`mysqli_real_escape_string()` is often presented as a safe way to handle
SQL inputs, but it only neutralises string injection by escaping quotes.
When the query compares a numeric column without wrapping the value in
quotes, the escaping is irrelevant — the injection payload needs no quotes.
The dropdown is purely a frontend control that disappears the moment a
request is intercepted. Backend validation should never rely on what
the frontend allows or restricts.

---

## Impact

Same as Low security. Intercepting the request takes about ten seconds
and the dropdown restriction becomes meaningless. Full extraction of
usernames and password hashes in a single query.

---

## Remediation

`mysqli_real_escape_string()` is not a substitute for parameterised
queries. The correct fix is the same as Low security — use prepared
statements with bound parameters. The query should never be constructed
by concatenating user input regardless of what escaping is applied.

---
---

# High Security

## Overview

High security changes the input mechanism entirely. Instead of a field
on the main page, the ID is submitted through a separate popup window and
passed to the query via a session variable. At first this looked like a
more serious attempt at a fix. Reading through the source code revealed it
still was not enough.

---

## What Changed

The source code at this level:

```php
$id = $_SESSION['id'];
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;";
$result = mysqli_query($GLOBALS["___mysqli_tn"], $query);
```

The input now comes from `$_SESSION['id']` instead of directly from
`$_REQUEST`. A `LIMIT 1` clause has also been added, which restricts the
query to a single row. The intent is likely to prevent UNION attacks from
returning multiple rows, and to make the injection harder to reach since
it goes through a session rather than a direct request parameter.

The session value is still set from user input though, and the query is
still built by string concatenation with no parameterisation. The session
is just an extra hop — the input still ends up in the query unsanitised.

---

## Testing the Vulnerability

The separate input page stores whatever is entered into the session, which
is then used in the query when the main page loads. I entered the payload
directly into the session input popup:

```
' or 1=1#
```

<img width="1350" height="567" alt="Screenshot 2026-05-30 230353" src="https://github.com/user-attachments/assets/13a89eee-fa02-4d99-9b65-36210c1fbb1c" />

The main page picked up the session value and ran the query with the
injected payload. All five users were returned despite the `LIMIT 1` clause.

The `LIMIT 1` only restricts how many rows the first part of the SELECT
returns — it does not prevent the injected condition from matching all rows
when `OR 1=1` makes the WHERE clause always true. The limit is applied
after the WHERE filter, so all matching rows still come through.

---

## Why It Still Failed

The session-based input adds friction — the payload has to go through a
separate popup rather than a direct form field. But it changes nothing
about what actually reaches the query. The `LIMIT 1` addition was the only
meaningful defensive change at this level, and it does not prevent
OR-based injection from returning all rows. The root cause — string
concatenation with no parameterisation — was never fixed across any of
the three levels.

---

## Impact

Still fully exploitable. Three security levels, three different delivery
methods, same outcome every time.

---

## Remediation

Across all three levels the correct fix was never applied. The right
solution is parameterised queries using prepared statements:

```php
$stmt = $pdo->prepare("SELECT first_name, last_name FROM users WHERE user_id = ?");
$stmt->execute([$id]);
```

With a prepared statement, the query structure is fixed at compile time.
User input is passed separately as a parameter and is never interpreted
as part of the SQL syntax. No quote, no operator, no encoding trick can
break out of it because the input is data, not code.

Additional hardening:

- Disable detailed database error messages in production
- Apply least privilege to the database account used by the application
- Use a WAF as a secondary layer — but never as a substitute for fixing
  the query itself

---![Uploading Screenshot 2026-05-30 230353.png…]()
