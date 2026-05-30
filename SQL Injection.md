# DVWA SQL Injection Writeup

**Target:** Damn Vulnerable Web Application (DVWA)
**Vulnerability:** SQL Injection

---

# Low Security

The module gives you a text field that takes a User ID and returns the
matching name from the database. No filtering, no validation, nothing.

Tried the most basic payload to see if it would just work:

```
' or 1=1#
```

<img width="1009" height="833" alt="Screenshot 2026-05-30 225334" src="https://github.com/user-attachments/assets/d82fd1ef-ec36-4a1e-abf1-193d1515741d" />

It did. Every user in the table came back — admin, Gordon Brown, Hack Me,
Pablo Picasso, Bob Smith. The `'` breaks out of the string, `OR 1=1` makes
the condition always true, and `#` comments out the rest of the query.

Looking at the source code confirmed why:

```php
$id = $_REQUEST['id'];
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
```

Raw input straight into the query. Nothing to bypass.

**Fix:** Parameterised queries. Never concatenate user input into SQL.

---

# Medium Security

At this level the text field is replaced with a dropdown — only valid IDs
selectable, so you can't type a payload directly. The backend also adds
`mysqli_real_escape_string()` to escape quotes.

The problem is the query itself:

```php
$query = "SELECT first_name, last_name FROM users WHERE user_id = $id;";
```

No quotes around `$id`. It's treated as a number, so the escaping is
completely pointless — a numeric payload has no quotes to escape in the
first place.

Intercepted the POST request in Burp and changed the `id` parameter manually:

```
id=1 or 1=1 UNION SELECT user, password FROM users#
```

<img width="1545" height="741" alt="Screenshot 2026-05-30 230103" src="https://github.com/user-attachments/assets/c7da18c9-b754-47f1-ba1b-cdd1cef8db16" />

Left side is the modified request, right side is the response. Every
username and MD5 hash in the database — admin, gordonb, 1337, pablo,
smithy — all returned in one shot. The dropdown restriction only exists
in the browser, not on the server.

**Fix:** Same as Low. The escaping function doesn't matter when the query
is still built by concatenation.

---

# High Security

This level moves the input to a separate popup window. You submit the ID
there, it gets stored in a session variable, and the main page queries
using that session value. There's also a `LIMIT 1` added to the query.

Source code:

```php
$id = $_SESSION['id'];
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;";
```

The session is just an extra step — whatever you type in the popup still
ends up in the query unchanged.

Entered the payload in the session input popup:

```
' or 1=1#
```

<img width="1350" height="567" alt="Screenshot 2026-05-30 225307" src="https://github.com/user-attachments/assets/13a89eee-fa02-4d99-9b65-36210c1fbb1c" />

<img width="1289" height="563" alt="Screenshot 2026-05-30 225913" src="https://github.com/user-attachments/assets/13a89eee-fa02-4d99-9b65-36210c1fbb1c" />

All five users came back. The `LIMIT 1` only applies to the first part of
the SELECT — `OR 1=1` still matches every row before the limit kicks in.

<img width="1350" height="839" alt="Screenshot 2026-05-30 230353" src="https://github.com/user-attachments/assets/13a89eee-fa02-4d99-9b65-36210c1fbb1c" />

Same result as the other two levels. The popup and session added friction
but changed nothing about what actually hit the query.

**Fix:** Prepared statements. The query structure needs to be fixed before
user input ever touches it:

```php
$stmt = $pdo->prepare("SELECT first_name, last_name FROM users WHERE user_id = ?");
$stmt->execute([$id]);
```

All three levels failed for the same reason — the input always reached
the query as raw string concatenation. The controls added at each level
(escaping, dropdowns, session routing, LIMIT) addressed symptoms without
touching the actual problem.

---
