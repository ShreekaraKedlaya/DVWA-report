# DVWA Vulnerability Writeup
Here I did hands-on vulnerability analysis and exploitation writeups 
performed on Damn Vulnerable Web Application (DVWA).

# Command Injection – DVWA

---

# Low Security

## Overview
In this lab, I tested the Command Injection vulnerability available in DVWA.
The application takes an IP address from the user and performs a ping request.
Since the input is not properly sanitized, additional commands can be executed
by appending them to the input.

---

## Initial Observation
When I first opened the Command Injection module, I noticed a simple input 
field asking for an IP address.

I entered:
```bash
127.0.0.1
```

<img width="1911" height="923" alt="image" src="https://github.com/user-attachments/assets/e056e88d-d843-4256-826f-a7a0b225c657" />


The application displayed the ping result on the webpage. From this behavior,
it was clear the backend was directly passing user input into a system command.
I also noticed extra file and directory output in the response, which suggested
the input was not being filtered at all.

---

## Testing the Vulnerability
To confirm command injection was possible, I appended a second command using
the `&&` operator. The shell interprets `&&` as "run the next command only if
the previous one succeeded" — since ping succeeds, the injected command runs
immediately after.

Payload used:
```bash
127.0.0.1 && whoami
```

<img width="732" height="293" alt="image" src="https://github.com/user-attachments/assets/6eb8a66d-32e8-4093-99f8-7dcb47ad5ff7" />


The page displayed both the ping result and the output of `whoami`, confirming
the server was executing appended commands. The server was running as `www-data`,
meaning an attacker would have read access to all web files.

I tested further:
```bash
127.0.0.1 && id
127.0.0.1 && ls /
```
Both executed successfully and returned system information on the webpage.

---

## Source Code Analysis
```php
$target = $_REQUEST['ip'];
$cmd = shell_exec('ping -c 4 ' . $target);
```

User input is taken directly from the request and concatenated into a shell
command with no validation or sanitization. The shell interprets special
operators like `&&` as command separators, which is what makes injection
possible here.

---

## Impact
If this vulnerability exists in a real application, an attacker could:
- Access sensitive files
- Gather server and user information
- Install malicious programs
- Escalate privileges
- Take complete control of the system

Severity depends on the permissions of the web server process.

---

## Remediation
- Accept only valid IP address formats using regex whitelist
- Avoid `shell_exec()` wherever possible
- Use `escapeshellarg()` to sanitize input if shell commands are necessary
- Run web applications with minimal privileges (principle of least privilege)

---
---

# Medium Security

## Overview
At Medium security, DVWA attempts to block command injection by filtering out
known dangerous operators from the input. This demonstrates a common but
flawed approach — blacklist filtering — and why it is not a reliable defense.

---

## What Changed
Clicking "View Source" at Medium level reveals the following filter:

```php
$substitutions = array(
    '&&' => '',
    ';'  => '',
);
$target = str_replace( array_keys($substitutions), $substitutions, $target );
```

The application removes `&&` and `;` from the input before passing it to the
shell. At first glance this looks like a fix, but it only blocks two specific
operators while leaving others untouched.

---

## Bypass
The `|` (pipe) operator is not in the blacklist. In shell, `|` passes the
output of the first command as input to the second. Even if ping produces no
useful output, the second command still executes.

Payload used:
```bash
127.0.0.1 | whoami
```

<img width="752" height="202" alt="image" src="https://github.com/user-attachments/assets/bdb596b6-cbc8-4dd3-a2e5-65a6f176f4a4" />

The page returned the result of `whoami`, confirming the filter was bypassed.
I tested further to confirm:
```bash
127.0.0.1 | id
127.0.0.1 | ls /
```

<img width="732" height="143" alt="image" src="https://github.com/user-attachments/assets/50825bad-152f-4edc-84cf-ebc7f06c1c0c" />
<img width="746" height="583" alt="image" src="https://github.com/user-attachments/assets/9509f107-8390-495a-bf77-653185bad747" />


Both executed successfully, identical outcome to Low security.

---

## Why the Blacklist Failed
The filter only accounts for operators the developer thought of. Shell has
multiple command chaining operators — `&&`, `||`, `;`, `|`, backticks, `$()` —
and blocking two of them leaves the rest available. This is the fundamental
problem with blacklist-based filtering: an attacker only needs to find one
gap, while the developer has to anticipate every possible bypass.

---

## Impact
Same as Low security. The filter provides a false sense of security — the
vulnerability is fully exploitable with a trivial one-character change to
the payload.

---

## Remediation
Blacklist filtering is not a reliable fix. The correct approach remains the
same as Low:
- Whitelist validation — only allow input that matches a strict IP address
  pattern (e.g., regex `^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)
- Avoid passing user input to shell functions entirely
- Use `escapeshellarg()` if shell execution is unavoidable
