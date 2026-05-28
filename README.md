# DVWA Command Injection Writeup

Target Application: Damn Vulnerable Web Application (DVWA)
Vulnerability: Command Injection (exec module)

---

# Low Security

## Overview

After opening the Command Injection module in DVWA, I noticed the application
accepted an IP address input and ran a ping command against it. My goal was
to check whether the input was being sanitized before getting passed to the
shell.

---

## Initial Observation

I started by entering a normal IP address to understand how the application
behaves.

```bash
127.0.0.1
```

<img width="1911" height="923" alt="image" src="https://github.com/user-attachments/assets/e056e88d-d843-4256-826f-a7a0b225c657" />

The ping result appeared directly on the page. What stood out to me was
the extra output at the bottom — `help`, `index.php`, `source` — directory
contents leaking into the response. That was a strong hint that the input
was going straight into a shell command with no filtering.

---

## Testing the Vulnerability

To confirm this, I tried chaining a second command using the `&&` operator.
In bash, `&&` runs the next command only if the previous one succeeded.
Since pinging localhost always succeeds, anything appended after it would
also run.

Payload used:

```bash
127.0.0.1 && whoami
```

<img width="732" height="293" alt="image" src="https://github.com/user-attachments/assets/6eb8a66d-32e8-4093-99f8-7dcb47ad5ff7" />

Both the ping output and the result of `whoami` appeared on the page.
The server was running as `www-data`, confirming the injection worked and
an attacker would have read access to all web server files.

I tested a few more commands to confirm the scope:

```bash
127.0.0.1 && id
127.0.0.1 && ls /
```

All of them executed successfully and returned system information directly
on the page.

---

## Source Code Analysis

DVWA provides a View Source option which showed exactly why this worked:

```php
$target = $_REQUEST['ip'];
$cmd = shell_exec('ping -c 4 ' . $target);
```

The user input is taken directly from the request and concatenated into
a shell command with zero validation. The shell interprets `&&` as a
command separator, so whatever comes after it runs as a separate command.
There is nothing to bypass here because there is nothing blocking it.

---

## Impact

If this vulnerability existed in a real application, an attacker could:

- Access sensitive files including config files and credentials
- Gather server and user information
- Download and execute malicious payloads
- Move laterally to other services on the network
- Establish persistence on the server

The `www-data` context limits direct privilege escalation but credentials
found in web application config files could open further doors.

---

## Remediation

- Only accept input that matches a valid IP address format
- Never pass raw user input into `shell_exec()`, `exec()`, or `system()`
- Use `escapeshellarg()` if shell execution cannot be avoided
- Run the web application with minimal privileges

---
---

# Medium Security

## Overview

At medium security, DVWA introduces input filtering to try and block
command injection. I wanted to see what exactly was being filtered and
whether it could be bypassed.

---

## What Changed

Checking the source code revealed the following filter:

```php
$substitutions = array(
    '&&' => '',
    ';'  => '',
);
$target = str_replace( array_keys($substitutions), $substitutions, $target );
```

The application strips `&&` and `;` from the input before passing it
to the shell. On the surface this looks like a fix, but bash has several
ways to chain commands and this only blocks two of them.

---

## Testing the Vulnerability

The `|` pipe operator is not in the blacklist. Pipe passes the output
of the first command as input to the second. Even if ping produces no
useful output, the second command still runs.

Payload used:

```bash
127.0.0.1 | whoami
```

<img width="752" height="202" alt="image" src="https://github.com/user-attachments/assets/bdb596b6-cbc8-4dd3-a2e5-65a6f176f4a4" />

The `whoami` output appeared immediately. Same result as Low security,
just a different operator. I confirmed with a couple more commands:

```bash
127.0.0.1 | id
127.0.0.1 | ls /
```

<img width="732" height="143" alt="image" src="https://github.com/user-attachments/assets/50825bad-152f-4edc-84cf-ebc7f06c1c0c" />
<img width="746" height="583" alt="image" src="https://github.com/user-attachments/assets/9509f107-8390-495a-bf77-653185bad747" />

Both executed successfully, identical outcome to Low security.

---

## Why the Filter Failed

Blacklist filtering is fundamentally reactive. You block what you know
is dangerous and an attacker finds what you missed. Bash alone gives you
`&&`, `||`, `;`, `|`, backticks, and `$()` for command execution. The
developer has to get the list perfect every single time. The attacker
just needs one gap.

---

## Impact

Same as Low security. The filter gives a false sense of security — the
vulnerability is fully exploitable with a one character change to the
payload.

---

## Remediation

Blacklist filtering is not a reliable fix. The correct approach is
whitelist validation — if the input should be an IP address, only accept
strings that match an IP address format and reject everything else before
it reaches any shell function.

---
---

# High Security

## Overview

High security uses a much more aggressive filter. At first glance it
looked like command injection was fully blocked. But after reading the
source code carefully, I noticed something off.

---

## What Changed

The source code at this level:

```php
$substitutions = array(
    '&'  => '',
    ';'  => '',
    '| ' => '',
    '-'  => '',
    '$'  => '',
    '('  => '',
    ')'  => '',
    '`'  => '',
    '||' => '',
);
$target = str_replace( array_keys($substitutions), $substitutions, $target );
```

Almost everything is blocked here — `&`, `;`, `||`, backticks, `$()`.
The pipe `|` is in the list too. But looking closely at that pipe entry,
it says `'| '` — pipe followed by a space. Not just `'|'` on its own.

That one missing space is the entire bypass.

---

## Testing the Vulnerability

If the filter only strips `| ` with a space, then using `|` without a
space should go through unfiltered.

Payload used:

```bash
127.0.0.1|whoami
```

<img width="743" height="182" alt="image" src="https://github.com/user-attachments/assets/6b7dd014-36c8-4a4a-838e-0601725e773a" />

It worked. The `whoami` output appeared exactly as it did at Low and
Medium security. I tested further:

```bash
127.0.0.1|id
127.0.0.1|ls /
```

<img width="741" height="181" alt="image" src="https://github.com/user-attachments/assets/48e13f18-deec-4c9d-9c57-704563ef26a8" />
<img width="737" height="587" alt="image" src="https://github.com/user-attachments/assets/bd3f547e-a7d5-43a5-bd46-6b49641630a9" />

Same results across the board.

---

## Why It Still Failed

The developer blocked `| ` but forgot `|` without the space. This is
exactly the kind of mistake that happens with manual blacklists — the
difference between `| ` and `|` is barely visible, and it's easy to miss
in a code review. One overlooked character kept the vulnerability wide open.

---

## Impact

Still fully exploitable. Three security levels, three different payloads,
same outcome every time.

---

## Remediation

Across all three levels the correct fix was never applied because
blacklisting is the wrong approach entirely. The right solution is
whitelist validation before the input reaches any shell function:

```php
if (!filter_var($target, FILTER_VALIDATE_IP)) {
    die("Invalid IP address.");
}
```

This rejects anything that is not a valid IP address. No operator, no
encoding trick, no edge case gets through because the valid input space
is defined explicitly rather than trying to block every bad input.

If shell execution cannot be avoided, use `escapeshellarg()` as an
additional layer — but input validation should always come first.

---
