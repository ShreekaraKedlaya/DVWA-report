# DVWA Command Injection Writeup

This is part of my ongoing DVWA exploitation series where I work through 
each vulnerability across all security levels. Command Injection was 
particularly interesting because the progression from Low to High shows 
exactly why blacklist filtering keeps failing in the real world.

---

# Low Security

## Overview
The Command Injection module gives you a simple input field that accepts 
an IP address and runs a ping against it. The idea is straightforward — 
but when there's no sanitization on that input, you're essentially handing 
the user a terminal.

---

## Initial Observation

I started by just entering a normal IP to see what the application actually 
does under the hood.

```bash
127.0.0.1
```

<img width="1911" height="923" alt="image" src="https://github.com/user-attachments/assets/e056e88d-d843-4256-826f-a7a0b225c657" />

The ping output appeared directly on the page. What caught my eye was the 
extra output at the bottom — `help`, `index.php`, `source` — file and 
directory names leaking into the response. That immediately suggested the 
input was being passed raw into a shell command with no filtering whatsoever.

---

## Exploitation

My first instinct was to try chaining a second command using `&&`. In bash, 
`&&` means "run the next command only if the previous one succeeded." Since 
ping on localhost will always succeed, whatever comes after it will execute.

```bash
127.0.0.1 && whoami
```

<img width="732" height="293" alt="image" src="https://github.com/user-attachments/assets/6eb8a66d-32e8-4093-99f8-7dcb47ad5ff7" />

Both the ping output and the result of `whoami` appeared on the page. The 
server was running as `www-data` — meaning an attacker at this point has 
read access to everything the web server can touch.

I pushed a bit further just to confirm the scope:

```bash
127.0.0.1 && id
127.0.0.1 && ls /
```

Both returned system information without any issues.

---

## Source Code Analysis

```php
$target = $_REQUEST['ip'];
$cmd = shell_exec('ping -c 4 ' . $target);
```

That's it. User input goes straight into `shell_exec()` with zero 
validation. The shell sees the full string including whatever operators 
you append, and executes accordingly. There's nothing to bypass here 
because there's nothing in the way.

---

## Impact

In a real application this would be critical. From here an attacker could:
- Read sensitive files including configs and credentials
- Map the internal network
- Download and execute malicious payloads
- Move laterally if other services are accessible
- Establish persistence

The `www-data` context limits privilege escalation directly, but it's 
often enough to find credentials stored in web application config files 
that open doors elsewhere.

---

## Remediation
- Validate input strictly — only accept strings matching a valid IP format
- Never pass raw user input to `shell_exec()`, `exec()`, or `system()`
- Use `escapeshellarg()` if shell execution genuinely can't be avoided
- Apply least privilege — the web server process shouldn't run with more 
  permissions than it needs

---
---

# Medium Security

## Overview

Medium security introduces filtering. The developer clearly recognised 
that `&&` and `;` are dangerous, so they removed them. It's a reasonable 
first instinct — but it's the wrong approach, and it took about thirty 
seconds to get past.

---

## What Changed

The source code at this level shows:

```php
$substitutions = array(
    '&&' => '',
    ';'  => '',
);
$target = str_replace( array_keys($substitutions), $substitutions, $target );
```

The app strips `&&` and `;` before passing input to the shell. On the 
surface that looks like a fix. The problem is that bash has several ways 
to chain commands, and this only blocks two of them.

---

## Bypass

The `|` pipe operator isn't on the blacklist. Pipe works differently from 
`&&` — it passes the stdout of the first command as stdin to the second — 
but the second command still executes regardless, which is all we need.

```bash
127.0.0.1 | whoami
```

<img width="752" height="202" alt="image" src="https://github.com/user-attachments/assets/bdb596b6-cbc8-4dd3-a2e5-65a6f176f4a4" />

`whoami` output appeared immediately. Same result as Low, different 
operator. I confirmed with a couple more:

```bash
127.0.0.1 | id
127.0.0.1 | ls /
```

<img width="732" height="143" alt="image" src="https://github.com/user-attachments/assets/50825bad-152f-4edc-84cf-ebc7f06c1c0c" />
<img width="746" height="583" alt="image" src="https://github.com/user-attachments/assets/9509f107-8390-495a-bf77-653185bad747" />

Both worked without any issues.

---

## Why This Keeps Failing

Blacklisting is fundamentally reactive. You block what you know is 
dangerous today, and an attacker finds what you didn't think of. Bash 
alone gives you `&&`, `||`, `;`, `|`, backticks, and `$()` for command 
execution — and that's before you start thinking about encoding tricks 
or whitespace manipulation.

The developer has to get the list perfect every single time. The attacker 
just needs one gap.

---

## Impact

Identical to Low. The filter changes the payload by one character and 
achieves nothing in practice.

---

## Remediation

Blacklisting isn't the answer here. The same whitelist approach from Low 
applies — if the input should be an IP address, only accept strings that 
look like IP addresses and reject everything else before it gets anywhere 
near a shell function.

---
---

# High Security

## Overview

High security is where it gets genuinely interesting. The filter is much 
more aggressive this time — but there's still a bypass, and it comes down 
to one missing character in the pattern matching.

---

## What Changed

The source code at High level:

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

This is a much longer blacklist. `&`, `;`, `||`, backticks, `$()` — all 
gone. The pipe `|` is in there too this time. At first glance it looks 
like command injection is fully blocked.

Look closer at the pipe entry: it's `'| '` — pipe followed by a space. 
Not just `'|'`.

That one missing character is the entire bypass.

---

## Bypass

If the filter strips `| ` (with space) but not `|` (without space), then 
removing the space before the pipe should work:

```bash
127.0.0.1|whoami
```

No space between the IP and the pipe operator.

<img width="743" height="182" alt="image" src="https://github.com/user-attachments/assets/6b7dd014-36c8-4a4a-838e-0601725e773a" />


It worked. The output of `whoami` appeared on the page exactly as it did 
at Low and Medium.

```bash
127.0.0.1|id
127.0.0.1|ls /
```

<img width="741" height="181" alt="image" src="https://github.com/user-attachments/assets/48e13f18-deec-4c9d-9c57-704563ef26a8" />
<img width="737" height="587" alt="image" src="https://github.com/user-attachments/assets/bd3f547e-a7d5-43a5-bd46-6b49641630a9" />

Same results across the board.

---

## Why It Still Failed

The developer added `| ` to the blacklist but accidentally left `|` 
without a space uncovered. This is a perfect example of why manual 
blacklisting is error-prone even when the developer is actively trying 
to be thorough — one typo, one forgotten edge case, and the whole filter 
falls apart.

This kind of mistake is also easy to miss in a code review because `| ` 
and `|` look nearly identical at a glance.

---

## Impact

Still fully exploitable. Three different security levels, three different 
payloads, same outcome every time.

---

## Final Remediation Note

Across all three levels, the correct fix was never implemented — because 
blacklisting is the wrong tool for this job. The right approach is:

**Whitelist validation before the input reaches any shell function.**

```php
// Only allow valid IPv4 format
if (!filter_var($target, FILTER_VALIDATE_IP)) {
    die("Invalid IP address.");
}
```

This rejects anything that isn't a valid IP address outright. No operator, 
no encoding trick, no edge case gets through — because the valid input 
space is defined explicitly rather than trying to enumerate the bad inputs.

If shell execution is unavoidable, wrap input in `escapeshellarg()` as an 
additional layer. But input validation should always be the first line of 
defence.

---
