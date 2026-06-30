---
name: cybersecurity_portfolio_hardening
description: Best practices and code patterns for security hardening in web dashboards, covering SQLi escaping, DOM XSS mitigations, log credential redaction, and non-root Docker files.
---

# Cybersecurity Portfolio Hardening Guidelines

Use this skill when modifying, extending, or building features for defensive security dashboards, SOAR systems, or web applications within this repository.

## 1. SQL Injection (SQLi) Wildcard Escaping
When implementing SQL `LIKE` queries in SQLite search fields, escape the search wildcards (`%` and `_`) to prevent attackers from leaking unauthorized portions of the database.

*Pattern:*
```python
# Escape characters
search_term = query.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')

# Use ESCAPE '\' in query execution
cursor.execute(
    "SELECT * FROM logs WHERE target LIKE ? ESCAPE '\\'",
    (f"%{search_term}%",)
)
```

## 2. DOM-Based XSS Mitigation
Always escape variables inserted dynamically into the DOM using `.innerHTML`. Prefer using `.textContent` where possible. If HTML formatting is required, wrap all dynamic strings using a secure escaping utility.

*Pattern (JavaScript):*
```javascript
function escapeHTML(str) {
    if (!str) return '';
    return str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
```

## 3. Log Redaction (CWE-532)
Ensure that exceptions, API tracebacks, or connection errors do not leak sensitive credentials or webhook tokens in logs.

*Pattern (Python):*
```python
import re

def redact_sensitive_info(text, sensitive_url):
    # Extract secret token/URL components and mask them
    token = sensitive_url.split('/')[-1]
    if len(token) > 10:
        return text.replace(token, "[REDACTED]")
    return text
```

## 4. Secure Docker Hardening (Non-Root Execution)
All Docker containers must run under a non-privileged user to mitigate privilege escalation vectors.

*Pattern (Dockerfile):*
```dockerfile
# Create non-privileged user/group
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -m -s /bin/bash appuser && \
    chown -R appuser:appgroup /app

# Switch context to the non-root user
USER appuser
```
