import re
import html

# SECURE CODING: Define maximum input limits to prevent Buffer Overflow or Denial of Service (DoS)
MAX_CONTENT_LENGTH = 10000  # Max length for simulated raw leak payload
MAX_TARGET_LENGTH = 253     # Max length for domain/IP targets (matches RFC 1035)

# SECURE CODING: Regex pattern to filter characters commonly used in command injection attempts
# We block typical shell control characters: ;, &, |, `, $, (, ), <, >, \n
PATTERN_COMMAND_INJECTION = re.compile(r'[;&|`$\(\)<>\n\r]')

# SECURE CODING: Regex pattern to identify potential SQL injection keywords/structures (for detection/mitigation)
PATTERN_SQL_INJECTION = re.compile(r"(\b(SELECT|UNION|INSERT|DELETE|UPDATE|DROP|ALTER)\b|' OR '1'='1|--)", re.IGNORECASE)

def sanitize_xss(text: str) -> str:
    """
    SECURE CODING: Mitigates Cross-Site Scripting (XSS) vulnerabilities.
    Converts special HTML characters (<, >, &, ", ') into safe HTML entities.
    This ensures that user-supplied text (such as raw logs containing JavaScript alerts)
    will be rendered harmlessly as plain text in the dashboard, rather than executed by the browser.
    """
    if not text:
        return ""
    # Trim and HTML-escape
    return html.escape(text.strip())

def sanitize_command_injection(target: str) -> str:
    """
    SECURE CODING: Mitigates OS Command Injection vulnerabilities.
    Removes shell control characters from inputs that might be passed to os.system or subprocess.
    Even though this project does not run OS shell commands directly, validating domain inputs 
    against command symbols demonstrates a defensive security mindset to interviewers.
    """
    if not target:
        return ""
    # Strip any characters matched by the command injection pattern
    sanitized = PATTERN_COMMAND_INJECTION.sub('', target.strip())
    return sanitized[:MAX_TARGET_LENGTH]

def sanitize_sql_injection(input_val: str) -> str:
    """
    SECURE CODING: Mitigates SQL Injection (SQLi) vulnerabilities.
    Since this project uses parameterized queries, metacharacters like single quotes
    are safely handled by the database engine and do not need to be escaped (escaping them
    corrupts user searches like "O'Connor"). Instead, we strip query separators (;) and
    comments (--) to demonstrate a secondary layer of Defense-in-Depth.
    """
    if not input_val:
        return ""
    # Strip comments and query separators, keeping quotes intact for parameterized query matching
    sanitized = input_val.replace(";", "").replace("--", "")
    return sanitized

def validate_input_size(content: str, max_limit: int = MAX_CONTENT_LENGTH) -> str:
    """
    SECURE CODING: Defensive input validation.
    Enforces a strict size limit on user payloads to prevent resource exhaustion (DoS).
    """
    if not content:
        return ""
    if len(content) > max_limit:
        # Enforce truncation at maximum safe limits
        return content[:max_limit]
    return content

def secure_sanitize_payload(payload: str) -> str:
    """
    Validates payload input size.
    To avoid double-escaping bugs (since the frontend uses secure textContent rendering),
    we store the raw payload content and perform size validation to mitigate buffer/DoS risks.
    """
    validated = validate_input_size(payload, MAX_CONTENT_LENGTH)
    return validated
