def get_vuln_info(vuln_type: str) -> tuple[str, str]:
    """Returns (Severity, Remediation) based on vulnerability type."""
    v_type = vuln_type.lower()
    if 'sql' in v_type:
        return 'High', 'Use parameterized queries (Prepared Statements) for all database access. Avoid concatenating user input directly into SQL strings. Validate all input.'
    elif 'xss' in v_type:
        return 'High', 'Implement strict context-aware output encoding. Sanitize all user-supplied data before rendering it in the browser. Use a robust Content Security Policy (CSP).'
    elif 'waf' in v_type:
        return 'Low', 'The Web Application Firewall successfully blocked the payload. Ensure WAF rules are regularly updated and monitored for bypasses.'
    else:
        return 'Medium', 'Review the affected component and ensure proper input validation and security controls are in place.'
