from websec.models import Finding, Severity, Status

def make_finding(
        check_id: str,
        title: str,
        severity: Severity,
        status: Status,
        description: str,
        evidence: str,
        recommendation: str,
) -> Finding:
    return Finding(
        check_id=check_id,
        title=title,
        severity=severity,
        status=status,
        description=description,
        evidence=evidence,
        recommendation=recommendation,
    )

def normalize_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        name.lower(): value.strip()
        for name, value in headers.items()
    }

def check_hsts(headers: dict[str, str], is_https: bool) -> Finding:
    value = headers.get("strict-transport-security")

    if not is_https:
        return make_finding(
            "HDR-001",
            "HSTS not applicable over HTTP",
            Severity.INFO,
            Status.UNKNOWN,
            "Browsers only honor HSTS received over HTTPS.",
            "Final response uses HTTP.",
            "Serve the site over HTTPS and configure HSTS there."
        )

    if not value:
        return make_finding(
            "HDR-001",
            "HSTS header missing",
            Severity.MEDIUM,
            Status.FAIL,
            "The HTTPS response does not declare an HSTS policy.",
            "Strict-Transport-Security header absent.",
            "Add an HSTS policy with an appropriate positive max-age."
        )

    directives = [part.strip() for part in value.split(";")]
    max_age_values = []

    for directive in directives:
        name, separator, argument = directive.partition("=")

        if name.strip().lower() == "max-age":
            max_age_values.append(argument.strip() if separator else "")

    if len(max_age_values) != 1:
        return make_finding(
            "HDR-001",
            "Invalid HSTS max-age",
            Severity.MEDIUM,
            Status.WARNING,
            "HSTS must contain exactly one valid max-age directive.",
            value,
            "Configure one max-age directive with a positive integer."
        )

    max_age_text = max_age_values[0].strip('"')

    if not max_age_text.isascii() or not max_age_text.isdecimal():
        return make_finding(
            "HDR-001",
            "Invalid HSTS max-age",
            Severity.MEDIUM,
            Status.WARNING,
            "The HSTS max-age is not a valid integer.",
            value,
            "Set max-age to a positive integer number of seconds."
        )

    max_age = int(max_age_text)

    if max_age == 0:
        return make_finding(
            "HDR-001",
            "HSTS disabled",
            Severity.MEDIUM,
            Status.FAIL,
            "A max-age of zero disables the HSTS policy.",
            value,
            "Use an appropriate positive max-age after testing HTTPS.",
        )

    return make_finding(
        "HDR-001",
        "HSTS configured",
        Severity.INFO,
        Status.PASS,
        "The HTTPS response declares a positive HSTS max-age.",
        value,
        "Review policy duration and subdomain coverage for your deployment.",
    )

def check_csp(headers: dict[str, str]) -> Finding:
    value = headers.get("content-security-policy")

    if not value:
        return make_finding(
            "HDR-002",
            "Content Security Policy missing",
            Severity.MEDIUM,
            Status.WARNING,
            "No enforcing Content Security Policy was found.",
            "Content-Security-Policy header absent.",
            "Define a restrictive CSP appropriate for the application.",
        )

    directives = {}

    for part in value.split(";"):
        tokens = part.strip().split()

        if tokens:
            name = tokens[0].lower()

            if name not in directives:
                directives[name] = tokens[1:]

    script_sources = directives.get(
        "script-src",
        directives.get("default-src", []),
    )

    normalized_sources = {
        source.lower() for source in script_sources
    }

    risky_sources = {
        "'unsafe-inline'",
        "'unsafe-eval'",
        "*",
    }

    detected = sorted(normalized_sources & risky_sources)

    if detected:
        return make_finding(
            "HDR-002",
            "Potentially permissive CSP",
            Severity.MEDIUM,
            Status.WARNING,
            "The script policy contains potentially risky source expressions.",
            f"{value} | Flagged: {', '.join(detected)}",
            "Review script sources and remove unnecessary unsafe allowances.",
        )

    if not script_sources:
        return make_finding(
            "HDR-002",
            "CSP requires review",
            Severity.LOW,
            Status.WARNING,
            "No script sources were identified by this basic CSP check.",
            value,
            "Review the effective script policy and application requirements.",
        )

    return make_finding(
        "HDR-002",
        "CSP present",
        Severity.INFO,
        Status.PASS,
        "An enforcing CSP was found without the risky tokens checked here.",
        value,
        "Review all CSP directives and test the policy against the application.",
    )

def check_x_frame_options(headers: dict[str, str]) -> Finding:
    value = headers.get("x-frame-options", "")
    normalized = value.upper()

    if normalized in ("DENY", "SAMEORIGIN"):
        return make_finding(
            "HDR-003",
            "X-Frame-Options configured",
            Severity.INFO,
            Status.PASS,
            "The response declares a recognized frame restriction.",
            value,
            "Keep framing restrictions aligned with application needs.",
        )

    return make_finding(
        "HDR-003",
        "X-Frame-Options missing or invalid",
        Severity.MEDIUM,
        Status.WARNING,
        "No recognized X-Frame-Options restriction was found.",
        value or "Header absent.",
        "Use DENY or SAMEORIGIN, or review CSP frame-ancestors protection.",
    )

def check_x_content_type_options(headers: dict[str, str]) -> Finding:
    value = headers.get("x-content-type-options", "")

    if value.lower() == "nosniff":
        return make_finding(
            "HDR-004",
            "MIME sniffing protection configured",
            Severity.INFO,
            Status.PASS,
            "The response sets X-Content-Type-Options to nosniff.",
            value,
            "Keep nosniff enabled.",
        )

    return make_finding(
        "HDR-004",
        "MIME sniffing protection missing or invalid",
        Severity.LOW,
        Status.WARNING,
        "The response does not declare a valid nosniff policy.",
        value or "Header absent.",
        "Set X-Content-Type-Options: nosniff.",
    )

def check_referrer_policy(headers: dict[str, str]) -> Finding:
    value = headers.get("referrer-policy", "")

    recognized = {
        "no-referrer",
        "no-referrer-when-downgrade",
        "origin",
        "origin-when-cross-origin",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "unsafe-url",
    }

    policies = [
        part.strip().lower()
        for part in value.split(",")
        if part.strip()
    ]

    effective_policy = next(
        (policy for policy in reversed(policies) if policy in recognized),
        None,
    )

    if effective_policy == "unsafe-url":
        return make_finding(
            "HDR-005",
            "Permissive Referrer-Policy",
            Severity.MEDIUM,
            Status.WARNING,
            "The effective policy can expose full referrer URLs across origins.",
            value,
            "Prefer strict-origin-when-cross-origin or a stricter policy.",
        )

    if effective_policy:
        return make_finding(
            "HDR-005",
            "Referrer-Policy configured",
            Severity.INFO,
            Status.PASS,
            "A recognized Referrer-Policy value was found.",
            value,
            "Keep the policy appropriate for your privacy requirements.",
        )
    
    return make_finding(
        "HDR-005",
        "Referrer-Policy missing or invalid",
        Severity.LOW,
        Status.WARNING,
        "No recognized Referrer-Policy value was found.",
        value or "Header absent.",
        "Set a suitable Referrer-Policy, such as strict-origin-when-cross-origin.",
    )

def analyze_headers(
    headers: dict[str, str],
    final_url: str,
) -> list[Finding]:
    from urllib.parse import urlsplit

    normalized = normalize_headers(headers)
    is_https = urlsplit(final_url).scheme.lower() == "https"

    return [
        check_hsts(normalized, is_https),
        check_csp(normalized),
        check_x_frame_options(normalized),
        check_x_content_type_options(normalized),
        check_referrer_policy(normalized),
    ]