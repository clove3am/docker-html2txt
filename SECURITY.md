# Security Policy

## Reporting a vulnerability

Please do not open a public issue for security problems. Instead, use GitHub's
private advisory reporting on the "Security" tab of this repository.

You can expect an initial response within a few days. Please include the URL or
request that triggers the issue and, if possible, a minimal reproduction.

## Scope

This service intentionally fetches user-supplied URLs. Reports about SSRF
bypasses (for example reaching internal or loopback addresses, cloud metadata
endpoints or redirects into private networks) are especially welcome.

The following are considered known limitations rather than vulnerabilities
(see the README):

- Pages behind authentication or cookies cannot be fetched.
- JavaScript is not executed.
- Denial of service through many requests must be mitigated in front of the
  service with rate limiting.
