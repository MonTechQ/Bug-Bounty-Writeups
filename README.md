# Bug Bounty Writeups by MontechQ

Example-based writeups of vulnerabilities I found and reported through bug bounty programs on HackerOne and Bugcrowd.

To respect program confidentiality, **every writeup is anonymized**: company names, hostnames, cookie names, user IDs, vendor names and source code are replaced with placeholders. The focus is on the technique, the testing process and the lessons, not on the target.

## Writeups

| # | Title | Class | Severity | Outcome |
|---|---|---|---|---|
| 01 | [Cross-Origin Token Theft via a Framable SSO Widget and `postMessage("*")`](writeups/01-sso-widget-postmessage-token-leak.md) | Client-side / Web messaging | High (8.1) | Duplicate (valid) |
| 02 | [Session Hijack via an Unverified "Remember Me" Cookie](writeups/02-unsigned-remember-me-cookie-session-hijack.md) | Broken authentication / Authorization | High (8.1) | Informative, fixed after report |

## How I work

- Manual testing first, with two of my own test accounts for every authorization test.
- I stop as soon as real user data appears and never touch accounts I do not own.
- Every finding gets a control test to find its real limits before I rate severity.
- Methodology references: OWASP WSTG, WASC Threat Classification, NIST SP 800-115, CVSS 3.1.

## Disclaimer

These writeups are for education. Everything was tested within each program's rules of engagement and reported through the platform. Do not use these techniques against systems you are not authorized to test.

## Contact

HackerOne / Bugcrowd: **MontechQ**
