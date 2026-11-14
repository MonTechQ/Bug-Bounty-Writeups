# Session Hijack via an Unverified "Remember Me" Cookie Overriding a Signed Session

| Field | Value |
|---|---|
| Vulnerability class | Broken authentication / improper authorization |
| Weaknesses | CWE-639 (Authorization Bypass Through User-Controlled Key), CWE-345 (Insufficient Verification of Data Authenticity) |
| Severity (as submitted) | High, CVSS 3.1 8.1 (`AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`) |
| Impact | Takeover of another customer's active storefront session and support-chat identity |
| Platform | HackerOne (public bug bounty program) |
| Outcome | Closed as Informative. The behavior stopped reproducing about 3 days after submission. Re-evaluation requested. |

> All names, hosts, cookie names, customer IDs and vendor names in this writeup are placeholders. The target and its third-party vendors are intentionally not disclosed. Requests are reconstructed and sanitized.

---

## TL;DR

An e-commerce site used two login cookies:

- `SIGNED_SESSION`: the "real" session cookie, cryptographically signed by the server.
- `REMEMBER_ME`: a long-lived convenience cookie that kept you logged in. It contained the **customer ID in plain text**, plus a signature (a MAC) at the end.

One backend endpoint trusted `REMEMBER_ME` over `SIGNED_SESSION`, and **never checked the MAC**. If I sent my own valid signed session together with a `REMEMBER_ME` cookie containing another customer's ID, the server:

1. issued a support-chat identity token for the **other** customer, and
2. **re-issued a freshly signed `SIGNED_SESSION` for the other customer**, replacing mine.

The only requirement was that the other customer had an active session at the time.

---

## Background: what a MAC is and why it matters

A **MAC (Message Authentication Code)** is a signature the server attaches to data it gives you, like a tamper seal. When the cookie comes back, the server recalculates the MAC. If you changed even one character, the seal no longer matches and the server should reject it.

A MAC only helps if the server **actually checks it**. If the server reads the plaintext ID and ignores the seal, the user controls the identity.

---

## Recon: how I found it

1. With two of my own test accounts (A and B), I decoded every cookie the site set after login. The `REMEMBER_ME` value looked like this (sanitized):
   ```
   <base64-MAC>;<timestamp>_<guid>_<storeId>_10000000001,-1,CAD,<base64-blob>
                                              ^ customer ID in plain text
   ```
2. Customer IDs were 11-digit numbers, and my two accounts' IDs were close together, so IDs were predictable.
3. I captured the request the site makes when it opens the support chat widget. It hits a backend-for-frontend (BFF) endpoint that returns a support-chat JWT (a signed token for the third-party chat vendor) plus the customer's first and last name.
4. I tested which cookie actually authenticated that request by removing them one at a time.

---

## Testing and proof of concept

All tests used only my own accounts A (`10000000001`) and B (`10000000002`).

**Request shape (sanitized):**
```http
POST /api/bff/customer HTTP/2
Host: www.shop.example
Content-Type: application/json
Cookie: SIGNED_SESSION=<...>; REMEMBER_ME=<...>

{"operations":["SUPPORT_CHAT_USER_QUERY"]}
```

### Step 1: Which cookie is the real authenticator?

| Cookies sent | Result |
|---|---|
| `REMEMBER_ME` only | `success:true`, chat token minted |
| `SIGNED_SESSION` only | `success:false`, "User must be logged in" |

So the long-lived cookie was the **only** thing this endpoint trusted.

### Step 2 (PoC 1): Is the MAC checked?

- Flipped characters in the trailing MAC/blob, same length: **token still minted.**
- Removed the MAC/blob entirely: **token still minted.**

The signature was decorative. Identity came only from the plaintext customer ID.

### Step 3 (PoC 2): Can a weaker cookie override a signed session?

Sent account A's **valid signed** `SIGNED_SESSION` together with a `REMEMBER_ME` carrying **B's** customer ID.

```http
HTTP/2 200
Set-Cookie: SIGNED_SESSION=<new value, signed by the server, for customer 10000000002>

{"success":true,"chatToken":"<JWT for B>","firstName":"<B>","lastName":"<B>"}
```

The server ignored A's signed session, minted B's chat token, **and issued a brand new signed session cookie for B**. Using that cookie, I could browse as B: account settings, order history, and personal details.

### Step 4 (PoC 3): Control test, where are the limits?

I wanted to know if this was full forgery (any ID, any time) or something narrower.

| Test | Result |
|---|---|
| B logged out for ~50 minutes, stripped MAC | Fail: "must be logged in" |
| A's live session + B's cold ID with a valid-looking blob | Fail |
| A's own ID, stripped MAC, A live | Success |

**Conclusion:** the attack works for any customer ID that **currently has a live server-side session**. It does not work for idle accounts. I reported it as a **session-scoped hijack**, not as unlimited forgery, because that is what the evidence supported.

---

## Impact

- **Unauthorized access:** an attacker with their own account can take over another customer's active storefront session (PoC 2).
- **Data exposure:** the victim's name, email and support-chat identity are returned.
- **Support-channel impersonation:** the attacker can chat with customer support as the victim.
- **Low barrier:** customer IDs are predictable, and "logged in" is normal shopper state. No victim click or attacker page is needed.

**Contributing weakness:** the session cookies were not `HttpOnly`, meaning JavaScript on the page could read them. Any future XSS would let an attacker steal them directly. I kept this out of the severity rating because I had no working XSS.

---

## Remediation

1. **Verify the MAC** on every cookie the server reads identity from, and reject on mismatch.
2. **Never let a weaker credential override a stronger one.** If the signed session and the remember-me cookie disagree on who the user is, reject the request and clear both.
3. **Bind identity to the server-side session**, not to a value the client sends back.
4. Set `HttpOnly` on all authentication cookies.
5. Consider opaque random tokens instead of putting customer IDs in cookies at all.

---

## What happened after submission

- The report was closed as **Informative** by the triager, who cited high preconditions and limited demonstrated impact.
- About **3 days after submission**, the behavior stopped reproducing. A later check showed that identity had moved to a different cookie and that the server now cross-checked it against the real session (ID swaps returned `403`). The MAC was still not enforced, but the binding check closed the hole.
- I requested re-evaluation, mapping each claimed impact to a specific PoC and pointing out that the post-submission fix confirms the issue was real and server-side.

---

## Lessons learned

- **Control tests change the story.** Early on, a "forgery fails" result looked like proof that the MAC was checked. It was actually a **dead session** being rejected. Re-testing with live vs. cold sessions showed the MAC was never checked and found the real boundary.
- **Report exactly what you proved.** I dropped claims I could not support (cold-account forgery, mass account takeover) and kept the rating defensible.
- **Lead with the strongest artifact.** The server issuing a fresh signed session for another user is much harder to dismiss than "a chat token was returned."
- **Know your escalation options.** If a program goes quiet after an informative close, platform mediation exists to restart communication. It is not a channel for demanding a bounty.
- **Answer "high user interaction" upfront.** Triagers often read "victim must be logged in" as a big precondition. Explain early that being logged in is normal and that the victim does nothing.

---

## References

- [OWASP WSTG: Testing for Bypassing Authorization Schema (WSTG-ATHZ-02)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema)
- [OWASP WSTG: Testing for Cookies Attributes (WSTG-SESS-02)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
