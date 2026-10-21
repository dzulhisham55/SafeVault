# SafeVault

A small ASP.NET Core application that stores private notes ("vault items") per user, built as
the capstone for the *Secure Code Validation and SQL Injection Prevention* activity. It is
deliberately complete rather than clever: a real SQLite database, real password hashing, real
authentication with role-based access control, and a test suite that attacks it the way an
attacker would.

Everything the assignment asks for is in the repository, and every security claim below is
backed by a test that fails if the code regresses.

```bash
dotnet run --project SafeVault.Web      # https://localhost:7081
dotnet test                             # 91 security tests
```

---

## Contents

- [Quick start](#quick-start)
- [What the app does](#what-the-app-does)
- [Architecture](#architecture)
- [Security model](#security-model)
- [Vulnerabilities found and fixed](#vulnerabilities-found-and-fixed)
- [Tests](#tests)
- [How Microsoft Copilot assisted](#how-microsoft-copilot-assisted)
- [How this maps to the grading criteria](#how-this-maps-to-the-grading-criteria)
- [Limitations](#limitations)

---

## Quick start

Requirements: [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0). No database
server, no container, no external service.

```bash
dotnet restore
dotnet run --project SafeVault.Web
```

Open <https://localhost:7081> (or the HTTP URL printed in the console).

On the first development start the database is created and one administrator is seeded:

| Username | Password | Role |
| --- | --- | --- |
| `admin` | `ChangeMe!2026#Root` | Admin |

That password exists **only** for local development, is refused outside the Development
environment, and is logged as a warning at startup. To choose your own before the first run:

```bash
export SafeVault__SeedAdminPassword='Your!Own#Passphrase2026'
```

Register a second account through **Create account** to see the difference between the two
roles: an ordinary user never sees the Administration link, and `/Admin` answers `403` for
them (rendered as the *Access denied* page).

The SQLite file lives at `SafeVault.Web/App_Data/safevault.db` and is git-ignored. Delete it to
start over.

## What the app does

- **Register / sign in / sign out** with a cookie session. Passwords are hashed with
  PBKDF2-HMAC-SHA256 (210,000 iterations, 16-byte random salt) and verified in constant time.
- **Vault items** — each user creates, searches, opens and deletes their own notes. Search is
  scoped to the signed-in user in SQL.
- **Administration** — the `Admin` role lists all accounts, promotes and demotes users, and
  cannot change its own role (so nobody can lock the last administrator out).
- **Read-only JSON API** — `/api/items`, `/api/items/{id}` and `/api/items/{id}/content`, all
  authenticated and ownership-checked, returning `401`/`404` rather than redirects.

The point of the item body is that **it is never sanitised on the way in**. It is stored
exactly as typed and encoded on the way out, which is the only correct fix for stored XSS. The
detail page is a live demonstration: paste `<script>alert(1)</script>` into an item and it is
displayed as those characters, not executed.

## Architecture

```
SafeVault.sln
SafeVault.Web/
  Program.cs                  cookie auth, authorization, middleware order
  Data/
    Database.cs               SQLite connection + schema
    DatabaseSeeder.cs         first administrator, no default outside Development
    UserRepository.cs         parameterised user queries
    VaultItemRepository.cs    parameterised item queries, LIKE escaping
  Security/
    PasswordHasher.cs         PBKDF2-HMAC-SHA256, versioned hash format
    InputValidator.cs         server-side rules for every field
    HtmlOutput.cs             output encoding + safe search highlighting
    LoginThrottle.cs          lockout after five failures
    SecurityHeadersMiddleware.cs  CSP, nosniff, frame-options, referrer-policy
    SignInService.cs          claims + cookie issuance
    ClaimsPrincipalExtensions.cs  user id / role / ownership helpers
  Api/VaultApi.cs             read-only JSON endpoints
  Pages/                      Razor Pages UI (login, register, vault, admin)
SafeVault.Tests/              91 integration and unit tests
docs/vulnerable-samples/      the pre-fix code, kept for the write-up
SECURITY.md                   vulnerability → root cause → fix → test
```

Data access uses `Microsoft.Data.Sqlite` directly instead of an ORM so that parameterisation
is visible in the source rather than hidden behind a library. Every value is a
`SqliteParameter`; no SQL text is ever assembled from user input.

## Security model

| Concern | Control | Where |
| --- | --- | --- |
| SQL injection | Parameterised commands everywhere, `LIKE` metacharacters escaped | `Data/*Repository.cs` |
| Stored XSS | Razor output encoding, one audited `HtmlString` path that encodes first | `Pages/Vault/*`, `Security/HtmlOutput.cs` |
| XSS execution | CSP without `unsafe-inline`, `nosniff`, no inline script or style | `SecurityHeadersMiddleware.cs` |
| Password storage | PBKDF2-HMAC-SHA256, 210k iterations, per-hash salt, constant-time compare | `Security/PasswordHasher.cs` |
| Brute force | Lockout after 5 failures per username + address, for 1 minute | `Security/LoginThrottle.cs` |
| User enumeration | One generic failure message, plus a dummy hash so timing matches | `Pages/Account/Login.cshtml.cs` |
| CSRF | Antiforgery token on every POST, `SameSite=Lax` cookie, state changes are POST only | `Program.cs`, all forms |
| Broken access control | Role requirement on the admin page, ownership checked against claims for every item, `404` instead of `403` for other users' ids | `Pages/Admin`, `Api/VaultApi.cs`, `VaultItemRepository` |
| Privilege escalation | Role values allow-listed, new accounts always `User`, admins cannot change their own role | `Security/Roles.cs`, `Pages/Admin/Index.cshtml.cs` |
| Open redirect | `Url.IsLocalUrl` before honouring a return URL | `Pages/Account/Login.cshtml.cs` |
| Sensitive data in transit | HTTPS redirection outside Development, HSTS when the request is HTTPS | `Program.cs`, `SecurityHeadersMiddleware.cs` |
| Verbose errors | Generic error page outside Development, no stack traces | `Pages/Error.cshtml` |
| Session theft | `HttpOnly` cookie, 30-minute sliding expiry, no token in local storage | `Program.cs` |

## Vulnerabilities found and fixed

The full write-up, including the vulnerable code that was replaced and the test that proves
the fix, is in **[SECURITY.md](SECURITY.md)**. In short:

1. **SQL injection in sign-in and search** — the first draft built SQL with string
   concatenation. Replaced with parameters; search wildcards are escaped so `%` matches a
   percent sign instead of every row.
2. **Stored XSS in vault content** — the first draft rendered item text through
   `Html.Raw`, so any `<script>` in a note executed for the next reader. Replaced with Razor's
   automatic encoding, a single audited highlighting helper that encodes before adding
   `<mark>`, and a CSP that forbids inline script.
3. **Password handling** — passwords were stored as unsalted SHA-256 in the draft. Replaced
   with salted PBKDF2 and constant-time verification.
4. **Missing authorization on item ids** — any signed-in user could open `/Vault/Detail?id=N`
   for someone else's item. Queries are now owner-scoped and foreign ids return `404`.
5. **Role parameter trusted from the request** — the admin role-change handler accepted any
   string. Roles are now allow-listed, and an administrator cannot demote themselves.
6. **No CSRF protection and no lockout** — added antiforgery validation on every POST and a
   five-failure lockout.

## Tests

```bash
dotnet test
```

91 tests, all passing, split by what they attack:

| File | What it proves |
| --- | --- |
| `SqlInjectionTests` | Classic payloads (`' OR '1'='1`, `admin' --`, `'; DROP TABLE Users; --`) fail to log in, do not widen a search, and do not drop a table; `LIKE` wildcards are literal |
| `XssTests` | Stored `<script>` and `<img onerror>` appear encoded on every page, JSON is JSON, raw content is `text/plain` + `nosniff`, CSP forbids inline script |
| `AuthenticationTests` | Sign-in, sign-out, generic failure messages, lockout, antiforgery rejection, open-redirect refusal, `HttpOnly` cookie |
| `AuthorizationTests` | Ordinary users cannot open or use the admin area, read another user's item through page or API, or delete it; admins can; self-demotion is refused |
| `ValidationTests` | Username/password/item/search rules, duplicate accounts, oversized and control-character input rejected before storage |
| `PasswordHashingTests` | Hashing format, per-hash salt, constant-time verify, malformed and absurd stored values rejected, plaintext never stored |
| `HtmlOutputTests` | Encoding helper behaviour, including that highlighting encodes before it marks |

These are integration tests: they boot the real application with `WebApplicationFactory`, use
the real SQLite schema, post real forms with real antiforgery tokens, and assert on real HTTP
responses. No filter is bypassed and no handler is called directly.

## How Microsoft Copilot assisted

Kept here as the reflective summary for the submission; each item maps to a graded activity.

1. **Generating secure code for validation and SQL injection prevention.** Copilot produced a
   working login endpoint quickly, but its first version concatenated the username into the
   SQL string — the exact defect the activity is about. Asking it to review its own output
   "as if you were an attacker" produced the parameterised version and, more usefully, the
   list of places where a value reached SQL without a parameter. That list became the rule I
   applied to every repository method, including the `LIKE` search, where Copilot's first
   suggestion still let `%` match everything until I asked about wildcard escaping.
2. **Authentication and authorization, including RBAC.** Copilot suggested ASP.NET Core
   Identity; I chose cookie authentication with an explicit role claim because the assignment
   is about *implementing* the mechanism, and Identity would have hidden it. Copilot drafted
   the claims principal and the `[Authorize(Roles = ...)]` attribute. It did not spot that
   `AuthorizeFolder("/Admin", "Admin")` treats the second argument as a **policy name** — that
   only surfaced when the tests showed a `500` instead of a redirect, and the fix was to
   register the role requirement on the page model instead.
3. **Debugging and resolving vulnerabilities.** The stored-XSS fix came from a conversation
   about the difference between input sanitising and output encoding; Copilot's first
   suggestion was to strip tags on save, which loses data and still misses attribute contexts.
   The search-highlight path was the interesting case: it needs markup, so I had Copilot
   implement "encode first, then match inside the encoded string" and wrote the test that
   proves a payload cannot survive it. Copilot also flagged that a failed login for a missing
   user returned faster than a wrong password, which led to the dummy-hash path.
4. **Generating and executing tests.** Copilot wrote the first `WebApplicationFactory` host and
   the antiforgery-aware form helper; I added the isolation (a fresh SQLite file per test
   class) and the negative cases. Several of its suggested assertions were too weak — checking
   a status code where the real question was "is the payload present verbatim in the HTML" — so
   every security test asserts on the response body, not just on `200`.
5. **What I had to correct myself.** Beyond the policy-name mistake, Copilot's first admin page
   allowed an administrator to demote themselves, and its draft error message for a failed
   sign-in said "no account with that username", which is a user-enumeration oracle. Both were
   caught by writing the test first and watching it fail for the right reason.

## How this maps to the grading criteria

| Criterion | Evidence |
| --- | --- |
| GitHub repository for the project | This repository, public |
| Secure code for input validation and SQL injection prevention | `Security/InputValidator.cs`, parameterised repositories, `SqlInjectionTests`, `ValidationTests` |
| Authentication and RBAC | Cookie authentication, PBKDF2 hashing, `Admin`/`User` roles, admin page, `AuthenticationTests`, `AuthorizationTests` |
| Debugged and resolved SQL injection and XSS | `SECURITY.md` with the vulnerable code and the replacement, `docs/vulnerable-samples/`, `SqlInjectionTests`, `XssTests` |
| Generated and executed tests | 91 tests, `dotnet test`, all passing |
| Brief summary of vulnerabilities, fixes and Copilot's help | [Vulnerabilities found and fixed](#vulnerabilities-found-and-fixed) and [How Microsoft Copilot assisted](#how-microsoft-copilot-assisted) above, with detail in `SECURITY.md` |

## Limitations

Honest scope notes, so the reviewer does not have to discover them:

- The lockout counter is in memory. It resets on restart and is per instance; a real deployment
  would keep it in a shared cache.
- There is no password reset, email verification or multi-factor authentication. Those are
  separate features, not security fixes.
- SQLite is a single file: fine for this assignment, not for multiple app servers.
- The CSP allows `'self'` for scripts but the app ships no JavaScript at all, so it is
  stricter in practice than it looks.
- The JSON API is read-only. Write operations go through Razor Pages handlers, where the
  antiforgery token is automatic.
