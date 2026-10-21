# Pre-fix code, kept for the write-up

These files are excerpts of the earlier, insecure drafts of SafeVault. They are stored as
`.txt` and are **not** part of the build: nothing here is compiled or reachable at runtime.

They exist so the review in [SECURITY.md](../../SECURITY.md) can show the exact defect that was
replaced rather than describing it from memory.

| File | Defect | Fixed in |
| --- | --- | --- |
| `login-sql.txt` | SQL injection by string concatenation in the sign-in query | `SafeVault.Web/Data/UserRepository.cs` |
| `search-like.txt` | Unescaped `LIKE` wildcards, so `%` returned every row | `SafeVault.Web/Data/VaultItemRepository.cs` |
| `vault-detail-xss.txt` | Stored XSS through `Html.Raw` | `SafeVault.Web/Pages/Vault/Detail.cshtml` |

Each file ends with the test that now guards against the defect returning.
