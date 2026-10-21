namespace SafeVault.Web.Security;

/// <summary>
/// Limits online password guessing: after <see cref="MaxFailures"/> failures for the same
/// username and client address, further attempts are refused for <see cref="LockoutDuration"/>
/// even if the password is correct.
/// </summary>
public sealed class LoginThrottle(TimeProvider timeProvider)
{
    public const int MaxFailures = 5;
    public static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(1);

    private readonly Dictionary<string, Entry> _entries = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    public TimeSpan? RemainingLockout(string key)
    {
        lock (_gate)
        {
            if (!_entries.TryGetValue(key, out var entry) || entry.LockedUntilUtc is null)
            {
                return null;
            }

            var remaining = entry.LockedUntilUtc.Value - timeProvider.GetUtcNow();
            if (remaining <= TimeSpan.Zero)
            {
                _entries.Remove(key);
                return null;
            }

            return remaining;
        }
    }

    public void RegisterFailure(string key)
    {
        lock (_gate)
        {
            if (!_entries.TryGetValue(key, out var entry))
            {
                entry = new Entry();
                _entries[key] = entry;
            }

            entry.Failures++;
            if (entry.Failures >= MaxFailures)
            {
                entry.LockedUntilUtc = timeProvider.GetUtcNow() + LockoutDuration;
            }
        }
    }

    public void Reset(string key)
    {
        lock (_gate)
        {
            _entries.Remove(key);
        }
    }

    private sealed class Entry
    {
        public int Failures;
        public DateTimeOffset? LockedUntilUtc;
    }
}
