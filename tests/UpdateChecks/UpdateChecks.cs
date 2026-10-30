namespace Pnt;

static class UpdateChecks
{
    static void Assert(bool value, string message) { if (!value) throw new Exception(message); }
    public static async Task Main()
    {
        var directory = Path.Combine(Path.GetTempPath(), "pnt-update-check-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        using var source = new Store(Path.Combine(directory, "source.db"));
        using var receiver = new Store(Path.Combine(directory, "receiver.db"));
        var commit = new string('a', 40);
        var first = source.AnnounceUpdate(commit.ToUpperInvariant());
        Assert(first.Commit == commit && source.Get("update_applied") == first.Id, "Initiator did not apply its own notice.");
        receiver.PutUpdate(first); receiver.Set("update_applied", first.Id);
        var second = source.AnnounceUpdate(commit);
        Assert(second.Id != first.Id && second.Version > first.Version, "Same-commit update did not create a new event.");
        receiver.PutUpdate(second);
        Assert(receiver.Update()?.Id == second.Id && receiver.Get("update_applied") != second.Id, "Previously updated member skipped the new event.");
        receiver.Set("update_applied", second.Id); receiver.PutUpdate(second);
        Assert(receiver.Update()?.Id == second.Id && receiver.Get("update_applied") == second.Id, "Automatic acknowledgement created an update loop.");
        source.PutUpdate(second with { Version = second.Version + 60_000 });
        var third = source.AnnounceUpdate(commit);
        Assert(third.Version > second.Version + 60_000, "Announcement did not supersede a newer stored clock.");
        var staleSync = Task.Run(() => { for (var i = 0; i < 30; i++) source.PutUpdate(first); });
        var concurrent = await Task.WhenAll(Enumerable.Range(0, 12).Select(_ => Task.Run(() => source.AnnounceUpdate(commit))));
        await staleSync;
        Assert(concurrent.Select(n => n.Id).Distinct().Count() == 12, "Concurrent announcements reused IDs.");
        var latest = concurrent.MaxBy(n => n.Version)!;
        Assert(source.Update()?.Id == latest.Id && source.Get("update_applied") == latest.Id, "Announcement and local acknowledgement were not atomic.");
        try { source.AnnounceUpdate("invalid"); throw new Exception("Invalid commit accepted."); } catch (ArgumentException) { }
        Assert(source.Update()?.Id == latest.Id, "Invalid announcement changed state.");
        Console.WriteLine("PASS: same-commit rollout, fresh event IDs, member reapplication, no automatic announcement loop, monotonic clocks and concurrent atomic announcements.");
    }
}
