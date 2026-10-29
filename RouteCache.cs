namespace Pnt;

record CachedRoute(string Target, string[] Path, double Ms, long Updated, int Successes, int Failures, int Streak, bool Primary = false);

static class RouteCache
{
    public const long FreshFor = 60_000;
    public static List<CachedRoute> Apply(IEnumerable<CachedRoute> previous, string target,
        IEnumerable<(string[] Path, double Ms)> measured, Func<string,bool>? behindNat = null)
    {
        var old = previous.ToArray();
        var routes = measured.Select(m =>
        {
            var p = old.FirstOrDefault(r => r.Path.SequenceEqual(m.Path));
            return new CachedRoute(target, m.Path, m.Ms, App.Now, (p?.Successes ?? 0) + 1, p?.Failures ?? 0,
                (p?.Streak ?? 0) + 1);
        }).OrderBy(r => r.Path.Length<=2?0:1).ThenBy(r=>r.Path.Skip(1).SkipLast(1).Count(n=>behindNat?.Invoke(n)==true)).ThenBy(r => r.Ms).ToList();
        var primary = old.FirstOrDefault(r => r.Primary);
        var current = routes.FirstOrDefault(r => primary is not null && r.Path.SequenceEqual(primary.Path));
        var best = routes.FirstOrDefault();
        var priorityImproved=best is not null && current is not null &&
            (best.Path.Length<=2 && current.Path.Length>2 ||
             best.Path.Length>2 && current.Path.Length>2 && best.Path.Skip(1).SkipLast(1).Count(n=>behindNat?.Invoke(n)==true)<current.Path.Skip(1).SkipLast(1).Count(n=>behindNat?.Invoke(n)==true));
        var chosen = current is null || priorityImproved || best is not null && (best.Path.Length>2)==(current.Path.Length>2) &&
            best.Ms < current.Ms * .8 && best.Streak >= 3 ? best : current;
        var failed = old.Where(p => !routes.Any(r => r.Path.SequenceEqual(p.Path)))
            .Select(r => r with { Updated = 0, Primary = false, Streak = 0, Failures = r.Failures+1 });
        return routes.OrderByDescending(r => ReferenceEquals(r, chosen))
            .Select(r => r with { Primary = ReferenceEquals(r, chosen) }).Concat(failed).Take(4).ToList();
    }
}
