namespace Pnt;

record CachedRoute(string Target, string[] Path, double Ms, long Updated, int Successes, int Failures, int Streak, bool Primary = false);

static class RouteCache
{
    public const long FreshFor = 60_000;
    public static List<CachedRoute> Apply(IEnumerable<CachedRoute> previous, string target,
        IEnumerable<(string[] Path, double Ms)> measured)
    {
        var old = previous.ToArray();
        var routes = measured.Select(m =>
        {
            var p = old.FirstOrDefault(r => r.Path.SequenceEqual(m.Path));
            return new CachedRoute(target, m.Path, m.Ms, App.Now, (p?.Successes ?? 0) + 1, p?.Failures ?? 0,
                (p?.Streak ?? 0) + 1);
        }).OrderBy(r => r.Ms).ToList();
        var primary = old.FirstOrDefault(r => r.Primary);
        var current = routes.FirstOrDefault(r => primary is not null && r.Path.SequenceEqual(primary.Path));
        var best = routes.FirstOrDefault();
        var chosen = current is null || best is not null && best.Ms < current.Ms * .8 && best.Streak >= 3 ? best : current;
        var failed = old.Where(p => !routes.Any(r => r.Path.SequenceEqual(p.Path)))
            .Select(r => r with { Updated = 0, Primary = false, Streak = 0, Failures = r.Failures+1 });
        return routes.OrderByDescending(r => ReferenceEquals(r, chosen))
            .Select(r => r with { Primary = ReferenceEquals(r, chosen) }).Concat(failed).Take(4).ToList();
    }
}
