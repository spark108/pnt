namespace Pnt;

record CachedRoute(string Target, string[] Path, double Ms, long Updated, int Successes, int Failures, int Streak, bool Primary = false);

static class RouteCache
{
    public const long FreshFor = 60_000;
    public static List<CachedRoute> Apply(IEnumerable<CachedRoute> previous, string target,
        IEnumerable<(string[] Path, double Ms)> measured, Func<string,bool>? behindNat = null,Func<string,bool>? reserveOnly = null)
    {
        (int Reserve,int Indirect,int Nat) Rank(string[] path)=>(path.Skip(1).SkipLast(1).Count(n=>reserveOnly?.Invoke(n)==true),path.Length<=2?0:1,path.Skip(1).SkipLast(1).Count(n=>behindNat?.Invoke(n)==true));
        var old = previous.ToArray();
        var routes = measured.Select(m =>
        {
            var p = old.FirstOrDefault(r => r.Path.SequenceEqual(m.Path));
            return new CachedRoute(target, m.Path, m.Ms, App.Now, (p?.Successes ?? 0) + 1, p?.Failures ?? 0,
                (p?.Streak ?? 0) + 1);
        }).OrderBy(r => Rank(r.Path)).ThenBy(r => r.Ms).ToList();
        var primary = old.FirstOrDefault(r => r.Primary);
        var current = routes.FirstOrDefault(r => primary is not null && r.Path.SequenceEqual(primary.Path));
        var best = routes.FirstOrDefault();
        var priorityImproved=best is not null&&current is not null&&Rank(best.Path).CompareTo(Rank(current.Path))<0;
        var chosen=current is null||priorityImproved||best is not null&&Rank(best.Path)==Rank(current.Path)&&best.Ms<current.Ms*.8&&best.Streak>=3?best:current;
        var failed = old.Where(p => !routes.Any(r => r.Path.SequenceEqual(p.Path)))
            .Select(r => r with { Updated = 0, Primary = false, Streak = 0, Failures = r.Failures+1 });
        var ordered=routes.OrderByDescending(r => ReferenceEquals(r, chosen))
            .Select(r => r with { Primary = ReferenceEquals(r, chosen) }).ToArray();
        var kept=ordered.Take(4).ToList();
        var backup=ordered.Skip(4).FirstOrDefault(r=>Rank(r.Path).Reserve>0);
        if(kept.Count==4&&backup is not null&&kept.All(r=>Rank(r.Path).Reserve==0))kept[^1]=backup;
        return kept.Concat(failed).Take(4).ToList();
    }
}
