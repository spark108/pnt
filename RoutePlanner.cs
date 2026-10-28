namespace Pnt;

static class RoutePlanner
{
    public static IEnumerable<Node> Candidates(Store db, string current, string target, IEnumerable<string> visited,
        bool skipTarget = false)
    {
        var excluded = visited.ToHashSet();
        var pings = db.Pings().Where(x => x.Direct).ToArray();
        return db.Nodes().Where(x => !x.Removed && x.Id != current && !excluded.Contains(x.Id) &&
                (!skipTarget || x.Id != target))
            .OrderBy(x => x.Id == target ? -1 : Score(current, x.Id, target, pings))
            .ToArray();
    }

    static double Score(string current, string candidate, string target, PingReport[] links)
    {
        var first = links.Where(x => x.Source == current && x.Target == candidate)
            .Select(x => x.Ms).DefaultIfEmpty(1000).Min();
        var rest = Distance(candidate, target, links);
        return first + (double.IsPositiveInfinity(rest) ? 10_000 : rest);
    }

    static double Distance(string start, string target, PingReport[] links)
    {
        if (start == target) return 0;
        var distances = new Dictionary<string, double> { [start] = 0 };
        var done = new HashSet<string>();
        while (true)
        {
            var next = distances.Where(x => !done.Contains(x.Key)).OrderBy(x => x.Value).FirstOrDefault();
            if (next.Key is null) return double.PositiveInfinity;
            if (next.Key == target) return next.Value;
            done.Add(next.Key);
            foreach (var link in links.Where(x => x.Source == next.Key && !done.Contains(x.Target)))
            {
                var cost = next.Value + link.Ms;
                if (!distances.TryGetValue(link.Target, out var old) || cost < old) distances[link.Target] = cost;
            }
        }
    }
}
