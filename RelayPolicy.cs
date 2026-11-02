namespace Pnt;

sealed class RelayPolicy(IEnumerable<Node> members)
{
    readonly Dictionary<string,Node> nodes=members.Where(n=>!n.Removed).ToDictionary(n=>n.Id);
    internal int ReserveCount(string[] path)=>path.Skip(1).SkipLast(1).Count(id=>nodes.TryGetValue(id,out var node)&&!node.RelayEnabled);
    internal int NatCount(string[] path)=>path.Skip(1).SkipLast(1).Count(id=>nodes.TryGetValue(id,out var node)&&node.BehindNat);
    internal (int Reserve,int Indirect,int Nat) Rank(string[] path)=>(ReserveCount(path),path.Length<=2?0:1,NatCount(path));
    internal IEnumerable<T> KeepBackup<T>(IEnumerable<T> ordered,Func<T,string[]> path,int count)
    {
        var all=ordered.ToArray();var selected=all.Take(count).ToList();
        if(count>1&&selected.Count==count&&selected.All(item=>ReserveCount(path(item))==0))
        {var backup=all.Skip(count).Where(item=>ReserveCount(path(item))>0).Take(1).ToArray();if(backup.Length>0)selected[^1]=backup[0];}
        return selected;
    }
}
