using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace Pnt;

sealed class Store : IDisposable
{
    readonly string path;
    public Store(string path)
    {
        this.path = path;
        using var c = Open();
        foreach (var sql in new[]
        {
            "CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY,v TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS nodes(id TEXT PRIMARY KEY,json TEXT NOT NULL,version INTEGER NOT NULL)",
            "CREATE TABLE IF NOT EXISTS rules(id TEXT PRIMARY KEY,json TEXT NOT NULL,version INTEGER NOT NULL)",
            "CREATE TABLE IF NOT EXISTS invites(id TEXT PRIMARY KEY,json TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS pings(id TEXT PRIMARY KEY,ms REAL NOT NULL,updated INTEGER NOT NULL)",
            "CREATE TABLE IF NOT EXISTS peer_pings(source TEXT NOT NULL,target TEXT NOT NULL,ms REAL NOT NULL,updated INTEGER NOT NULL,PRIMARY KEY(source,target))"
        }) { using var cmd = c.CreateCommand(); cmd.CommandText = sql; cmd.ExecuteNonQuery(); }
        using var columns = c.CreateCommand();
        columns.CommandText = "PRAGMA table_info(peer_pings)";
        using var reader = columns.ExecuteReader();
        var hasDirect = false;
        while (reader.Read()) if (reader.GetString(1) == "direct") hasDirect = true;
        reader.Close();
        if (!hasDirect) { using var alter = c.CreateCommand(); alter.CommandText = "ALTER TABLE peer_pings ADD COLUMN direct INTEGER NOT NULL DEFAULT 0"; alter.ExecuteNonQuery(); }
    }
    SqliteConnection Open()
    {
        var c = new SqliteConnection($"Data Source={path};Pooling=False;Default Timeout=5");
        c.Open();
        using var cmd = c.CreateCommand(); cmd.CommandText = "PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000"; cmd.ExecuteNonQuery();
        return c;
    }
    public void Dispose() { }
    public string? Get(string key)
    {
        using var c = Open(); using var q = c.CreateCommand();
        q.CommandText = "SELECT v FROM meta WHERE k=$k"; q.Parameters.AddWithValue("$k", key);
        return q.ExecuteScalar() as string;
    }
    public void Set(string key, string value)
    {
        using var c = Open(); using var q = c.CreateCommand();
        q.CommandText = "INSERT INTO meta VALUES($k,$v) ON CONFLICT(k) DO UPDATE SET v=excluded.v";
        q.Parameters.AddWithValue("$k", key); q.Parameters.AddWithValue("$v", value); q.ExecuteNonQuery();
    }
    public UpdateNotice? Update()
    {
        var json = Get("update_notice");
        return json is null ? null : JsonSerializer.Deserialize<UpdateNotice>(json, App.Json);
    }
    public void PutUpdate(UpdateNotice notice)
    {
        if (notice.Id.Length != 32 || !notice.Id.All(Uri.IsHexDigit) || notice.Commit.Length != 40 || !notice.Commit.All(Uri.IsHexDigit)) return;
        var old = Update();
        if (old is not null && (old.Version > notice.Version || old.Version == notice.Version && string.CompareOrdinal(old.Id, notice.Id) >= 0)) return;
        Set("update_notice", JsonSerializer.Serialize(notice, App.Json));
    }
    public WebConfig? Web()
    {
        var json = Get("web_config");
        return json is null ? null : JsonSerializer.Deserialize<WebConfig>(json, App.Json);
    }
    public void PutWeb(WebConfig config)
    {
        if (config.Id.Length != 32 || !config.Id.All(Uri.IsHexDigit) ||
            (config.Enabled && (config.Salt.Length != 64 || config.Hash.Length != 64 ||
                !config.Salt.All(Uri.IsHexDigit) || !config.Hash.All(Uri.IsHexDigit))) ||
            (!config.Enabled && (config.Salt.Length != 0 || config.Hash.Length != 0))) return;
        var old = Web();
        if (old is not null && (old.Version > config.Version ||
            old.Version == config.Version && string.CompareOrdinal(old.Id, config.Id) >= 0)) return;
        Set("web_config", JsonSerializer.Serialize(config, App.Json));
    }
    public void Put(Node value)
    {
        var old = Nodes().FirstOrDefault(x => x.Id == value.Id);
        if (old?.Removed == true && !value.Removed) return;
        if (old?.Removed == false && value.Removed && value.Version <= old.Version) value = value with { Version = old.Version + 1 };
        Upsert("nodes", value.Id, value.Version, JsonSerializer.Serialize(value, App.Json));
    }
    public void Put(Rule value)
    {
        var old = Rules().FirstOrDefault(x => x.Id == value.Id);
        if (old?.Removed == true && !value.Removed) return;
        if (old?.Removed == false && value.Removed && value.Version <= old.Version) value = value with { Version = old.Version + 1 };
        Upsert("rules", value.Id, value.Version, JsonSerializer.Serialize(value, App.Json));
    }
    void Upsert(string table, string id, long version, string json)
    {
        using var c = Open(); using var q = c.CreateCommand();
        q.CommandText = $"INSERT INTO {table}(id,json,version) VALUES($id,$json,$version) ON CONFLICT(id) DO UPDATE SET json=excluded.json,version=excluded.version WHERE (excluded.version > {table}.version OR (json_extract(excluded.json,'$.removed')=1 AND json_extract({table}.json,'$.removed')=0)) AND NOT (json_extract({table}.json,'$.removed')=1 AND json_extract(excluded.json,'$.removed')=0)";
        q.Parameters.AddWithValue("$id", id); q.Parameters.AddWithValue("$json", json); q.Parameters.AddWithValue("$version", version); q.ExecuteNonQuery();
    }
    List<T> All<T>(string table)
    {
        using var c = Open(); using var q = c.CreateCommand(); q.CommandText = $"SELECT json FROM {table}";
        using var reader = q.ExecuteReader(); var result = new List<T>();
        while (reader.Read()) { var item = JsonSerializer.Deserialize<T>(reader.GetString(0), App.Json); if (item != null) result.Add(item); }
        return result;
    }
    public List<Node> Nodes() => All<Node>("nodes");
    public List<Rule> Rules() => All<Rule>("rules");
    public List<Invite> Invites() => All<Invite>("invites");
    public Node? Self() => Nodes().FirstOrDefault(x => x.Id == Get("self"));
    public Node? Resolve(string id) => Nodes().FirstOrDefault(x => !x.Removed && (x.Id == id || x.Name.Equals(id, StringComparison.OrdinalIgnoreCase) || x.Ip == id));
    public void Invite(Invite value)
    {
        using var c = Open(); using var q = c.CreateCommand();
        q.CommandText = "INSERT INTO invites VALUES($id,$json) ON CONFLICT(id) DO UPDATE SET json=excluded.json";
        q.Parameters.AddWithValue("$id", value.Id); q.Parameters.AddWithValue("$json", JsonSerializer.Serialize(value, App.Json)); q.ExecuteNonQuery();
    }
    public bool Consume(Invite value)
    {
        using var c = Open(); using var q = c.CreateCommand();
        q.CommandText = "UPDATE invites SET json=$new WHERE id=$id AND json=$old";
        q.Parameters.AddWithValue("$id", value.Id);
        q.Parameters.AddWithValue("$old", JsonSerializer.Serialize(value, App.Json));
        q.Parameters.AddWithValue("$new", JsonSerializer.Serialize(value with { Used = true }, App.Json));
        return q.ExecuteNonQuery() == 1;
    }
    public void Revoke(string id)
    {
        using var c = Open(); using var q = c.CreateCommand(); q.CommandText = "DELETE FROM invites WHERE id=$id";
        q.Parameters.AddWithValue("$id", id); if (q.ExecuteNonQuery() == 0) throw new Exception("Приглашение не найдено.");
    }
    public void SetPing(string id, double ms, bool direct = false)
    {
        using var c = Open(); using var q = c.CreateCommand();
        q.CommandText = "INSERT INTO pings VALUES($id,$ms,$time) ON CONFLICT(id) DO UPDATE SET ms=excluded.ms,updated=excluded.updated";
        q.Parameters.AddWithValue("$id", id); q.Parameters.AddWithValue("$ms", ms); q.Parameters.AddWithValue("$time", App.Now); q.ExecuteNonQuery();
        if (Get("self") is string self) PutPing(new PingReport(self, id, ms, App.Now, direct));
    }
    public void PutPing(PingReport report)
    {
        if (report.Source.Length != 16 || report.Target.Length != 16 || !double.IsFinite(report.Ms) || report.Ms < 0 || report.Updated > App.Now + 60_000 || report.Updated < App.Now - 60_000) return;
        if (!Nodes().Any(x => x.Id == report.Source && !x.Removed) || !Nodes().Any(x => x.Id == report.Target && !x.Removed)) return;
        using var c = Open(); using var q = c.CreateCommand();
        q.CommandText = "INSERT INTO peer_pings(source,target,ms,updated,direct) VALUES($source,$target,$ms,$updated,$direct) ON CONFLICT(source,target) DO UPDATE SET ms=excluded.ms,updated=excluded.updated,direct=excluded.direct WHERE excluded.updated>peer_pings.updated";
        q.Parameters.AddWithValue("$source", report.Source); q.Parameters.AddWithValue("$target", report.Target);
        q.Parameters.AddWithValue("$ms", report.Ms); q.Parameters.AddWithValue("$updated", report.Updated);
        q.Parameters.AddWithValue("$direct", report.Direct ? 1 : 0); q.ExecuteNonQuery();
    }
    public List<PingReport> Pings()
    {
        using var c = Open(); using var q = c.CreateCommand();
        q.CommandText = "SELECT source,target,ms,updated,direct FROM peer_pings WHERE updated>$minimum";
        q.Parameters.AddWithValue("$minimum", App.Now - 30_000);
        using var reader = q.ExecuteReader(); var result = new List<PingReport>();
        while (reader.Read()) result.Add(new PingReport(reader.GetString(0), reader.GetString(1), reader.GetDouble(2), reader.GetInt64(3), reader.GetInt64(4) != 0));
        return result;
    }
    public double? PingFrom(string source, string target)
    {
        if (source == target) return 0;
        using var c = Open(); using var q = c.CreateCommand();
        q.CommandText = "SELECT ms FROM peer_pings WHERE source=$source AND target=$target AND updated>$minimum";
        q.Parameters.AddWithValue("$source", source); q.Parameters.AddWithValue("$target", target);
        q.Parameters.AddWithValue("$minimum", App.Now - 30_000);
        return q.ExecuteScalar() is double ms ? ms : null;
    }
    public double? Ping(string id)
    {
        if (id == Get("self")) return 0;
        using var c = Open(); using var q = c.CreateCommand();
        q.CommandText = "SELECT ms FROM pings WHERE id=$id AND updated>$time";
        q.Parameters.AddWithValue("$id", id); q.Parameters.AddWithValue("$time", App.Now - 30000);
        return q.ExecuteScalar() is double d ? d : null;
    }
}
