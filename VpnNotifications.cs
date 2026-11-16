namespace Pnt;

record VpnNotification(string Id, string Client, string Text, long Created)
{
    internal const int PageSize = 64;
    internal const int MaxTextLength = 1024;

    internal bool Valid() => Guid.TryParseExact(Id, "N", out _) &&
        Client is { Length: 16 } && Client.All(Uri.IsHexDigit) &&
        Text is { Length: > 0 and <= MaxTextLength } && !string.IsNullOrWhiteSpace(Text) &&
        Created is > 0 and <= 253402300799999;
}

sealed partial class Store
{
    internal const string InsertVpnNotification = """
        INSERT INTO vpn_notifications(id,client,text,created) VALUES($id,$client,$text,$created)
        ON CONFLICT(id) DO NOTHING
        """;

    internal void PutVpnNotification(VpnNotification value)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = InsertVpnNotification;
        command.Parameters.AddWithValue("$id", value.Id);
        command.Parameters.AddWithValue("$client", value.Client);
        command.Parameters.AddWithValue("$text", value.Text);
        command.Parameters.AddWithValue("$created", value.Created);
        command.ExecuteNonQuery();
    }

    internal (long Sequence, VpnNotification Value)[] VpnNotifications(long after = 0, string? client = null, int limit = int.MaxValue)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = client is null
            ? "SELECT seq,id,client,text,created FROM vpn_notifications WHERE seq>$after ORDER BY seq LIMIT $limit"
            : "SELECT seq,id,client,text,created FROM vpn_notifications WHERE client=$client AND seq>$after ORDER BY seq LIMIT $limit";
        command.Parameters.AddWithValue("$after", after);
        command.Parameters.AddWithValue("$limit", limit);
        if (client is not null) command.Parameters.AddWithValue("$client", client);
        using var reader = command.ExecuteReader();
        var result = new List<(long, VpnNotification)>();
        while (reader.Read())
            result.Add((reader.GetInt64(0), new(reader.GetString(1), reader.GetString(2), reader.GetString(3), reader.GetInt64(4))));
        return result.ToArray();
    }
}
