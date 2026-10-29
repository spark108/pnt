using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Data.Sqlite;

[assembly: System.Runtime.Versioning.SupportedOSPlatform("windows")]

if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows ACL regression check.");
var fixture = Path.Combine(Path.GetTempPath(), "pnt-access-check-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(fixture);
var database = Path.Combine(fixture, "pnt.db");
var certificate = Path.Combine(fixture, "node.pfx");
File.WriteAllBytes(certificate, [1, 2, 3, 4]);
var nested = Directory.CreateDirectory(Path.Combine(fixture, "nested"));
var protectedFile = Path.Combine(nested.FullName, "protected-state");
File.WriteAllText(protectedFile, "preserve me");
var connectionString = new SqliteConnectionStringBuilder { DataSource = database, Pooling = false }.ToString();
using var db = new SqliteConnection(connectionString);
db.Open();
using (var command = db.CreateCommand())
{
    command.CommandText = "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE state(value TEXT); INSERT INTO state VALUES('original identity');";
    command.ExecuteNonQuery();
}
// Keep SQLite open so the repair must preserve real WAL and SHM files as well.
static byte[] ReadShared(string path)
{
    using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
    using var output = new MemoryStream(); input.CopyTo(output); return output.ToArray();
}
var wal = ReadShared(database + "-wal");
var shm = ReadShared(database + "-shm");
var identity = WindowsIdentity.GetCurrent().User!;
var group = new SecurityIdentifier("S-1-5-21-111111111-222222222-333333333-1234");
var acl = new FileSecurity();
acl.SetAccessRuleProtection(true, false);
acl.AddAccessRule(new FileSystemAccessRule(identity, FileSystemRights.FullControl, AccessControlType.Allow));
new FileInfo(protectedFile).SetAccessControl(acl);
File.SetAttributes(database, FileAttributes.ReadOnly);
var helper = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../deploy/access.ps1"));
var script = ". '" + helper.Replace("'", "''") + "'; Set-PntDirectoryAcl -DataPath '" + fixture.Replace("'", "''") + "' -GroupSid '" + group.Value + "' -AdministratorSid '" + identity.Value + "'";
using var process = Process.Start(new ProcessStartInfo("powershell.exe")
{
    UseShellExecute = false,
    ArgumentList = { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "$ErrorActionPreference='Stop';" + script }
})!;
process.WaitForExit();
if (process.ExitCode != 0) throw new Exception("ACL repair failed; fixture: " + fixture);
foreach (var path in Directory.EnumerateFileSystemEntries(fixture, "*", SearchOption.AllDirectories).Prepend(fixture))
{
    var isDirectory = Directory.Exists(path);
    FileSystemSecurity security = isDirectory ? new DirectoryInfo(path).GetAccessControl() : new FileInfo(path).GetAccessControl();
    var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
    if (!security.AreAccessRulesProtected || rules.Any(r => r.AccessControlType != AccessControlType.Allow || r.IsInherited)) throw new Exception("Unprotected ACL: " + path);
    foreach (var (sid, rights) in new[] { (identity.Value, FileSystemRights.FullControl), ("S-1-5-18", FileSystemRights.FullControl), (group.Value, FileSystemRights.Modify) })
    {
        var rule = rules.Single(r => r.IdentityReference.Value == sid);
        if ((rule.FileSystemRights & rights) != rights || rule.PropagationFlags != PropagationFlags.None ||
            rule.InheritanceFlags != (isDirectory ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit : InheritanceFlags.None)) throw new Exception("Wrong ACL: " + path);
    }
    if (rules.Length != 3) throw new Exception("Unexpected access: " + path);
}
if (!wal.SequenceEqual(ReadShared(database + "-wal")) || !shm.SequenceEqual(ReadShared(database + "-shm")) ||
    !File.ReadAllBytes(certificate).SequenceEqual(new byte[] { 1, 2, 3, 4 }) || File.ReadAllText(protectedFile) != "preserve me") throw new Exception("State changed during repair.");
using (var reopened = new SqliteConnection(connectionString))
{
    reopened.Open();
    using var command = reopened.CreateCommand();
    command.CommandText = "SELECT value FROM state";
    if ((string?)command.ExecuteScalar() != "original identity") throw new Exception("Lost SQLite data.");
    command.CommandText = "INSERT INTO state VALUES('after repair')";
    command.ExecuteNonQuery();
}
db.Close();
// This path was created locally above and is never derived from user input.
if (!Path.GetFullPath(fixture).StartsWith(Path.GetFullPath(Path.GetTempPath()), StringComparison.OrdinalIgnoreCase)) throw new Exception("Unsafe cleanup.");
Directory.Delete(fixture, true);
Console.WriteLine("PASS: Windows ACL repair, protected files, SQLite WAL/SHM, write access, and identity preservation (no elevation required).");
