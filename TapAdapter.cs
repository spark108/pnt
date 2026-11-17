using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace Pnt;

internal abstract class TapAdapter : IAsyncDisposable
{
    internal const int Mtu = 1120; // Leave room for the authenticated UDP envelope, even on 1280-byte outer paths.
    internal abstract byte[] Mac { get; }
    internal abstract ValueTask<int> Read(byte[] frame, CancellationToken token);
    internal abstract ValueTask Write(byte[] frame, CancellationToken token);
    public abstract ValueTask DisposeAsync();

    internal static async Task<TapAdapter> Open(string subnet, IPAddress ip, byte[] mac, IEnumerable<IPAddress> serviceAddresses, CancellationToken token)
    {
        var prefix = ip.GetAddressBytes()[..3];
        if (serviceAddresses.Any(a => a.GetAddressBytes().AsSpan().StartsWith(prefix)))
            throw new IOException("Подсеть TAP пересекается с адресом служебного канала PNT.");
        if (OperatingSystem.IsLinux())
        {
            var routes = await Run(token, "ip", "-4", "-o", "route", "show", "table", "all");
            if (routes.Split('\n').SelectMany(l => l.Split(' ', StringSplitOptions.RemoveEmptyEntries).Take(2)).Any(p => Overlap(prefix, p)))
                throw new IOException("Подсеть TAP пересекается с существующим IPv4-маршрутом.");
            return await Linux.Open(ip, mac, token);
        }
        if (OperatingSystem.IsWindows()) return await Windows.Open(subnet, ip, prefix, token);
        throw new PlatformNotSupportedException("TAP поддерживается на Windows и Linux.");
    }

    internal static bool Overlap(byte[] prefix, string route)
    {
        var fields = route.Trim().Split('/');
        if (fields.Length > 2 || !IPAddress.TryParse(fields[0], out var ip) ||
            ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork || ip.ToString() != fields[0]) return false;
        var bits = 32;
        if (fields.Length == 2 && (!int.TryParse(fields[1], out bits) || bits is < 1 or > 32)) return false;
        var bytes = ip.GetAddressBytes();
        for (var i = 0; i < Math.Min(bits, 24); i++)
            if (((bytes[i / 8] ^ prefix[i / 8]) & (0x80 >> (i % 8))) != 0) return false;
        return true;
    }

    static Task<string> Run(CancellationToken token, string name, params string[] args)
        => Run(token, TimeSpan.FromSeconds(12), name, args);

    internal static async Task<string> Run(CancellationToken token, TimeSpan timeout, string name, params string[] args)
    {
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(token);
        budget.CancelAfter(timeout);
        var info = new ProcessStartInfo(name) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
        foreach (var arg in args) info.ArgumentList.Add(arg);
        using var process = Process.Start(info) ?? throw new IOException($"Не удалось запустить {name}.");
        var output = process.StandardOutput.ReadToEndAsync(budget.Token);
        var error = process.StandardError.ReadToEndAsync(budget.Token);
        try
        {
            await process.WaitForExitAsync(budget.Token);
            if (process.ExitCode != 0)
                throw new IOException($"{Path.GetFileName(name)} (код {process.ExitCode}): {((await error) + (await output)).Trim()}");
            return await output;
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested) { throw new IOException($"Истекло время ожидания {name}."); }
        finally { if (!process.HasExited) process.Kill(entireProcessTree: true); }
    }

    sealed class Linux(SafeFileHandle file, byte[] mac) : TapAdapter
    {
        internal override byte[] Mac => mac;
        internal static async Task<Linux> Open(IPAddress ip, byte[] mac, CancellationToken token)
        {
            var fd = open("/dev/net/tun", 2 | 0x800 | 0x80000); // O_RDWR | O_NONBLOCK | O_CLOEXEC
            if (fd < 0) throw Error("/dev/net/tun");
            var file = new SafeFileHandle(fd, true);
            try
            {
                var ifreq = new byte[40];
                Encoding.ASCII.GetBytes("pnttap%d").CopyTo(ifreq, 0);
                BitConverter.GetBytes((short)0x1002).CopyTo(ifreq, 16); // IFF_TAP | IFF_NO_PI
                if (ioctl(file, 0x400454ca, ifreq) < 0) throw Error("TUNSETIFF");
                var name = Encoding.ASCII.GetString(ifreq, 0, Array.IndexOf(ifreq, (byte)0));
                await Run(token, "ip", "link", "set", "dev", name, "address", string.Join(':', mac.Select(b => b.ToString("x2"))), "mtu", Mtu.ToString(), "up");
                // Disable IPv6 on the dedicated adapter. This transport currently carries IPv4 and ARP.
                var ipv6 = $"/proc/sys/net/ipv6/conf/{name}/disable_ipv6";
                if (File.Exists(ipv6)) await File.WriteAllTextAsync(ipv6, "1", token);
                await Run(token, "ip", "-4", "address", "add", ip + "/24", "dev", name);
                return new(file, mac);
            }
            catch { file.Dispose(); throw; }
        }

        internal override async ValueTask<int> Read(byte[] frame, CancellationToken token)
        {
            while (true)
            {
                token.ThrowIfCancellationRequested();
                var count = read(file, frame, (nuint)frame.Length);
                if (count > 0) return (int)count;
                if (count == 0 || Marshal.GetLastPInvokeError() is not (4 or 11)) throw Error("TAP read");
                await Task.Delay(2, token);
            }
        }

        internal override ValueTask Write(byte[] frame, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (write(file, frame, (nuint)frame.Length) != frame.Length && Marshal.GetLastPInvokeError() is not (4 or 11))
                throw Error("TAP write");
            return ValueTask.CompletedTask;
        }

        public override ValueTask DisposeAsync() { file.Dispose(); return ValueTask.CompletedTask; }
        [DllImport("libc", SetLastError = true)] static extern int open([MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags);
        [DllImport("libc", SetLastError = true)] static extern int ioctl(SafeFileHandle fd, nuint request, [In, Out] byte[] data);
        [DllImport("libc", SetLastError = true)] static extern nint read(SafeFileHandle fd, [Out] byte[] buffer, nuint length);
        [DllImport("libc", SetLastError = true)] static extern nint write(SafeFileHandle fd, byte[] buffer, nuint length);
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    sealed class Windows(SafeFileHandle file, byte[] mac, Guid adapter, IPAddress ip, bool manageFirewall) : TapAdapter
    {
        const string ClassPath = @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}";
        internal override byte[] Mac => mac;
        static Task<string> PowerShell(CancellationToken token, string script) =>
            Run(token, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop';" + script);
        static string Select(Guid id) => $"$a=Get-NetAdapter -IncludeHidden | Where-Object InterfaceGuid -eq '{{{id:D}}}'; if (!$a) {{ throw 'TAP adapter missing' }};";
        static string RemoveRules(Guid id) =>
            $"Get-NetFirewallRule -Name 'PNT-TAP-{id:D}-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule;";
        static Task<string> Cleanup(Guid id, IPAddress address, bool manageFirewall, CancellationToken token) => PowerShell(token,
            (manageFirewall ? RemoveRules(id) : "") + Select(id) +
            $"Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -IPAddress {address} -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false");

        static bool Driver(Guid adapter)
        {
            using var root = Registry.LocalMachine.OpenSubKey(ClassPath);
            foreach (var name in root?.GetSubKeyNames() ?? [])
            {
                using var key = root!.OpenSubKey(name);
                if (Guid.TryParse(key?.GetValue("NetCfgInstanceId") as string, out var id) && id == adapter)
                    return WindowsTapInstaller.IsTap(key?.GetValue("ComponentId") as string);
            }
            return false;
        }

        internal static async Task<Windows> Open(string subnet, IPAddress ip, byte[] prefix, CancellationToken token)
        {
            var name = Environment.GetEnvironmentVariable("PNT_TAP_ADAPTER") ?? "PNT TAP";
            var id = await WindowsTapInstaller.Ensure(name, Driver, token);
            var setup = Select(id);
            var result = await PowerShell(token, setup + "Get-NetRoute -AddressFamily IPv4 | Where-Object InterfaceIndex -ne $a.ifIndex | ForEach-Object DestinationPrefix");
            if (result.Split('\n').Any(p => Overlap(prefix, p))) throw new IOException("Подсеть TAP пересекается с существующим IPv4-маршрутом.");
            var file = CreateFile($@"\\.\Global\{{{id:D}}}.tap", 0xc0000000, 0, IntPtr.Zero, 3, 0x40000000, IntPtr.Zero);
            if (file.IsInvalid) { var error = Error("TAP-Windows6"); file.Dispose(); throw error; }
            var configured = false;
            var manageFirewall = Environment.GetEnvironmentVariable("PNT_MANAGE_FIREWALL") != "0";
            try
            {
                var mac = new byte[6];
                Ioctl(file, 1, mac);
                Ioctl(file, 6, BitConverter.GetBytes(1));
                // The named adapter is owned by PNT. Clear stale PNT addresses after an unclean stop.
                configured = true;
                await PowerShell(token, setup +
                    "Set-NetIPInterface -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -Dhcp Disabled;" +
                    "Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object PrefixOrigin -eq 'Manual' | Remove-NetIPAddress -Confirm:$false;" +
                    $"Set-NetIPInterface -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -NlMtuBytes {Mtu};" +
                    $"New-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -IPAddress {ip} -PrefixLength 24 | Out-Null;" +
                    (manageFirewall ? RemoveRules(id) +
                    $"New-NetFirewallRule -Name 'PNT-TAP-{id:D}-ICMP' -DisplayName 'PNT TAP ICMP' -InterfaceAlias $a.Name -Direction Inbound -Action Allow -Protocol ICMPv4 -IcmpType 8 -LocalAddress {ip} -RemoteAddress {subnet} | Out-Null;" +
                    $"New-NetFirewallRule -Name 'PNT-TAP-{id:D}-VPN' -DisplayName 'PNT TAP VPN' -InterfaceAlias $a.Name -Direction Inbound -Action Allow -Protocol UDP -LocalPort {TapVpnPath.FirstPort}-{TapVpnPath.LastPort} -LocalAddress {ip} -RemoteAddress {subnet} | Out-Null;" : ""));
                return new(file, mac, id, ip, manageFirewall);
            }
            catch
            {
                if (configured) try { await Cleanup(id, ip, manageFirewall, CancellationToken.None); } catch (Exception e) { Console.Error.WriteLine("pnt: TAP: " + e.Message); }
                file.Dispose(); throw;
            }
        }

        internal override ValueTask<int> Read(byte[] frame, CancellationToken token) => Transfer(frame, false, token);
        internal override async ValueTask Write(byte[] frame, CancellationToken token)
        {
            if (await Transfer(frame, true, token) != frame.Length) throw new IOException("Неполная запись кадра TAP.");
        }
        public override async ValueTask DisposeAsync()
        {
            try { await Cleanup(adapter, ip, manageFirewall, CancellationToken.None); }
            finally
            {
                try { Ioctl(file, 6, BitConverter.GetBytes(0)); }
                finally { file.Dispose(); }
            }
        }
        [StructLayout(LayoutKind.Sequential)]
        struct Overlapped { public IntPtr Internal, InternalHigh; public uint Offset, OffsetHigh; public IntPtr Event; }
        async ValueTask<int> Transfer(byte[] frame, bool write, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            using var signal = new EventWaitHandle(false, EventResetMode.ManualReset);
            var data = GCHandle.Alloc(frame, GCHandleType.Pinned);
            var ov = Marshal.AllocHGlobal(Marshal.SizeOf<Overlapped>());
            try
            {
                Marshal.StructureToPtr(new Overlapped { Event = signal.SafeWaitHandle.DangerousGetHandle() }, ov, false);
                var ptr = data.AddrOfPinnedObject();
                var size = (uint)frame.Length;
                uint count;
                if (write ? WriteFile(file, ptr, size, out count, ov) : ReadFile(file, ptr, size, out count, ov)) return (int)count;
                if (Marshal.GetLastPInvokeError() != 997) throw Error("TAP transfer");
                using var cancel = token.Register(() => CancelIoEx(file, ov));
                try
                {
                    var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                    var wait = ThreadPool.RegisterWaitForSingleObject(signal, (_, _) => done.TrySetResult(), null, Timeout.Infinite, true);
                    try { await done.Task; } finally { wait.Unregister(null); }
                    if (!GetOverlappedResult(file, ov, out count, false))
                    { token.ThrowIfCancellationRequested(); throw Error("TAP transfer"); }
                    return (int)count;
                }
                catch
                {
                    CancelIoEx(file, ov);
                    GetOverlappedResult(file, ov, out _, true);
                    throw;
                }
            }
            finally { Marshal.FreeHGlobal(ov); data.Free(); }
        }
        static void Ioctl(SafeFileHandle file, uint function, byte[] buffer)
        {
            using var signal = new EventWaitHandle(false, EventResetMode.ManualReset);
            var data = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            var ov = Marshal.AllocHGlobal(Marshal.SizeOf<Overlapped>());
            try
            {
                Marshal.StructureToPtr(new Overlapped { Event = signal.SafeWaitHandle.DangerousGetHandle() }, ov, false);
                var size = (uint)buffer.Length;
                var ptr = data.AddrOfPinnedObject();
                if (!DeviceIoControl(file, 0x220000 | function << 2, ptr, size, ptr, size, out _, ov) &&
                    (Marshal.GetLastPInvokeError() != 997 || !GetOverlappedResult(file, ov, out _, true))) throw Error("TAP IOCTL");
            }
            finally { Marshal.FreeHGlobal(ov); data.Free(); }
        }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool DeviceIoControl(SafeFileHandle file, uint code, IntPtr input, uint inputSize, IntPtr output, uint outputSize, out uint done, IntPtr overlapped);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetOverlappedResult(SafeFileHandle file, IntPtr overlapped, out uint done, bool wait);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CancelIoEx(SafeFileHandle file, IntPtr overlapped);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadFile(SafeFileHandle file, IntPtr buffer, uint size, out uint done, IntPtr overlapped);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteFile(SafeFileHandle file, IntPtr buffer, uint size, out uint done, IntPtr overlapped);
    }

    static IOException Error(string operation) => new($"{operation}: {new Win32Exception(Marshal.GetLastPInvokeError()).Message}");
}
