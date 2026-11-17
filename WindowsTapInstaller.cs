using System.ComponentModel;
using System.IO.Compression;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace Pnt;

[SupportedOSPlatform("windows")]
static class WindowsTapInstaller
{
    const string PackageUrl = "https://github.com/OpenVPN/tap-windows6/releases/download/9.27.0/dist.win10.zip";
    const string PackageSha256 = "36E2609B7CEEFEDCB978CE5C48CAF9E0E5AF83423717C4E2E3C1D7EBCA8F62A5";
    const string Instance = @"ROOT\PNTTAP\0000", HardwareId = @"root\tap0901";
    const uint RegisterDevice = 0x19, HardwareIdProperty = 1, GlobalScope = 1, DriverKey = 2, KeyRead = 0x20019;
    const uint NoFinishInstallUi = 2;
    const uint NoSuchDevice = 0xe000020b;
    static readonly Guid NetworkClass = new("4D36E972-E325-11CE-BFC1-08002BE10318");
    static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(35), MaxResponseContentBufferSize = 1024 * 1024 };
    static readonly SemaphoreSlim InstallGate = new(1);
    static long retryAt;
    static string? lastFailure;

    internal static bool IsTap(string? component) =>
        string.Equals(component, "tap0901", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(component, HardwareId, StringComparison.OrdinalIgnoreCase);

    internal static async Task<Guid> Ensure(string name, Func<Guid, bool> isTap, CancellationToken token)
    {
        if (FindNamed(name, isTap) is { } existing) return existing;

        await InstallGate.WaitAsync(token);
        try
        {
            if (FindNamed(name, isTap) is { } installed) return installed;
            if (Environment.TickCount64 < retryAt) throw new IOException(lastFailure ?? "Установка TAP-Windows6 ожидает повтора.");
            try
            {
                using var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                if (!identity.IsSystem && !principal.IsInRole(WindowsBuiltInRole.Administrator))
                    throw new IOException("Для автоматической установки TAP-Windows6 запустите службу PNT с правами администратора.");

                using var devices = SetupDiCreateDeviceInfoList(NetworkClass, IntPtr.Zero);
                if (devices.IsInvalid) throw Error("SetupDiCreateDeviceInfoList");
                var device = new DeviceInfo { Size = (uint)Marshal.SizeOf<DeviceInfo>() };
                if (!SetupDiOpenDeviceInfo(devices, Instance, IntPtr.Zero, 0, ref device))
                {
                    // Do not take over a different device on access, class or other SetupAPI errors.
                    if ((uint)Marshal.GetLastPInvokeError() != NoSuchDevice) throw Error("SetupDiOpenDeviceInfo");
                    await StageDriver(token);
                    token.ThrowIfCancellationRequested();
                    if (!SetupDiCreateDeviceInfo(devices, Instance, NetworkClass, "PNT TAP", IntPtr.Zero, 0, ref device))
                        throw Error("SetupDiCreateDeviceInfo");
                    var hardwareIds = Encoding.Unicode.GetBytes(HardwareId + "\0\0");
                    if (!SetupDiSetDeviceRegistryProperty(devices, ref device, HardwareIdProperty, hardwareIds, (uint)hardwareIds.Length))
                        throw Error("SetupDiSetDeviceRegistryProperty");
                    if (!SetupDiCallClassInstaller(RegisterDevice, devices, ref device)) throw Error("DIF_REGISTERDEVICE");
                }
                VerifyHardwareId(devices, ref device);

                var id = InterfaceId(devices, ref device);
                if (id is null)
                {
                    if (!DiInstallDevice(IntPtr.Zero, devices, ref device, IntPtr.Zero, NoFinishInstallUi, out var reboot))
                        throw Error("DiInstallDevice");
                    if (reboot)
                        throw new IOException("Windows требует перезагрузку для установки TAP-Windows6.");
                    for (var i = 0; i < 20 && id is null; i++)
                    {
                        await Task.Delay(500, token);
                        id = InterfaceId(devices, ref device);
                    }
                }
                if (id is not { } adapter || !isTap(adapter))
                    throw new IOException("Windows ещё не зарегистрировала интерфейс TAP-Windows6.");

                await Rename(adapter, name, token);
                return adapter;
            }
            catch (Exception e) when (!token.IsCancellationRequested)
            {
                lastFailure = "Установка TAP-Windows6: " + e.GetBaseException().Message;
                retryAt = Environment.TickCount64 + 60_000;
                throw new IOException(lastFailure, e);
            }
        }
        finally { InstallGate.Release(); }
    }

    static Guid? FindNamed(string name, Func<Guid, bool> isTap)
    {
        var adapter = NetworkInterface.GetAllNetworkInterfaces()
            .FirstOrDefault(n => n.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
        if (adapter is null) return null;
        if (Guid.TryParse(adapter.Id, out var id) && isTap(id)) return id;
        throw new IOException($"Имя интерфейса «{name}» уже занято другим адаптером.");
    }

    static Guid? InterfaceId(DeviceSet devices, ref DeviceInfo device)
    {
        using var handle = SetupDiOpenDevRegKey(devices, ref device, GlobalScope, 0, DriverKey, KeyRead);
        if (handle.IsInvalid) return null;
        using var key = RegistryKey.FromHandle(handle);
        return Guid.TryParse(key.GetValue("NetCfgInstanceId") as string, out var id) ? id : null;
    }

    static void VerifyHardwareId(DeviceSet devices, ref DeviceInfo device)
    {
        var data = new byte[1024];
        if (!SetupDiGetDeviceRegistryProperty(devices, ref device, HardwareIdProperty, out var type, data, (uint)data.Length, out var size))
            throw Error("SetupDiGetDeviceRegistryProperty");
        if (type != 7 || size > data.Length ||
            !Encoding.Unicode.GetString(data, 0, (int)size).Split('\0').Contains(HardwareId, StringComparer.OrdinalIgnoreCase))
            throw new IOException("Идентификатор устройства PNT уже занят другим оборудованием.");
    }

    static async Task StageDriver(CancellationToken token)
    {
        var architecture = RuntimeInformation.OSArchitecture switch
        {
            Architecture.X64 => "amd64",
            Architecture.Arm64 => "arm64",
            Architecture.X86 => "i386",
            _ => throw new PlatformNotSupportedException("Для этой архитектуры нет пакета TAP-Windows6.")
        };
        using var response = await Http.GetAsync(PackageUrl, token);
        response.EnsureSuccessStatusCode();
        var bytes = await response.Content.ReadAsByteArrayAsync(token);
        if (!SHA256.HashData(bytes).AsSpan().SequenceEqual(Convert.FromHexString(PackageSha256)))
            throw new IOException("Контрольная сумма пакета TAP-Windows6 не совпала.");

        using var archive = new ZipArchive(new MemoryStream(bytes), ZipArchiveMode.Read);
        var directory = new DirectoryInfo(Path.Combine(Path.GetTempPath(), $"pnt-tap-{Guid.NewGuid():N}"));
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(true, false);
        foreach (var account in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
            security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(account, null), FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        directory.Create(security);
        try
        {
            foreach (var file in new[] { "OemVista.inf", "tap0901.cat", "tap0901.sys" })
            {
                var entry = archive.GetEntry($"dist.win10/{architecture}/{file}") ??
                    throw new IOException($"Файл {file} отсутствует в пакете TAP-Windows6.");
                await using var input = entry.Open();
                await using var output = new FileStream(Path.Combine(directory.FullName, file), FileMode.CreateNew, FileAccess.Write, FileShare.None);
                await input.CopyToAsync(output, token);
            }
            // Staging lets Windows verify the catalog. The install call targets only the PNT device.
            await TapAdapter.Run(token, TimeSpan.FromSeconds(90), Path.Combine(Environment.SystemDirectory, "pnputil.exe"),
                "/add-driver", Path.Combine(directory.FullName, "OemVista.inf"));
        }
        finally
        {
            try { directory.Delete(recursive: true); }
            catch (IOException e) { Console.Error.WriteLine("pnt: TAP: " + e.Message); }
            catch (UnauthorizedAccessException e) { Console.Error.WriteLine("pnt: TAP: " + e.Message); }
        }
    }

    static Task<string> Rename(Guid adapter, string name, CancellationToken token)
    {
        var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(name));
        var script = "$ErrorActionPreference='Stop';" +
            $"$name=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded}'));" +
            $"$id=[guid]'{adapter:D}';" +
            // Registration of the Windows network adapter can lag behind the PnP device.
            "for ($i=0; $i -lt 20; $i++) { " +
            "$adapters=@(Get-NetAdapter -IncludeHidden); $a=$adapters | Where-Object { [guid]$_.InterfaceGuid -eq $id };" +
            "if ($a) { if ($a.Name -eq $name) { exit 0 };" +
            "if ($adapters | Where-Object Name -eq $name) { throw 'Requested TAP name is already in use' };" +
            "Rename-NetAdapter -InputObject $a -NewName $name -Confirm:$false; exit 0 };" +
            "Start-Sleep -Milliseconds 500 }; throw 'TAP adapter is not available yet'";
        return TapAdapter.Run(token, TimeSpan.FromSeconds(30),
            Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe"),
            "-NoProfile", "-NonInteractive", "-Command", script);
    }

    static Win32Exception Error(string operation)
    {
        var code = Marshal.GetLastPInvokeError();
        return new Win32Exception(code, $"{operation} (0x{code:X8}): {new Win32Exception(code).Message}");
    }

    [StructLayout(LayoutKind.Sequential)]
    struct DeviceInfo { internal uint Size; Guid ClassGuid; uint DevInst; UIntPtr Reserved; }

    sealed class DeviceSet : SafeHandleMinusOneIsInvalid
    {
        public DeviceSet() : base(true) { }
        protected override bool ReleaseHandle() => SetupDiDestroyDeviceInfoList(handle);
    }

    [DllImport("setupapi.dll", SetLastError = true)] static extern DeviceSet SetupDiCreateDeviceInfoList(in Guid classGuid, IntPtr parent);
    [DllImport("setupapi.dll", SetLastError = true)] static extern bool SetupDiDestroyDeviceInfoList(IntPtr devices);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool SetupDiOpenDeviceInfo(DeviceSet devices, string id, IntPtr parent, uint flags, ref DeviceInfo data);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool SetupDiCreateDeviceInfo(DeviceSet devices, string name, in Guid classGuid, string description, IntPtr parent, uint flags, ref DeviceInfo data);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool SetupDiSetDeviceRegistryProperty(DeviceSet devices, ref DeviceInfo data, uint property, byte[] value, uint size);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool SetupDiGetDeviceRegistryProperty(DeviceSet devices, ref DeviceInfo data, uint property,
        out uint type, [Out] byte[] value, uint size, out uint requiredSize);
    [DllImport("setupapi.dll", SetLastError = true)]
    static extern bool SetupDiCallClassInstaller(uint function, DeviceSet devices, ref DeviceInfo data);
    [DllImport("setupapi.dll", SetLastError = true)]
    static extern SafeRegistryHandle SetupDiOpenDevRegKey(DeviceSet devices, ref DeviceInfo data, uint scope, uint profile, uint type, uint access);
    [DllImport("newdev.dll", SetLastError = true)]
    static extern bool DiInstallDevice(IntPtr parent, DeviceSet devices, ref DeviceInfo data, IntPtr driver, uint flags, out bool reboot);
}
