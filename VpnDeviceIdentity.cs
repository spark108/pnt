using System.Security.Cryptography;

namespace Pnt;

static class VpnDeviceIdentity
{
    internal static ECDsa Load()
    {
        if(OperatingSystem.IsWindows())return Windows("PNT VPN device v1");
        var directory=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"pnt-vpn");
        Directory.CreateDirectory(directory,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);
        var path=Path.Combine(directory,"device.pk8");
        using(var generated=ECDsa.Create(ECCurve.NamedCurves.nistP256))
        {
            try
            {
                using var file=new FileStream(path,new FileStreamOptions{Mode=FileMode.CreateNew,Access=FileAccess.Write,Share=FileShare.None,UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite});
                var bytes=generated.ExportPkcs8PrivateKey();
                try{file.Write(bytes);}finally{CryptographicOperations.ZeroMemory(bytes);}
            }
            catch(IOException) when(File.Exists(path)){}
        }
        var secret=File.ReadAllBytes(path);var key=ECDsa.Create();
        try{key.ImportPkcs8PrivateKey(secret,out _);return key;}
        catch{key.Dispose();throw;}
        finally{CryptographicOperations.ZeroMemory(secret);}
    }
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    internal static ECDsa Windows(string name)
    {
        var provider=CngProvider.MicrosoftSoftwareKeyStorageProvider;
        if(!CngKey.Exists(name,provider))
        {
            try
            {
                using var created=CngKey.Create(CngAlgorithm.ECDsaP256,name,new CngKeyCreationParameters{Provider=provider,ExportPolicy=CngExportPolicies.None,KeyUsage=CngKeyUsages.Signing});
            }
            catch(CryptographicException) when(CngKey.Exists(name,provider)){}
        }
        using var key=CngKey.Open(name,provider);return new ECDsaCng(key);
    }
}
