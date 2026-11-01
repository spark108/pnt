using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace Pnt;

record FtpConfig(string Id,bool Enabled,long Version);

static class FtpControl
{
    internal static bool Active(Store db)=>db.Get("cluster") is not null&&db.Get("left")!="1"&&db.Self() is {Removed:false};
    internal static bool Reserved(Store db,int port)=>db.Ftp()?.Enabled==true&&(port==FtpGateway.Port||port is >=FtpGateway.PassiveFirst and <=FtpGateway.PassiveLast);
    internal static async Task Command(Store db,X509Certificate2 cert,string[] args)
    {
        if(!Active(db))throw new IOException("Узел не состоит в активном кластере.");
        if(args is ["enable"] or ["disable"])
        {
            var enabled=args[0]=="enable";
            if(enabled&&db.Rules().Any(r=>!r.Removed&&(r.InPort==FtpGateway.Port||r.InPort is >=FtpGateway.PassiveFirst and <=FtpGateway.PassiveLast)))throw new IOException("Порты FTPS заняты пробросами. Удалите конфликтующие правила.");
            if(enabled&&db.Get("key_hash") is not {Length:64})throw new IOException("В кластере отсутствует проверочный хеш ключа.");
            var previous=db.Ftp();
            if(!enabled||previous?.Enabled!=true)db.PutFtp(new(Guid.NewGuid().ToString("N"),enabled,Math.Max(App.Now,(previous?.Version??0)+1)));
            var result=await App.Broadcast(db,cert);
            Console.WriteLine(enabled?"FTPS включён: TCP 440, пассивные порты 44100–44131. Логин admin, пароль — ключ кластера.":"FTPS выключен; активные файловые сеансы будут закрыты.");
            Console.WriteLine("Подтвердили синхронизацию: "+result+". Остальные узлы получат настройку при восстановлении связи.");
        }
        else if(args is ["status"])
        {
            Console.WriteLine("FTPS в кластере: "+(db.Ftp()?.Enabled==true?"включён":"выключен"));
            Console.WriteLine("Явный TLS (AUTH TLS), TCP 440; защищённые пассивные соединения TCP 44100–44131.");
            Console.WriteLine("Логин admin; пароль — исходный ключ кластера. Режим передачи файлов: двоичный.");
            Console.WriteLine("SHA-256 сертификата этого узла: "+Certificate.Fingerprint(cert));
            Console.WriteLine("Состояние слушателя: "+(db.Get("ftp_listener")??"ещё не объявлено службой")+" (обновлено: "+(db.Get("ftp_listener_time")??"—")+").");
        }
        else throw new ArgumentException("pnt ftp enable|disable|status");
    }
}
