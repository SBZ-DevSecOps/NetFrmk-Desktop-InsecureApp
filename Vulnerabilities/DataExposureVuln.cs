using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

namespace NetFrmk_Desktop_InsecureApp.Vulnerabilities
{
    public static class DataExposureVuln
    {
        // ===== 1) RAM secret (jamais effacé) =====
        private static string _ramSecret; // ❌ secret conservé en mémoire statique

        public static string StoreInMemory(string secret)
        {
            _ramSecret = secret; // ❌ pas d'effacement/zeroization
            return "Stored in RAM (not cleared).";
        }

        // ===== 2) Export CSV en clair =====
        public static string ExportCsvPlain(string path)
        {
            var content = "email,user,secret\nalice@example.com,alice,ABC123\n";
            File.WriteAllText(path, content); // ❌ données sensibles en clair
            return "CSV written: " + path;
        }

        // ===== 3) Journalisation sensible =====
        public static string LogSensitive(string line)
        {
            var log = Path.Combine(Environment.CurrentDirectory, "app.log");
            File.AppendAllText(log, DateTime.Now.ToString("s") + " " + line + Environment.NewLine); // ❌ log sensible
            return "Logged to: " + log;
        }

        // ===== 4) Dépôt sur partage public =====
        public static string PublicShareDrop(string content)
        {
            var folder = @"C:\PublicShare"; // ❌ répertoire public
            Directory.CreateDirectory(folder);
            var path = Path.Combine(folder, "exposed.txt");
            File.WriteAllText(path, content);
            return @"Dropped to " + path;
        }

        // ===== 5) "Crypto" faible : Base64 =====
        public static string WeakEncryptionBase64(string input)
        {
            var b = Encoding.UTF8.GetBytes(input);
            return Convert.ToBase64String(b); // ❌ pas un chiffrement
        }

        // ===== 6) Secret/clé en dur =====
        private const string HARDCODED = "HARDCODED_SECRET_KEY_123"; // ❌ secret en dur

        public static string HardcodedKey(string marker)
        {
            return "Marker=" + marker + " Secret=" + HARDCODED;
        }

        // ===== 7) Ecriture en %TEMP% =====
        public static string TempWrite(string content)
        {
            var path = Path.Combine(Path.GetTempPath(), "sensitive.tmp");
            File.WriteAllText(path, content); // ❌ pas de protection
            return "Temp file: " + path;
        }

        // ===== 8) Exception verbeuse qui divulgue =====
        public static void VerboseError(string secret)
        {
            // ❌ message d'erreur contient le secret
            throw new InvalidOperationException("Operation failed; secret = " + secret);
        }

        // ===== 9) Transport HTTP POST non sécurisé =====
        public static string HttpPostInsecure(string url, string body)
        {
            using (var wc = new WebClient())
            {
                wc.Headers[HttpRequestHeader.ContentType] = "application/x-www-form-urlencoded";
                // ❌ pas de TLS exigé; http:// encouragé par défaut côté UI
                var resp = wc.UploadString(url, "POST", body);
                if (resp.Length > 300) resp = resp.Substring(0, 300) + "...";
                return "POST " + url + " -> " + resp;
            }
        }

        // ===== 10) Stockage en clair sur disque =====
        public static string StoreCleartext(string data)
        {
            var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "clear.txt");
            File.WriteAllText(path, data); // ❌ en clair
            return "Cleartext written: " + path;
        }

        // ===== 11) ROT13 "faible chiffrement" =====
        public static string WeakEncryptionRot13(string input)
        {
            var arr = input.ToCharArray();
            for (int i = 0; i < arr.Length; i++)
            {
                char c = arr[i];
                if (c >= 'a' && c <= 'z') arr[i] = (char)('a' + (c - 'a' + 13) % 26);
                else if (c >= 'A' && c <= 'Z') arr[i] = (char)('A' + (c - 'A' + 13) % 26);
            }
            return new string(arr); // ❌ pas de sécurité
        }

        // ===== 12) HTTP GET non sécurisé avec query =====
        public static string HttpGetInsecure(string url, string query)
        {
            using (var wc = new WebClient())
            {
                var full = url.Contains("?") ? (url + "&" + query) : (url + "?" + query); // ❌ secrets dans l'URL
                var resp = wc.DownloadString(full); // ❌ HTTP clair possible
                if (resp.Length > 300) resp = resp.Substring(0, 300) + "...";
                return "GET " + full + " -> " + resp;
            }
        }

        // ===== 13) ConnString en clair dans App.config =====
        public static string WritePlainConfig()
        {
            var path = Path.Combine(Environment.CurrentDirectory, "App.config"); // ❌ demo: en clair
            var content =
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
                "<configuration>\n" +
                "  <connectionStrings>\n" +
                "    <add name=\"db\" connectionString=\"Server=127.0.0.1;Database=app;User Id=sa;Password=Pa$$w0rd;\" providerName=\"System.Data.SqlClient\" />\n" +
                "  </connectionStrings>\n" +
                "</configuration>\n";
            File.WriteAllText(path, content);
            return "Plaintext connection string written to " + path;
        }

        // ===== 14) Ecriture registre en clair =====
        public static string RegistryWritePlain(string name, string value)
        {
            using (var key = Registry.CurrentUser.CreateSubKey(@"Software\DA03Demo")) // ❌ pas d'ACL, en clair
            {
                if (key != null) key.SetValue(name, value, RegistryValueKind.String);
            }
            return @"Written to HKCU\Software\DA03Demo (" + name + ")";
        }

        // ===== 15) DES-ECB (clé en dur) =====
        public static string DesEcbEncrypt(string plain)
        {
            var input = Encoding.UTF8.GetBytes(plain);
            using (var des = new DESCryptoServiceProvider())
            {
                des.Mode = CipherMode.ECB;         // ❌ ECB
                des.Padding = PaddingMode.PKCS7;
                des.Key = Encoding.ASCII.GetBytes("12345678"); // ❌ clé en dur 8 bytes

                using (var enc = des.CreateEncryptor())
                {
                    var ct = enc.TransformFinalBlock(input, 0, input.Length);
                    return Convert.ToBase64String(ct);
                }
            }
        }
    }
}
