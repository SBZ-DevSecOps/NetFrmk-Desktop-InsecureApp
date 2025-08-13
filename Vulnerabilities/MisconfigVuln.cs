using Newtonsoft.Json;
using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Windows;

namespace NetFrmk_Desktop_InsecureApp.Vulnerabilities
{
    public static class MisconfigVuln
    {
        // 1. Plaintext secrets in App.config (simulate reading a plaintext key)
        public static void AppConfigSecret()
        {
            // ❌ Secret codé en dur détectable par SAST
            string plainSecret = "MySuperSecretAppPassword123";
            MessageBox.Show("[INSECURE] App.config contains: " + plainSecret, "App.config secret");
        }

        // 2. Hardcoded absolute path
        public static void HardcodedAbsolutePath()
        {
            // ❌ Chemin absolu codé en dur
            string absPath = @"C:\SensitiveData\data.txt";
            if (File.Exists(absPath))
            {
                string content = File.ReadAllText(absPath);
                MessageBox.Show("Read from " + absPath + ": " + content, "Hardcoded Path");
            }
            else
            {
                MessageBox.Show("Path not found: " + absPath, "Hardcoded Path");
            }
        }

        // 3. Verbose logging in production
        public static void VerboseLogging()
        {
            // ❌ Logs verbeux en prod
            string sensitive = "User=admin;Password=1234";
            Debug.WriteLine("[DEBUG] Login data: " + sensitive);
            MessageBox.Show("Debug logging active! (see Output window)\n" + sensitive, "Verbose Logging");
        }

        // 4. Global/shared temp dir
        public static void GlobalTempDir()
        {
            // ❌ Fichiers temporaires partagés/mondiaux
            string temp = Path.Combine(Path.GetTempPath(), "insecure.tmp");
            File.WriteAllText(temp, "Sensitive Info");
            MessageBox.Show("Wrote temp file: " + temp, "Global Temp Directory");
        }

        // 5. Private key/cert in project (simulate)
        public static void PrivateKeyInProject()
        {
            // ❌ Clé privée incluse dans le binaire/projet
            string privateKey = @"-----BEGIN PRIVATE KEY-----
MIIEv...fake...kGB7
-----END PRIVATE KEY-----";
            MessageBox.Show("[INSECURE] Private key hardcoded:\n" + privateKey.Substring(0, 40) + "...", "Private Key");
        }

        // 6. Wide permissions (Everyone) - set file ACLs to Everyone
        public static void WidePermissions()
        {
            // ❌ Permissions Everyone
            string file = Path.Combine(Environment.CurrentDirectory, "everyone.txt");
            File.WriteAllText(file, "Critical data (Everyone)");
            try
            {
                var fi = new FileInfo(file);
                var acl = fi.GetAccessControl();
                acl.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                    FileSystemRights.FullControl,
                    AccessControlType.Allow));
                fi.SetAccessControl(acl);
            }
            catch { /* ignore demo errors */ }
            MessageBox.Show("Created file with Everyone permissions: " + file, "Wide Permissions");
        }

        // 7. Writable hosts/system files
        public static void WritableHosts()
        {
            // ❌ Modification de fichier système (nécessite admin)
            string hosts = @"C:\Windows\System32\drivers\etc\hosts";
            try
            {
                File.AppendAllText(hosts, "\n# Hacked by DA08\n");
                MessageBox.Show("Hosts file modified!", "Writable System File");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Cannot write hosts file (need admin):\n" + ex.Message, "Writable System File");
            }
        }

        // 8. Debug mode enabled in prod
        public static void DebugModeEnabled()
        {
#if DEBUG
            MessageBox.Show("DEBUG mode ENABLED! (Release build should NOT have this)", "Debug Mode");
#else
            MessageBox.Show("No debug symbols present (this is a Release build).", "Debug Mode");
#endif
        }

        // 9. Weak cryptography
        public static void WeakCryptography()
        {
            // ❌ Usage MD5 (obsolète)
            string secret = "SensitiveData";
            using (var md5 = MD5.Create())
            {
                var hash = md5.ComputeHash(Encoding.UTF8.GetBytes(secret));
                MessageBox.Show("MD5(secret) = " + BitConverter.ToString(hash), "Weak Cryptography");
            }
        }

        // 10. Insecure IPC (Named Pipe, no auth) – simulated
        public static void InsecureIPC()
        {
            // ❌ Pas d’auth/chiffrement sur IPC (simulation)
            MessageBox.Show("Named pipe server started without authentication (not implemented)", "Insecure IPC");
        }

        // 11. Runs as admin by default (simulate check)
        public static void RunAsAdmin()
        {
            bool isAdmin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
            MessageBox.Show(isAdmin ? "App is running as ADMIN!" : "App is NOT running as admin.", "Runs as Admin");
        }

        // =================== NEW CASES (12..15) ===================

        // 12. Global TLS validation bypass (accept any certificate)
        public static string DisableCertValidation(string testUrl)
        {
            try
            {
                // ❌ Désactive la validation TLS pour tout le processus
                ServicePointManager.ServerCertificateValidationCallback += (s, cert, chain, errors) => true;

                string note = "TLS cert validation is now DISABLED process-wide.";
                if (!string.IsNullOrWhiteSpace(testUrl))
                {
                    using (var wc = new WebClient())
                    {
                        string data = wc.DownloadString(testUrl); // peut réussir même si certificat invalide
                        return note + " Fetched bytes: " + (data == null ? 0 : data.Length) + " from " + testUrl;
                    }
                }
                return note;
            }
            catch (Exception ex)
            {
                return "Cert bypass error: " + ex.Message;
            }
        }

        // 13. Misconfigured HTTP listener (binds to all interfaces 0.0.0.0)
        public static string HttpListenerAnyHost(string prefix)
        {
            try
            {
                // ❌ Expose un listener sur toutes les IP (http://+:<port>/)
                HttpListener listener = new HttpListener();
                listener.Prefixes.Add(prefix); // ex: "http://+:8081/test/"
                listener.Start();
                listener.Stop();
                return "HttpListener bound and stopped on: " + prefix;
            }
            catch (Exception ex)
            {
                return "HttpListener error: " + ex.Message;
            }
        }

        // 14. Newtonsoft.Json TypeNameHandling=All (dangerous)
        public static string JsonNetTypeNameHandlingAll(string json)
        {
            try
            {
                var settings = new JsonSerializerSettings
                {
                    TypeNameHandling = TypeNameHandling.All // ❌ permet la résolution de types arbitraires
                };

                if (string.IsNullOrWhiteSpace(json))
                {
                    // Exemple inoffensif mais démontre la config dangereuse
                    json = "{\"$type\":\"System.Version, mscorlib\",\"Major\":1,\"Minor\":2,\"Build\":3,\"Revision\":4}";
                }

                object obj = JsonConvert.DeserializeObject(json, settings);
                string typeName = obj != null ? obj.GetType().FullName : "(null)";
                return "Deserialized with TypeNameHandling=All → " + typeName;
            }
            catch (Exception ex)
            {
                return "Json.NET error: " + ex.Message;
            }
        }

        // 15. Default credentials present (admin:admin)
        public static string DefaultCredentials(string username, string password)
        {
            // ❌ Identifiants par défaut
            const string DEFAULT_USER = "admin";
            const string DEFAULT_PASS = "admin";

            if (string.Equals(username, DEFAULT_USER, StringComparison.OrdinalIgnoreCase) &&
                password == DEFAULT_PASS)
            {
                return "Login SUCCESS with default credentials (admin:admin) — MISCONFIGURATION!";
            }
            return "Login failed (try admin/admin).";
        }
    }
}
