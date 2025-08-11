using System;
using System.Diagnostics;
using System.IO;
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
            // Simule la présence d’un secret dur dans le App.config (SAST détectable)
            string plainSecret = "MySuperSecretAppPassword123"; // Vulnérable: secret codé en dur
            MessageBox.Show($"[INSECURE] App.config contains: {plainSecret}", "App.config secret");
        }

        // 2. Hardcoded absolute path
        public static void HardcodedAbsolutePath()
        {
            // Vulnérable: chemin absolu codé en dur
            string absPath = @"C:\SensitiveData\data.txt";
            if (File.Exists(absPath))
            {
                string content = File.ReadAllText(absPath);
                MessageBox.Show($"Read from {absPath}: {content}", "Hardcoded Path");
            }
            else
            {
                MessageBox.Show($"Path not found: {absPath}", "Hardcoded Path");
            }
        }

        // 3. Verbose logging in production
        public static void VerboseLogging()
        {
            // Vulnérable: logs verbeux actifs (simulateur: messagebox ici, mais pattern détectable)
            string sensitive = "User=admin;Password=1234";
            Debug.WriteLine($"[DEBUG] Login data: {sensitive}");
            MessageBox.Show("Debug logging active! (see Output window)\n" + sensitive, "Verbose Logging");
        }

        // 4. Global/shared temp dir
        public static void GlobalTempDir()
        {
            // Vulnérable: fichiers temporaires partagés/mondiaux
            string temp = Path.Combine(Path.GetTempPath(), "insecure.tmp");
            File.WriteAllText(temp, "Sensitive Info");
            MessageBox.Show($"Wrote temp file: {temp}", "Global Temp Directory");
        }

        // 5. Private key/cert in project (simulate reading a private key file)
        public static void PrivateKeyInProject()
        {
            // Vulnérable: clé privée incluse dans le code/source/projet
            string privateKey = @"-----BEGIN PRIVATE KEY-----
MIIEv...fake...kGB7
-----END PRIVATE KEY-----";
            MessageBox.Show($"[INSECURE] Private key hardcoded:\n{privateKey.Substring(0, 40)}...", "Private Key");
        }

        // 6. Wide permissions (Everyone) - set file ACLs to Everyone
        public static void WidePermissions()
        {
            // Vulnérable: permissions Everyone sur fichier
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
            catch { }
            MessageBox.Show($"Created file with Everyone permissions: {file}", "Wide Permissions");
        }

        // 7. Writable hosts/system files
        public static void WritableHosts()
        {
            // Vulnérable: modification fichier system/hosts (ne va pas marcher sans droits admin !)
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
            // Vulnérable: usage de MD5 (obsolète)
            string secret = "SensitiveData";
            var md5 = MD5.Create();
            var hash = md5.ComputeHash(Encoding.UTF8.GetBytes(secret));
            MessageBox.Show($"MD5(secret) = {BitConverter.ToString(hash)}", "Weak Cryptography");
        }

        // 10. Insecure IPC (Named Pipe, no auth)
        public static void InsecureIPC()
        {
            // Vulnérable: pipe nommé sans auth/chiffrement (simulateur simple)
            MessageBox.Show("Named pipe server started without authentication (not implemented)", "Insecure IPC");
        }

        // 11. Runs as admin by default (simulate check)
        public static void RunAsAdmin()
        {
            // Vulnérable: l’app tourne toujours en admin
            bool isAdmin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
            MessageBox.Show(isAdmin ? "App is running as ADMIN!" : "App is NOT running as admin.", "Runs as Admin");
        }
    }
}
