using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading.Tasks;
using System.Windows;

namespace NetFrmk_Desktop_InsecureApp.Vulnerabilities
{
    public static class ErrorHandlingVuln
    {
        // 1. Stacktrace affichée à l’utilisateur
        public static void StacktraceToUI()
        {
            try
            {
                throw new InvalidOperationException("Demo error: failed to parse value!");
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.ToString(), "Stacktrace");
            }
        }

        // 2. Exception non catchée (crash)
        public static void UncaughtException()
        {
            throw new DivideByZeroException("This will crash the app (no try/catch)");
        }

        // 3. Catch générique “swallow”
        public static void SilentSwallow()
        {
            try
            {
                int.Parse("not_an_int");
            }
            catch { /* silent: swallow */ }
            MessageBox.Show("No error, but failed silently.", "Silent Swallow");
        }

        // 4. Message technique UI
        public static void TechnicalErrorUI()
        {
            try
            {
                File.ReadAllLines("missing-file.txt");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"[DEBUG] Exception: {ex.Message} @ {ex.StackTrace}", "Technical Error");
            }
        }

        // 5. Log détaillé en prod
        public static void VerboseProdLog()
        {
            try { throw new NullReferenceException("Simulated bug"); }
            catch (Exception ex)
            {
                File.AppendAllText("prod-errors.log", ex.ToString() + "\n");
                MessageBox.Show("Logged full error to prod-errors.log", "Verbose Log");
            }
        }

        // 6. Fuite d’info système
        public static void LeakSystemInfo()
        {
            try { File.OpenRead("C:\\forbidden.txt"); }
            catch (Exception ex)
            {
                string info = $"OS: {Environment.OSVersion}, User: {Environment.UserName}, Error: {ex.Message}";
                MessageBox.Show(info, "System Info Leak");
            }
        }

        // 7. Exposer inner exceptions
        public static void InnerExceptions()
        {
            try
            {
                try
                {
                    WebClient wc = new WebClient();
                    wc.DownloadString("http://localhost:9999");
                }
                catch (WebException wex)
                {
                    throw new ApplicationException("Wrapper error", wex);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error: {ex.Message}\nInner: {ex.InnerException}", "Inner Exception");
            }
        }

        // 8. Throw sans handling global
        public static void ThrowUncaught()
        {
            throw new InvalidProgramException("Thrown without handler (will crash)");
        }

        // 9. No global handler (à simuler dans App.xaml.cs, mais rappel ici)
        public static void NoGlobalHandler()
        {
            MessageBox.Show("No AppDomain/Dispatcher handler set! Any error = crash.", "No Global Handler");
        }

        // 10. Mauvais try/catch accès IO ou réseau
        public static void PoorIoNetworkHandling()
        {
            try
            {
                File.ReadAllText("file-not-exist.txt");
                WebClient wc = new WebClient();
                wc.DownloadString("http://bad:9999");
            }
            catch (Exception ex)
            {
                // Mauvais pattern : catch générique, pas de différenciation, log incomplet
                Debug.WriteLine(ex.ToString());
            }
            MessageBox.Show("Error(s) happened but were only debugged.", "Poor IO/Net Handling");
        }

        // 11. Logging d’exception sensible
        public static void SensitiveLog()
        {
            string password = "secret-in-error";
            try
            {
                throw new Exception($"Auth failed for password: {password}");
            }
            catch (Exception ex)
            {
                File.AppendAllText("app-errors.log", ex.ToString() + "\n");
                MessageBox.Show("Sensitive info written to error log!", "Sensitive Log");
            }
        }

        // 12. Crash dump world-readable
        public static void DumpWorldReadable()
        {
            string dump = "crash-dump.txt";
            File.WriteAllText(dump, "Simulated crash dump, secret: Qwerty123!\nStack: ...");
            try
            {
                var fi = new FileInfo(dump);
                var acl = fi.GetAccessControl();
                acl.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                    FileSystemRights.FullControl,
                    AccessControlType.Allow));
                fi.SetAccessControl(acl);
            }
            catch { }
            MessageBox.Show($"Crash dump written with Everyone permissions: {dump}", "World-Readable Dump");
        }

        // =================== NOUVEAUX CAS ===================

        // 13. Mauvais rethrow qui perd la stack (throw ex)
        public static void RethrowLostStack()
        {
            try
            {
                int.Parse("xxx");
            }
            catch (Exception ex)
            {
                try
                {
                    // ❌ Mauvais rethrow : perd la stack d'origine
                    throw ex;
                }
                catch (Exception re)
                {
                    MessageBox.Show("Rethrow used 'throw ex;' (original stack lost):\n\n" + re, "Rethrow (lost stack)");
                }
            }
        }

        // 14. Exception dans finally masque la cause initiale
        public static void FinallyMasksOriginal()
        {
            try
            {
                try
                {
                    File.ReadAllText("missing-again.txt");
                }
                finally
                {
                    // ❌ Masque l'exception initiale
                    throw new Exception("Finally threw and masked original error");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Observed exception (original masked):\n\n" + ex, "Finally Mask");
            }
        }

        // 15. Tâche fire-and-forget non observée (UnobservedTaskException)
        public static string FireAndForgetTask()
        {
            Task.Run(() =>
            {
                // ❌ Exception jamais await/observée
                throw new Exception("Background task crashed (unobserved)");
            });

            // Tente d’induire la finalisation des tâches fautives
            GC.Collect();
            GC.WaitForPendingFinalizers();

            return "Started a background task that throws without being awaited. Exception may be lost/unobserved.";
        }
    }
}
